import { Artifact } from '../../domain/entities/Artifact.js';
import { ScanReport } from '../../domain/entities/ScanReport.js';
import { ContentHash } from '../../domain/value-objects/ContentHash.js';
import { WorkspaceId } from '../../domain/value-objects/WorkspaceId.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { ScanEngine } from '../../domain/services/ScanEngine.js';
import type { RuleSwitches } from '../../domain/rules/RuleRegistry.js';
import type { Clock, Decision, DecisionStore, FileSystem } from '../ports/index.js';
import { mapWithConcurrency } from '../services/BoundedConcurrency.js';

const SCAN_IO_CONCURRENCY = 8;
const MAX_SCANNED_ARTIFACT_BYTES = 512 * 1024;

/**
 * Only these are ever read: a scan is cheap because it looks at very little.
 *
 * Case-insensitive, and that is a security property rather than tidiness.
 * Windows delivers paths already lower-cased, so a case-sensitive `CLAUDE.md`
 * matched nothing there and the instruction-injection family was unreachable
 * on the whole platform. Reading a few extra candidates costs nothing; missing
 * the one that carries the payload costs everything.
 */
const INTERESTING = [
  /^\.claude\/settings(\.local)?\.json$/i,
  /^\.claude\/.*\.json$/i,
  /^\.vscode\/(tasks|settings|mcp)\.json$/i,
  /^\.devcontainer\/.*devcontainer\.json$/i,
  /^\.git\/hooks\/[^.]+$/i,
  /^\.envrc$/i,
  /^\.env(\..+)?$/i,
  /^\.gemini\/.*$/i,
  /^\.(mcp|cursorrules|windsurfrules)$/i,
  /^\.mcp\.json$/i,
  /^\.cursor\/.*$/i,
  /^(CLAUDE|AGENTS|GEMINI)(\.local)?\.md$/i,
  /^\.github\/(workflows\/.+\.ya?ml|copilot-instructions\.md)$/i,
];

const INTERESTING_TREES = [
  /^\.claude(?:\/|$)/i,
  /^\.vscode(?:\/|$)/i,
  /^\.devcontainer(?:\/|$)/i,
  /^\.git(?:\/hooks(?:\/|$)|$)/i,
  /^\.gemini(?:\/|$)/i,
  /^\.cursor(?:\/|$)/i,
  /^\.github(?:\/workflows(?:\/|$)|$)/i,
];

export interface ScanResult {
  readonly report: ScanReport;
  readonly filesInspected: number;
}

/**
 * `agentkeeper scan` and the git hook (entry points E1, spec §5).
 *
 * The file filter is the whole performance story: a repository has thousands of
 * files and about a dozen that can execute something on your behalf. Walking
 * everything to hash it would blow the 200 ms budget and find nothing extra.
 */
export class ScanWorkspace {
  constructor(
    private readonly files: FileSystem,
    private readonly engine: ScanEngine<Artifact>,
    private readonly decisions: DecisionStore,
    private readonly switches: RuleSwitches,
    private readonly clock: Clock,
  ) {}

  async execute(workspace: AbsolutePath): Promise<ScanResult> {
    // The filesystem walk and the decision snapshot are independent. Loading
    // the snapshot once also avoids re-reading decisions.json for every drift
    // key and every finding.
    const [candidates, storedDecisions] = await Promise.all([
      this.files.list(workspace, {
        maxEntries: 20_000,
        maxDepth: 24,
        failOnLimit: true,
        includeFile: (path) => isInteresting(workspace, path),
        shouldDescend: (path) =>
          INTERESTING_TREES.some((pattern) => pattern.test(relativeTo(workspace, path))),
      }),
      this.decisions.all(),
    ]);
    const decisions = new Map(storedDecisions.map((decision) => [decision.key, decision]));
    const interesting = candidates.flatMap((path) => {
      const relative = relativeTo(workspace, path);
      return INTERESTING.some((pattern) => pattern.test(relative)) ? [{ path, relative }] : [];
    });

    const inspected = await mapWithConcurrency(
      interesting,
      SCAN_IO_CONCURRENCY,
      async ({ path, relative }): Promise<Artifact | null> => {
        const info = await this.files.stat(path);
        if (info !== null && info.size > MAX_SCANNED_ARTIFACT_BYTES) {
          throw new Error(
            `Refusing a partial scan: ${relative} is ${info.size} bytes ` +
              `(limit ${MAX_SCANNED_ARTIFACT_BYTES})`,
          );
        }
        const content = await this.files.read(path);
        if (content === null) return null;
        return new Artifact({
          path,
          workspace,
          content,
          previousHash: previousHash(decisions.get(driftKey(workspace, relative))),
        });
      },
    );
    const artifacts = inspected.filter((artifact): artifact is Artifact => artifact !== null);

    const report = this.engine.scan(artifacts, this.switches);
    const filtered = this.applyDecisions(report, decisions);
    await this.recordArtifactHashes(workspace, artifacts);
    return { report: filtered, filesInspected: artifacts.length };
  }

  /** TOFU: something already approved by content is not asked about again (spec §7). */
  private applyDecisions(
    report: ScanReport,
    decisions: ReadonlyMap<string, Decision>,
  ): ScanReport {
    const kept = [];
    for (const finding of report.findings) {
      const previous = decisions.get(finding.decisionKey);
      if (previous?.verdict === 'allow') continue;
      kept.push(finding);
    }
    return ScanReport.of(kept);
  }

  /**
   * Drift is a baseline, not an approval. Recording it under a separate key
   * means the next content hash is compared with what was actually inspected,
   * while durable allow/deny decisions remain tied to their own decision keys.
   */
  private async recordArtifactHashes(
    workspace: AbsolutePath,
    artifacts: readonly Artifact[],
  ): Promise<void> {
    const changed = artifacts.filter(
      (artifact) => artifact.previousHash === null || !artifact.previousHash.equals(artifact.hash),
    );
    if (changed.length === 0) return;
    await this.decisions.recordMany(
      changed.map((artifact) => ({
        key: driftKey(workspace, artifact.relativePath),
        verdict: 'allow' as const,
        subject: artifact.hash.toString(),
        ruleIds: [],
        decidedAt: this.clock.now(),
      })),
    );
  }
}

function isInteresting(workspace: AbsolutePath, path: AbsolutePath): boolean {
  const relative = relativeTo(workspace, path);
  return INTERESTING.some((pattern) => pattern.test(relative));
}

function previousHash(record: Decision | undefined): ContentHash | null {
  if (record === undefined) return null;
  try {
    return ContentHash.parse(record.subject);
  } catch {
    return null;
  }
}

function relativeTo(workspace: AbsolutePath, path: AbsolutePath): string {
  return workspace.contains(path) ? path.value.slice(workspace.value.length + 1) : path.value;
}

/**
 * Drift is a per-repository fact, so the record is keyed by workspace too.
 *
 * Keying by relative path alone made a first-ever scan of a second project
 * report its `AGENTS.md` as "changed since the last scan", because another
 * project had one. Old records simply stop matching, which reads as "not seen
 * before" and reports nothing — the safe direction for a migration.
 */
function driftKey(workspace: AbsolutePath, relativePath: string): string {
  return `drift:${WorkspaceId.fromPath(workspace).toString()}:${relativePath}`;
}
