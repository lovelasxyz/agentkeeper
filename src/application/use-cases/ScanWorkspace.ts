import { Artifact } from '../../domain/entities/Artifact.js';
import { ScanReport } from '../../domain/entities/ScanReport.js';
import { ContentHash } from '../../domain/value-objects/ContentHash.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { ScanEngine } from '../../domain/services/ScanEngine.js';
import type { RuleSwitches } from '../../domain/rules/RuleRegistry.js';
import type { DecisionStore, FileSystem } from '../ports/index.js';

/** Only these are ever read: a scan is cheap because it looks at very little. */
const INTERESTING = [
  /^\.claude\/settings(\.local)?\.json$/,
  /^\.claude\/.*\.json$/,
  /^\.vscode\/(tasks|settings|mcp)\.json$/,
  /^\.devcontainer\/.*devcontainer\.json$/,
  /^\.git\/hooks\/[^.]+$/,
  /^\.envrc$/,
  /^\.env(\..+)?$/,
  /^\.gemini\/.*$/,
  /^\.(mcp|cursorrules|windsurfrules)$/,
  /^\.mcp\.json$/,
  /^\.cursor\/.*$/,
  /^(CLAUDE|AGENTS|GEMINI)(\.local)?\.md$/,
  /^\.github\/(workflows\/.+\.ya?ml|copilot-instructions\.md)$/,
];

export interface ScanResult {
  readonly report: ScanReport;
  readonly filesInspected: number;
}

/**
 * `agent-guard scan` and the git hook (entry points E1, spec §5).
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
  ) {}

  async execute(workspace: AbsolutePath): Promise<ScanResult> {
    const candidates = await this.files.list(workspace);
    const artifacts: Artifact[] = [];

    for (const path of candidates) {
      const relative = relativeTo(workspace, path);
      if (!INTERESTING.some((pattern) => pattern.test(relative))) continue;

      const content = await this.files.read(path);
      if (content === null) continue;

      artifacts.push(
        new Artifact({
          path,
          workspace,
          content,
          previousHash: await this.previousHash(relative),
        }),
      );
    }

    const report = this.engine.scan(artifacts, this.switches);
    return { report: await this.applyDecisions(report), filesInspected: artifacts.length };
  }

  /** TOFU: something already approved by content is not asked about again (spec §7). */
  private async applyDecisions(report: ScanReport): Promise<ScanReport> {
    const kept = [];
    for (const finding of report.findings) {
      const previous = await this.decisions.find(finding.decisionKey);
      if (previous?.verdict === 'allow') continue;
      kept.push(finding);
    }
    return ScanReport.of(kept);
  }

  private async previousHash(relative: string): Promise<ContentHash | null> {
    const record = await this.decisions.find(`drift:${relative}`);
    if (record === null) return null;
    try {
      return ContentHash.parse(record.subject);
    } catch {
      return null;
    }
  }
}

function relativeTo(workspace: AbsolutePath, path: AbsolutePath): string {
  return workspace.contains(path) ? path.value.slice(workspace.value.length + 1) : path.value;
}
