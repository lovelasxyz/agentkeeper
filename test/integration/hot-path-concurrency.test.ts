import { describe, expect, it } from 'vitest';
import { ScanWorkspace } from '../../src/application/use-cases/ScanWorkspace.js';
import { EvaluateToolCall } from '../../src/application/use-cases/EvaluateToolCall.js';
import { BaselineCollector } from '../../src/presentation/daemon/BaselineCollector.js';
import { JsonDecisionStore } from '../../src/infrastructure/store/stores.js';
import { ScanEngine } from '../../src/domain/services/ScanEngine.js';
import { ARTIFACT_RULES } from '../../src/domain/rules/artifact/index.js';
import { actionRules } from '../../src/domain/rules/toolcall/index.js';
import { ALL_RULES_ENABLED, RuleRegistry } from '../../src/domain/rules/RuleRegistry.js';
import { SensitivePathRegistry } from '../../src/domain/paths/SensitivePathRegistry.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { ToolCall } from '../../src/domain/entities/ToolCall.js';
import type { PathContext } from '../../src/domain/paths/PathContext.js';
import type {
  Decision,
  DecisionStore,
  FileStat,
} from '../../src/application/ports/index.js';
import { FixedClock, InMemoryFileSystem, RecordingAudit } from './fakes.js';

const HOME = AbsolutePath.of('/Users/perf');
const WORKSPACE = HOME.join('project');
const STATE = HOME.join('.agentkeeper');
const MAX_HOT_PATH_CONCURRENCY = 8;

class DelayedFileSystem extends InMemoryFileSystem {
  activeIo = 0;
  maximumIo = 0;
  reads = 0;
  writes = 0;

  override async read(path: AbsolutePath): Promise<string | null> {
    this.reads += 1;
    return this.delayed(() => super.read(path));
  }

  override async stat(path: AbsolutePath): Promise<FileStat | null> {
    return this.delayed(() => super.stat(path));
  }

  override async write(path: AbsolutePath, content: string, mode?: number): Promise<void> {
    this.writes += 1;
    void mode;
    await super.write(path, content);
  }

  resetMetrics(): void {
    this.activeIo = 0;
    this.maximumIo = 0;
    this.reads = 0;
    this.writes = 0;
  }

  private async delayed<T>(operation: () => Promise<T>): Promise<T> {
    this.activeIo += 1;
    this.maximumIo = Math.max(this.maximumIo, this.activeIo);
    try {
      await new Promise((resolve) => setTimeout(resolve, 2));
      return await operation();
    } finally {
      this.activeIo -= 1;
    }
  }
}

class BatchSpyDecisions implements DecisionStore {
  private readonly values = new Map<string, Decision>();
  findCalls = 0;
  allCalls = 0;
  recordCalls = 0;
  recordManyCalls = 0;

  async find(key: string): Promise<Decision | null> {
    this.findCalls += 1;
    return this.values.get(key) ?? null;
  }

  async all(): Promise<readonly Decision[]> {
    this.allCalls += 1;
    return [...this.values.values()];
  }

  async record(decision: Decision): Promise<void> {
    this.recordCalls += 1;
    this.values.set(decision.key, decision);
  }

  async recordMany(decisions: readonly Decision[]): Promise<void> {
    this.recordManyCalls += 1;
    for (const decision of decisions) this.values.set(decision.key, decision);
  }
}

describe('bounded hot-path I/O', () => {
  it('scans independent artifacts concurrently and snapshots decisions once', async () => {
    const files = new DelayedFileSystem();
    const decisions = new BatchSpyDecisions();
    for (let index = 0; index < 48; index += 1) {
      await files.write(
        WORKSPACE.join(`.cursor/rules/rule-${String(index).padStart(2, '0')}.md`),
        `Rule ${index}: keep changes focused.\n`,
      );
    }
    files.resetMetrics();

    const result = await new ScanWorkspace(
      files,
      new ScanEngine(RuleRegistry.of(ARTIFACT_RULES)),
      decisions,
      ALL_RULES_ENABLED,
      new FixedClock(),
    ).execute(WORKSPACE);

    expect(result.filesInspected).toBe(48);
    expect(files.maximumIo).toBeGreaterThan(1);
    expect(files.maximumIo).toBeLessThanOrEqual(MAX_HOT_PATH_CONCURRENCY);
    expect(decisions.allCalls).toBe(1);
    expect(decisions.findCalls).toBe(0);
    expect(decisions.recordManyCalls).toBe(1);
    expect(decisions.recordCalls).toBe(0);
  });

  it('collects independent baseline targets concurrently with the same hard limit', async () => {
    const files = new DelayedFileSystem();
    const context: PathContext = { home: HOME, workspace: WORKSPACE, platform: 'darwin' };
    const collector = new BaselineCollector(
      files,
      SensitivePathRegistry.default(),
      new FixedClock(),
    );
    const targets = collector.targets(context);
    for (const [index, target] of targets.entries()) {
      files.files.set(target.value, `baseline-${index}`);
    }
    files.resetMetrics();

    const entries = await collector.collect(context);

    expect(entries).toHaveLength(targets.length);
    expect(files.maximumIo).toBeGreaterThan(1);
    expect(files.maximumIo).toBeLessThanOrEqual(MAX_HOT_PATH_CONCURRENCY);
  });

  it('merges a drift batch with one store read and one atomic write', async () => {
    const files = new DelayedFileSystem();
    const store = new JsonDecisionStore(files, STATE);
    const decisions = Array.from({ length: 100 }, (_, index): Decision => ({
      key: `drift:file-${index}`,
      verdict: 'allow',
      subject: `sha256:${String(index).padStart(64, '0')}`,
      ruleIds: [],
      decidedAt: new Date(0),
    }));
    files.resetMetrics();

    await store.recordMany(decisions);

    expect(files.reads).toBe(1);
    expect(files.writes).toBe(1);
    expect(await store.all()).toHaveLength(100);
  });

  it('does not rewrite unchanged drift records on a repeated scan', async () => {
    const files = new DelayedFileSystem();
    const decisions = new BatchSpyDecisions();
    await files.write(WORKSPACE.join('AGENTS.md'), 'Keep changes focused.\n');
    const scanner = new ScanWorkspace(
      files,
      new ScanEngine(RuleRegistry.of(ARTIFACT_RULES)),
      decisions,
      ALL_RULES_ENABLED,
      new FixedClock(),
    );

    await scanner.execute(WORKSPACE);
    decisions.recordManyCalls = 0;
    await scanner.execute(WORKSPACE);

    expect(decisions.recordManyCalls).toBe(0);
    expect(decisions.recordCalls).toBe(0);
  });

  it('resolves every asking hook finding from one decision snapshot', async () => {
    const decisions = new BatchSpyDecisions();
    const verdict = await new EvaluateToolCall(
      new ScanEngine(RuleRegistry.of(actionRules())),
      decisions,
      new RecordingAudit(),
      new FixedClock(),
      ALL_RULES_ENABLED,
    ).execute(
      new ToolCall({
        tool: 'Bash',
        input: { command: 'npm publish && git push --force origin main' },
        context: { home: HOME, workspace: WORKSPACE, platform: 'darwin' },
      }),
    );

    expect(verdict.decision).toBe('ask');
    expect(verdict.findings.length).toBeGreaterThan(1);
    expect(decisions.allCalls).toBe(1);
    expect(decisions.findCalls).toBe(0);
  });
});
