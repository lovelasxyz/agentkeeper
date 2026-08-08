import { watch, type FSWatcher } from 'node:fs';
import { Container } from '../../../composition/Container.js';
import { BaselineCollector } from '../../daemon/BaselineCollector.js';
import { BaselineChange } from '../../../domain/entities/BaselineChange.js';
import type { AbsolutePath } from '../../../domain/value-objects/AbsolutePath.js';
import type { PathContext } from '../../../domain/paths/PathContext.js';
import type { BaselineEntry } from '../../../application/ports/index.js';
import type { Command } from '../Command.js';

/** Editors write a file three times in a row; one report is enough. */
const SETTLE_MS = 750;

/**
 * `agent-guard daemon` — entry point E2, zone B (spec §5).
 *
 * Event-driven, never polling: idle CPU has to be indistinguishable from zero
 * or the thing gets uninstalled. A change reported here while isolation was
 * active is the highest-value signal the product produces — it means something
 * got out of the sandbox — which is why family P escalates severity in that
 * case rather than reporting the same "file changed" either way.
 */
export class DaemonCommand implements Command {
  readonly name = 'daemon';
  readonly usage = 'daemon [--once]';
  readonly summary = 'Internal: watch for persistence changes (started by init)';

  private readonly watchers: FSWatcher[] = [];
  private timer: NodeJS.Timeout | null = null;

  async execute(args: readonly string[]): Promise<number> {
    const container = new Container({ interactive: false });
    const context: PathContext = {
      home: container.files.realPath(container.environment.home),
      workspace: container.files.realPath(container.environment.cwd),
      platform: container.environment.platform,
    };

    const collector = new BaselineCollector(container.files, container.paths, container.clock);
    const report = async (): Promise<number> => this.compare(container, collector, context);

    if (args.includes('--once')) return report();

    for (const target of collector.targets(context)) {
      if (!(await container.files.exists(target))) continue;
      try {
        const watcher = watch(target.value, { persistent: true }, () => {
          if (this.timer !== null) clearTimeout(this.timer);
          this.timer = setTimeout(() => void report(), SETTLE_MS);
        });
        this.watchers.push(watcher);
      } catch {
        // A path that cannot be watched is skipped rather than fatal: the rest
        // of zone B is still worth watching.
        continue;
      }
    }

    await container.audit.append({
      at: container.clock.now(),
      event: 'daemon.started',
      details: { watching: this.watchers.length },
    });

    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      process.on(signal, () => {
        for (const watcher of this.watchers) watcher.close();
        process.exit(0);
      });
    }

    // Nothing further to do on this stack; the watchers hold the process open.
    return new Promise<number>(() => {});
  }

  private async compare(
    container: Container,
    collector: BaselineCollector,
    context: PathContext,
  ): Promise<number> {
    const previous = new Map(
      (await container.baseline.load()).map((entry) => [entry.path.value, entry]),
    );
    const current = await collector.collect(context);
    const sandboxActive = process.env['AGENT_GUARD_ACTIVE'] === '1';

    const changes: BaselineChange[] = [];
    const seen = new Set<string>();

    for (const entry of current) {
      seen.add(entry.path.value);
      const before = previous.get(entry.path.value);
      if (before !== undefined && before.hash.equals(entry.hash)) continue;

      changes.push(
        new BaselineChange({
          path: entry.path,
          kind: before === undefined ? 'created' : 'modified',
          previousHash: before?.hash ?? null,
          currentHash: entry.hash,
          content: await container.files.read(entry.path),
          context,
          sandboxActive,
        }),
      );
    }

    for (const [value, entry] of previous) {
      if (seen.has(value)) continue;
      changes.push(deletion(entry, context, sandboxActive));
    }

    if (changes.length === 0) return 0;

    const report = container.persistenceScanner().scan(changes, await container.config());
    const notifier = container.notifier();

    for (const finding of report.findings) {
      await notifier.notify(finding);
      await container.audit.append({
        at: container.clock.now(),
        event: 'persistence.change',
        details: {
          rule: finding.ruleId.toString(),
          subject: finding.subject,
          severity: finding.severity.name,
          sandboxActive,
        },
      });
    }

    // The new state becomes the baseline: the user has been told once, and
    // repeating the same alert every time the file is touched is how a security
    // tool trains people to ignore it.
    await container.baseline.save(current);
    return report.blocking().length > 0 ? 2 : 0;
  }
}

function deletion(
  entry: BaselineEntry,
  context: PathContext,
  sandboxActive: boolean,
): BaselineChange {
  return new BaselineChange({
    path: entry.path as AbsolutePath,
    kind: 'deleted',
    previousHash: entry.hash,
    currentHash: null,
    content: null,
    context,
    sandboxActive,
  });
}
