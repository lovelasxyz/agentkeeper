import { Container } from '../../../composition/Container.js';
import { MonitorPersistence } from '../../../application/use-cases/MonitorPersistence.js';
import { SingleFlightScheduler } from '../../../application/services/SingleFlightScheduler.js';
import { SerialAuditLog } from '../../../application/services/SerialAuditLog.js';
import { JsonPauseState } from '../../../infrastructure/store/JsonPauseState.js';
import { JsonPersistencePendingStore } from '../../../infrastructure/store/JsonPersistencePendingStore.js';
import { NodeWatchService, type WatchSession } from '../../../infrastructure/watch/NodeWatchService.js';
import { BaselineCollector } from '../../daemon/BaselineCollector.js';
import type { PathContext } from '../../../domain/paths/PathContext.js';
import type { Command } from '../Command.js';

/** One leading comparison catches transient drift; one trailing pass sees settled editor output. */
const SETTLE_MS = 750;

/** `agentkeeper daemon` — resident persistence monitor (entry point E2). */
export class DaemonCommand implements Command {
  readonly name = 'daemon';
  readonly usage = 'daemon [--once]';
  readonly summary = 'Internal: watch for persistence changes (started by activate)';

  private timer: NodeJS.Timeout | null = null;

  async execute(args: readonly string[]): Promise<number> {
    const container = new Container({ interactive: false });
    const context: PathContext = {
      // Persistence belongs to the effective OS identity. An inherited HOME is
      // compatibility input, not authority to move the monitored boundary.
      home: container.files.realPath(container.environment.identityHome),
      workspace: container.files.realPath(container.environment.cwd),
      platform: container.environment.platform,
    };
    const collector = new BaselineCollector(container.files, container.paths, container.clock);
    const audit = new SerialAuditLog(container.audit);
    const monitor = new MonitorPersistence({
      files: container.files,
      baseline: container.baseline,
      decisions: container.decisions,
      pending: new JsonPersistencePendingStore(container.files, container.stateDir),
      pause: new JsonPauseState(container.files, container.stateDir, container.clock),
      collector,
      scanner: await container.persistenceScanner(),
      switches: await container.config(),
      notifier: container.notifier(),
      audit,
      clock: container.clock,
      context,
      sandboxActive: process.env['AGENTKEEPER_ACTIVE'] === '1',
    });

    if (args.includes('--once')) return (await monitor.execute()).exitCode;

    let comparisonFailures = 0;
    const scheduler = new SingleFlightScheduler(
      async () => {
        await monitor.execute();
      },
      async (error) => {
        comparisonFailures += 1;
        container.logger.error(`persistence comparison failed: ${error.message}`);
        await audit.append({
          at: container.clock.now(),
          event: 'daemon.comparison.failed',
          details: { reason: error.message, failures: comparisonFailures },
        });
      },
    );

    const started = await new NodeWatchService().start(
      collector.watchTargets(context),
      (event) => {
        if (!collector.isRelevantWatchEvent(event.path, context)) return;
        const leadingEdge = this.timer === null;
        if (this.timer !== null) clearTimeout(this.timer);
        if (leadingEdge) void scheduler.request();
        this.timer = setTimeout(() => {
          this.timer = null;
          void scheduler.request();
        }, SETTLE_MS);
      },
      (fault) => {
        container.logger.error(`watch coverage lost for ${fault.path.value}: ${fault.reason}`);
        void audit
          .append({
            at: container.clock.now(),
            event: 'daemon.watch.degraded',
            details: { path: fault.path.value, reason: fault.reason },
          })
          .catch((error: unknown) => {
            container.logger.error(`could not record watcher failure: ${message(error)}`);
          });
      },
    );

    if (started.coverage.status === 'failed') {
      started.session.close();
      await audit.append({
        at: container.clock.now(),
        event: 'daemon.start.failed',
        details: {
          requested: started.coverage.requestedTargets,
          reasons: started.coverage.reasons,
        },
      });
      container.logger.error(
        `persistence watcher has no coverage: ${started.coverage.reasons.join('; ')}`,
      );
      return 2;
    }

    // Watch first, then compare. An event arriving during the first comparison
    // marks the scheduler dirty and receives a second, non-overlapping pass.
    await scheduler.request();
    const effectiveStatus =
      started.coverage.status === 'degraded' || comparisonFailures > 0 ? 'degraded' : 'protected';
    const effectiveReasons = [
      ...started.coverage.reasons,
      ...(comparisonFailures > 0 ? ['initial persistence comparison failed'] : []),
    ];
    await audit.append({
      at: container.clock.now(),
      event: 'daemon.started',
      details: {
        status: effectiveStatus,
        requested: started.coverage.requestedTargets,
        watching: started.coverage.watchedDirectories,
        reasons: effectiveReasons,
      },
    });
    if (effectiveStatus === 'degraded') {
      container.logger.warn(`daemon coverage is degraded: ${effectiveReasons.join('; ')}`);
    }

    return this.waitForShutdown(started.session, audit, container);
  }

  private waitForShutdown(
    session: WatchSession,
    audit: SerialAuditLog,
    container: Container,
  ): Promise<number> {
    return new Promise<number>((resolve) => {
      let stopped = false;
      const shutdown = (signal: NodeJS.Signals): void => {
        if (stopped) return;
        stopped = true;
        session.close();
        if (this.timer !== null) clearTimeout(this.timer);
        process.removeListener('SIGINT', onInterrupt);
        process.removeListener('SIGTERM', onTerminate);
        void audit
          .append({
            at: container.clock.now(),
            event: 'daemon.stopped',
            details: { signal },
          })
          .catch((error: unknown) => {
            container.logger.error(`could not record daemon shutdown: ${message(error)}`);
          })
          .finally(() => resolve(0));
      };
      const onInterrupt = (): void => shutdown('SIGINT');
      const onTerminate = (): void => shutdown('SIGTERM');
      process.once('SIGINT', onInterrupt);
      process.once('SIGTERM', onTerminate);
    });
  }
}

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}
