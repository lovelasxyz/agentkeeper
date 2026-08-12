import { Container } from '../../../composition/Container.js';
import { BaselineCollector } from '../../daemon/BaselineCollector.js';
import { NodeSandboxProbe } from '../../../infrastructure/sandbox/NodeSandboxProbe.js';
import { Palette, renderDiff } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';
import type { InstallationOperation } from '../../../application/ports/InstallationLifecycle.js';
import type { AbsolutePath } from '../../../domain/value-objects/AbsolutePath.js';
import type { Platform } from '../../../domain/value-objects/Platform.js';

/** Transactional install-once lifecycle used by activate/repair/deactivate. */
export class InstallationCommand implements Command {
  readonly name: string;
  readonly usage: string;
  readonly summary: string;

  constructor(
    private readonly operation: InstallationOperation,
    invokedAs: 'activate' | 'repair' | 'deactivate' | 'init' | 'uninstall' = operation,
  ) {
    this.name = invokedAs;
    this.usage =
      operation === 'activate'
        ? `${invokedAs} [--yes] [--dry-run] [--profile web|python|infra|minimal]`
        : `${invokedAs} [--yes] [--dry-run]${operation === 'deactivate' ? ' [--purge]' : ''}`;
    this.summary =
      operation === 'activate'
        ? 'Install transparent interception once, transactionally'
        : operation === 'repair'
          ? 'Verify and repair checksum-managed interception files'
          : 'Remove managed interception and restore shared files';
  }

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const container = new Container();
    const palette = Palette.forStream(process.stdout);
    const write = (line = ''): void => void process.stdout.write(`${line}\n`);
    const profileId = flags.value('profile') ?? 'web';

    if (this.operation === 'activate') {
      try {
        await (await container.profiles()).load(profileId);
      } catch (error) {
        write(`${palette.red('Refused')} — ${(error as Error).message}`);
        return 2;
      }
    }

    if (this.operation === 'activate' && !flags.has('dry-run')) {
      const runner = await container.sandboxRunner();
      const canary =
        runner === null
          ? null
          : await new NodeSandboxProbe().probe({
              runner,
              platform: container.environment.platform,
            });
      if (canary?.passed !== true) {
        const detail = canary === null ? 'backend unavailable' : canary.code;
        write(
          `${palette.red('UNPROTECTED')} — OS sandbox deny-canary failed (${detail}); ` +
            'refusing to install transparent shims.',
        );
        write('Run `agentkeeper doctor` after installing or repairing the platform backend.');
        return 3;
      }
    }

    const components = await container.managedInstallation();
    const plan = await components.planner.plan(this.operation);
    write(palette.bold(`agentkeeper ${this.name}`));
    if (components.agents.length > 0) {
      write(`Detected agents: ${components.agents.join(', ')}`);
    }

    if (plan.conflicts.length > 0) {
      write(`${palette.red('Refused')} — ${plan.conflicts.length} conflict(s):`);
      for (const conflict of plan.conflicts) {
        write(`  ${conflict.code}: ${conflict.path.value}`);
        write(`    ${conflict.message}`);
      }
      return 2;
    }

    const changeCount = plan.filePlan.changes.length + plan.externalChanges.length;
    if (changeCount === 0) {
      write(
        this.operation === 'activate'
          ? `${palette.green('✓')} Already active; every managed checksum matches.`
          : this.operation === 'repair'
            ? `${palette.green('✓')} No repair needed.`
            : 'Nothing installed.',
      );
      return 0;
    }

    for (const change of plan.filePlan.changes) write(renderDiff(change, palette));
    for (const change of plan.externalChanges) write(`  ${palette.yellow('~')} ${change.summary}`);
    if (flags.has('dry-run')) {
      write(`Dry run: ${changeCount} change(s), nothing written.`);
      return 0;
    }

    if (!flags.has('yes')) {
      const approved = await container.prompter.confirm(
        `${this.operation} ${changeCount} managed change(s)?`,
      );
      if (!approved) {
        write('Nothing was changed.');
        return 1;
      }
    }

    const controlPlaneBefore =
      this.operation === 'activate' && !plan.installed
        ? await Promise.all([
            container.files.read(container.stateDir.join('config.json')),
            container.files.read(container.stateDir.join('baseline.json')),
          ])
        : null;
    const result = await components.executor.execute(plan);
    if (this.operation === 'activate' && !plan.installed) {
      try {
        await this.finishActivation(container, profileId);
      } catch (error) {
        const rollbackErrors: unknown[] = [];
        try {
          await components.executor.execute(await components.planner.plan('deactivate'));
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
        if (controlPlaneBefore !== null) {
          const paths = [
            container.stateDir.join('config.json'),
            container.stateDir.join('baseline.json'),
          ] as const;
          for (const [index, path] of paths.entries()) {
            try {
              const previous = controlPlaneBefore[index] as string | null;
              if (previous === null) await container.files.remove(path);
              else await container.files.write(path, previous, 0o600);
            } catch (rollbackError) {
              rollbackErrors.push(rollbackError);
            }
          }
        }
        if (rollbackErrors.length > 0) {
          throw new AggregateError(
            [error, ...rollbackErrors],
            'Activation initialization failed and rollback was incomplete',
          );
        }
        throw error;
      }
    }

    await container.audit.append({
      at: container.clock.now(),
      event: `installation.${this.operation}`,
      details: {
        filesApplied: result.filesApplied,
        externalApplied: result.externalApplied,
        agents: components.agents,
      },
    });

    if (this.operation === 'deactivate' && flags.has('purge')) {
      await container.files.remove(container.stateDir);
      write(`${palette.green('✓')} Deactivated and purged agentkeeper state.`);
      return 0;
    }

    write(
      `${palette.green('✓')} ${this.operation} complete ` +
        `(${result.filesApplied} file, ${result.externalApplied} system change(s)).`,
    );
    for (const reason of result.degraded) {
      write(`${palette.yellow('!')} Degraded: ${reason}`);
      write('  Interception is installed; run `agentkeeper doctor` for the effective status.');
    }
    // Only where a watcher was just asked to run; after a deactivation there is
    // nothing left that could fail to start.
    const unreachable =
      this.operation === 'deactivate'
        ? null
        : backgroundLaunchWarning(
            components.entrypoint,
            container.files.realPath(container.environment.identityHome),
            container.environment.platform,
          );
    if (unreachable !== null) write(`${palette.yellow('!')} ${unreachable}`);
    if (this.operation === 'activate') {
      write('Open a new terminal once; after that use your agent command normally.');
      write('Verify the effective boundary with `agentkeeper doctor`.');
    }
    return 0;
  }

  private async finishActivation(container: Container, profileId: string): Promise<void> {
    const stateDir = container.stateDir;
    await container.files.write(
      stateDir.join('config.json'),
      `${JSON.stringify(
        {
          version: 1,
          sandbox: { enabled: true, starterProfile: profileId, onUnavailable: 'fail' },
          watchHome: true,
          strictMode: false,
          notifications: 'native',
          rules: { categoryA: { enabled: false } },
          logRetentionDays: 90,
        },
        null,
        2,
      )}\n`,
    );

    const snapshot = await new BaselineCollector(
      container.files,
      container.paths,
      container.clock,
    ).collect({
      home: container.files.realPath(container.environment.identityHome),
      workspace: container.environment.cwd,
      platform: container.environment.platform,
    });
    await container.baseline.save(snapshot);
  }
}

/** Directories macOS withholds from background agents until the user consents. */
const TCC_PROTECTED = ['Desktop', 'Documents', 'Downloads'];

/**
 * Explains, at activation time, a watcher that could never run.
 *
 * macOS TCC denies a launchd agent access to these directories, so a CLI
 * installed from a clone inside one of them cannot read its own entrypoint:
 * launchd accepts the registration, the job exits, and it respawns forever with
 * `EPERM` in a log nobody thinks to open. Naming it here costs one line and
 * saves the whole diagnosis.
 */
export function backgroundLaunchWarning(
  entrypoint: AbsolutePath,
  home: AbsolutePath,
  platform: Platform,
): string | null {
  if (platform !== 'darwin') return null;
  const directory = TCC_PROTECTED.find((name) => home.join(name).contains(entrypoint));
  if (directory === undefined) return null;
  return (
    `The resident watcher will not start: macOS withholds ~/${directory} from background ` +
    `agents, so it cannot read ${entrypoint.value}. Everything else is active. ` +
    'Install with `npm i -g agentkeeper` and run `agentkeeper repair` to enable it.'
  );
}
