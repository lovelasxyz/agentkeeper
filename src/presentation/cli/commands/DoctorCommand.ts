import { Container } from '../../../composition/Container.js';
import { AssessProtection } from '../../../application/use-cases/AssessProtection.js';
import { NodeNetworkProbe } from '../../../infrastructure/network/NodeNetworkProbe.js';
import { NodeSandboxProbe } from '../../../infrastructure/sandbox/NodeSandboxProbe.js';
import { WorkspaceId } from '../../../domain/value-objects/WorkspaceId.js';
import { Palette } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';

/** Runs a fresh deny-canary and reports effective guarantees, never configured intent. */
export class DoctorCommand implements Command {
  readonly name = 'doctor';
  readonly usage = 'doctor [--json]';
  readonly summary = 'Probe the real sandbox and explain every protection gap';

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const container = new Container({ quiet: flags.has('json'), interactive: false });
    const config = await container.config();
    const runner = await container.sandboxRunner();
    const home = container.files.realPath(container.environment.identityHome);
    const context = {
      home,
      workspace: home.join('.agentkeeper/doctor-workspace'),
      platform: container.environment.platform,
    } as const;
    const profile = await (await container.profiles()).load(config.starterProfile);
    const { policy } = container.policies.build({
      profile,
      grants: await container.grants.all(),
      context,
      workspaceId: WorkspaceId.fromPath(context.workspace),
      toolchainRoots: container.environment.toolchainRoots().map((path) =>
        container.files.realPath(path),
      ),
      stateDir: home.join('.agentkeeper'),
      agentStateDirs: ['.claude', '.gemini', '.cursor', '.codex', '.config/claude'].map(
        (relative) => home.join(relative),
      ),
      tempDirs: [],
    });
    const status = await new AssessProtection(
      new NodeSandboxProbe(),
      new NodeNetworkProbe(),
    ).execute({
      platform: container.environment.platform,
      runner,
      policy,
      context,
      // There is deliberately no environment-variable bypass. A disabled
      // backend makes protected runs fail closed and is reported as such.
      bypassed: false,
      // Left undecided on purpose: the network canary answers it by running
      // the broker, so `doctor` reports egress it has just proven.
    });

    let installation:
      | {
          readonly active: boolean;
          readonly healthy: boolean;
          readonly changes: number;
          readonly conflicts: number;
        }
      | { readonly healthy: false; readonly error: string };
    try {
      const managed = await container.managedInstallation();
      const health = await managed.planner.health();
      installation = {
        active: health.installed,
        healthy: health.healthy,
        changes: health.repairsNeeded,
        conflicts: health.conflicts.length,
      };
    } catch (error) {
      installation = { healthy: false, error: (error as Error).message };
    }

    if (flags.has('json')) {
      process.stdout.write(`${JSON.stringify({ status, installation }, null, 2)}\n`);
    } else {
      this.render(status, installation);
    }
    if (status.level === 'PROTECTED' && installation.healthy) return 0;
    return status.level === 'DEGRADED' ? 2 : 3;
  }

  private render(
    status: Awaited<ReturnType<AssessProtection['execute']>>,
    installation:
      | {
          readonly active: boolean;
          readonly healthy: boolean;
          readonly changes: number;
          readonly conflicts: number;
        }
      | { readonly healthy: false; readonly error: string },
  ): void {
    const palette = Palette.forStream(process.stdout);
    const colour =
      status.level === 'PROTECTED'
        ? palette.green(status.level)
        : status.level === 'DEGRADED'
          ? palette.yellow(status.level)
          : palette.red(status.level);
    const lines = [
      `${palette.bold('agentkeeper doctor')}: ${colour}`,
      `  mechanism: ${status.capabilities.mechanism}`,
      `  deny canary: ${status.capabilities.denyCanary}`,
      `  filesystem: ${status.capabilities.filesystem}`,
      `  process tree: ${status.capabilities.processTree}`,
      `  network: ${status.capabilities.network}`,
      '',
      palette.bold('Effective gaps'),
      ...(status.reasons.length === 0
        ? ['  none']
        : status.reasons.map((reason) => `  ${reason.code}: ${reason.message}`)),
      '',
      palette.bold('Managed installation'),
      'error' in installation
        ? `  unhealthy: ${installation.error}`
        : installation.healthy
          ? '  healthy: manifest and managed checksums match'
          : installation.active
            ? `  needs repair: ${installation.changes} change(s), ${installation.conflicts} conflict(s)`
            : '  inactive: run `agentkeeper activate` once',
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
  }
}
