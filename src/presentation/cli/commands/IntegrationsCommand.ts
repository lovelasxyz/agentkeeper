import { Container } from '../../../composition/Container.js';
import { Palette } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';

export type AgentIntegrationStatus =
  /** No such agent on this machine; nothing to intercept. */
  | 'absent'
  /** The agent is installed and currently launches without the boundary. */
  | 'unprotected'
  /** A shim exists but the managed installation no longer matches its manifest. */
  | 'needs-repair'
  | 'intercepted';

export interface AgentIntegration {
  readonly agent: string;
  readonly executable: string | null;
  readonly shimPresent: boolean;
  readonly managedHealthy: boolean;
}

/**
 * `agentkeeper integrations` (spec §32) — which agents actually route through
 * the guard.
 *
 * The distinction that matters is between *configured* and *effective*: a shim
 * whose manifest no longer matches is reported as needing repair rather than
 * being counted as protection.
 */
export class IntegrationsCommand implements Command {
  readonly name = 'integrations';
  readonly usage = 'integrations [--json]';
  readonly summary = 'Show which agents launch through agentkeeper';

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const container = new Container({ quiet: flags.has('json'), interactive: false });
    const rows = await this.collect(container);

    if (flags.has('json')) {
      process.stdout.write(
        `${JSON.stringify(
          rows.map((row) => ({ ...row, status: classifyIntegration(row) })),
          null,
          2,
        )}\n`,
      );
    } else {
      process.stdout.write(`${renderIntegrations(rows).join('\n')}\n`);
    }
    return rows.some((row) => classifyIntegration(row) === 'needs-repair') ? 2 : 0;
  }

  private async collect(container: Container): Promise<readonly AgentIntegration[]> {
    const [{ MANAGED_AGENTS }, { ExecutableResolver }] = await Promise.all([
      import('../../../infrastructure/install/ManagedInstallation.js'),
      import('../../../infrastructure/system/ExecutableResolver.js'),
    ]);
    const home = container.files.realPath(container.environment.identityHome);
    const stateDir = home.join('.agentkeeper');
    const shell = container.environment.platform === 'win32' ? 'powershell' : 'posix';
    const shimDirectory = stateDir.join(`shims/${shell}`);

    const [resolved, health] = await Promise.all([
      new ExecutableResolver().resolveMany(
        MANAGED_AGENTS,
        container.environment.variables['PATH'] ?? '',
        [stateDir.join('shims')],
      ),
      this.health(container),
    ]);

    return Promise.all(
      MANAGED_AGENTS.map(async (agent) => {
        const shim = shimDirectory.join(shell === 'posix' ? agent : `${agent}.ps1`);
        const executable = resolved[agent];
        return {
          agent,
          executable: executable === undefined ? null : executable.value,
          shimPresent: (await container.files.read(shim)) !== null,
          managedHealthy: health,
        };
      }),
    );
  }

  private async health(container: Container): Promise<boolean> {
    try {
      const managed = await container.managedInstallation();
      return (await managed.planner.health()).healthy;
    } catch {
      return false;
    }
  }
}

/** Effective state of one agent, derived only from what is on disk. */
export function classifyIntegration(integration: AgentIntegration): AgentIntegrationStatus {
  if (integration.executable === null) return 'absent';
  if (!integration.shimPresent) return 'unprotected';
  return integration.managedHealthy ? 'intercepted' : 'needs-repair';
}

export function renderIntegrations(
  integrations: readonly AgentIntegration[],
): readonly string[] {
  const palette = Palette.forStream(process.stdout);
  const mark: Readonly<Record<AgentIntegrationStatus, string>> = {
    intercepted: palette.green('✓'),
    unprotected: palette.red('✗'),
    'needs-repair': palette.yellow('!'),
    absent: palette.dim('·'),
  };
  const explain: Readonly<Record<AgentIntegrationStatus, string>> = {
    intercepted: 'launches through agentkeeper',
    unprotected: 'unprotected — runs outside the boundary',
    'needs-repair': 'needs repair — run `agentkeeper repair`',
    absent: 'not installed on this machine',
  };

  const width = Math.max(...integrations.map((row) => row.agent.length));
  const lines = integrations.map((row) => {
    const status = classifyIntegration(row);
    return `${mark[status]} ${row.agent.padEnd(width)}  ${explain[status]}`;
  });

  const unprotected = integrations.filter((row) => classifyIntegration(row) === 'unprotected');
  return [
    palette.bold('agentkeeper integrations'),
    ...lines,
    '',
    unprotected.length === 0
      ? 'Every agent found on this machine launches through agentkeeper.'
      : `Run \`agentkeeper activate\` to intercept: ${unprotected
          .map((row) => row.agent)
          .join(', ')}.`,
  ];
}
