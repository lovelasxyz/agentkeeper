import type { Command } from './Command.js';
import { AGENTKEEPER_VERSION } from '../../version.js';

/**
 * Name, help text, and how to load the implementation.
 *
 * The metadata is static so `--help` costs nothing; the module behind it is
 * imported only when that verb is actually used.
 */
interface CommandDescriptor {
  readonly name: string;
  readonly usage: string;
  readonly summary: string;
  load(): Promise<Command>;
}

/**
 * Maps a verb to a command object (spec §10.2).
 *
 * Commands are loaded lazily, and that is a measured decision rather than a
 * style preference. Importing all ten eagerly pulled the installer, the daemon
 * and every rule family into the process before `main` ran — 107 ms of module
 * graph on a hook whose entire budget is 50 ms. `hook pretooluse` now loads the
 * hook and nothing else.
 *
 * Argument parsing stays hand-rolled: nine verbs and a handful of flags do not
 * justify a third of the package's dependency budget.
 */
export class CommandRouter {
  private readonly commands: ReadonlyMap<string, CommandDescriptor>;

  constructor(commands: readonly CommandDescriptor[] = DESCRIPTORS) {
    this.commands = new Map(commands.map((command) => [command.name, command]));
  }

  async run(argv: readonly string[]): Promise<number> {
    const [verb, ...rest] = argv;

    if (verb === undefined || verb === '--help' || verb === '-h' || verb === 'help') {
      this.printHelp();
      return verb === undefined ? 1 : 0;
    }
    if (verb === '--version' || verb === '-v') {
      process.stdout.write(`${AGENTKEEPER_VERSION}\n`);
      return 0;
    }

    const descriptor = this.commands.get(verb);
    if (descriptor === undefined) {
      process.stderr.write(`agentkeeper: unknown command "${verb}"\n\n`);
      this.printHelp();
      return 1;
    }
    return (await descriptor.load()).execute(rest);
  }

  private printHelp(): void {
    const descriptors = [...this.commands.values()];
    const width = Math.max(...descriptors.map((command) => command.usage.length));
    const lines = [
      'agentkeeper — confine an AI coding agent to what it needs.',
      '',
      'Usage: agentkeeper <command> [options]',
      '',
      ...descriptors.map((command) => `  ${command.usage.padEnd(width + 2)}${command.summary}`),
      '',
      '  --version                 Print the version',
      '',
      'Start with: agentkeeper activate',
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
  }
}

const DESCRIPTORS: readonly CommandDescriptor[] = [
  {
    name: 'activate',
    usage: 'activate [--yes] [--dry-run] [--profile web|python|infra|minimal]',
    summary: 'Install transparent interception once, transactionally',
    load: async () =>
      new (await import('./commands/InstallationCommand.js')).InstallationCommand('activate'),
  },
  {
    name: 'repair',
    usage: 'repair [--yes] [--dry-run]',
    summary: 'Verify and repair checksum-managed interception files',
    load: async () =>
      new (await import('./commands/InstallationCommand.js')).InstallationCommand('repair'),
  },
  {
    name: 'deactivate',
    usage: 'deactivate [--yes] [--dry-run] [--purge]',
    summary: 'Remove managed interception and restore shared files',
    load: async () =>
      new (await import('./commands/InstallationCommand.js')).InstallationCommand('deactivate'),
  },
  {
    name: 'init',
    usage: 'init [--yes] [--profile web|python|infra|minimal]',
    summary: 'Alias for activate',
    load: async () =>
      new (await import('./commands/InstallationCommand.js')).InstallationCommand(
        'activate',
        'init',
      ),
  },
  {
    name: 'run',
    usage: 'run -- <command>',
    summary: 'Run a command inside the isolation profile',
    load: async () => new (await import('./commands/RunCommand.js')).RunCommand(),
  },
  {
    name: 'status',
    usage: 'status',
    summary: 'Show what is active, what is granted, and what is not enforced',
    load: async () => new (await import('./commands/StatusCommand.js')).StatusCommand(),
  },
  {
    name: 'doctor',
    usage: 'doctor [--json]',
    summary: 'Probe the real sandbox and explain every protection gap',
    load: async () => new (await import('./commands/DoctorCommand.js')).DoctorCommand(),
  },
  {
    name: 'scan',
    usage: 'scan [path] [--quiet] [--json]',
    summary: 'Inspect a workspace for autorun artifacts and injected instructions',
    load: async () => new (await import('./commands/ScanCommand.js')).ScanCommand(),
  },
  {
    name: 'policy',
    usage: 'policy [--json]',
    summary: 'Show the effective policy for this directory and its identity hash',
    load: async () => new (await import('./commands/PolicyCommand.js')).PolicyCommand(),
  },
  {
    name: 'integrations',
    usage: 'integrations [--json]',
    summary: 'Show which agents launch through agentkeeper',
    load: async () =>
      new (await import('./commands/IntegrationsCommand.js')).IntegrationsCommand(),
  },
  {
    name: 'grants',
    usage: 'grants [--add <dir:path>] [--write] [--revoke <id>]',
    summary: 'List, add or revoke what the sandbox opens',
    load: async () => new (await import('./commands/GrantsCommand.js')).GrantsCommand(),
  },
  {
    name: 'allow',
    usage: 'allow <path> [--read|--write] [--workspace]',
    summary: 'Open one tier 1 path to the sandbox',
    load: async () => new (await import('./commands/GrantsCommand.js')).GrantsCommand('allow'),
  },
  {
    name: 'revoke',
    usage: 'revoke <id>',
    summary: 'Close a grant by id',
    load: async () => new (await import('./commands/GrantsCommand.js')).GrantsCommand('revoke'),
  },
  {
    name: 'log',
    usage: 'log [--since 24h|7d]',
    summary: 'Show what agentkeeper recorded',
    load: async () => new (await import('./commands/LogCommand.js')).LogCommand(),
  },
  {
    name: 'pause',
    usage: 'pause <30m|1h|today> | pause --resume',
    summary: 'Silence notifications for a while (isolation stays on)',
    load: async () => new (await import('./commands/PauseCommand.js')).PauseCommand(),
  },
  {
    name: 'hook',
    usage: 'hook pretooluse',
    summary: 'Internal: evaluate a tool call (registered by init)',
    load: async () => new (await import('./commands/HookCommand.js')).HookCommand(),
  },
  {
    name: 'daemon',
    usage: 'daemon [--once]',
    summary: 'Internal: watch for persistence changes (started by init)',
    load: async () => new (await import('./commands/DaemonCommand.js')).DaemonCommand(),
  },
  {
    name: 'uninstall',
    usage: 'uninstall [--yes] [--purge]',
    summary: 'Alias for deactivate',
    load: async () =>
      new (await import('./commands/InstallationCommand.js')).InstallationCommand(
        'deactivate',
        'uninstall',
      ),
  },
];
