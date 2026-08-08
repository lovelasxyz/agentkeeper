import { RunCommand } from './commands/RunCommand.js';
import { ScanCommand } from './commands/ScanCommand.js';
import { StatusCommand } from './commands/StatusCommand.js';
import { GrantsCommand } from './commands/GrantsCommand.js';
import { InitCommand } from './commands/InitCommand.js';
import { UninstallCommand } from './commands/UninstallCommand.js';
import { LogCommand } from './commands/LogCommand.js';
import { PauseCommand } from './commands/PauseCommand.js';
import { HookCommand } from './commands/HookCommand.js';
import { DaemonCommand } from './commands/DaemonCommand.js';
import type { Command } from './Command.js';

const VERSION = '0.1.0';

/**
 * Maps a verb to a command object (spec §10.2).
 *
 * Argument parsing is hand-rolled and stays that way: the surface is nine verbs
 * and a handful of flags, and a parser dependency would be a third of the
 * package's dependency budget for something this small.
 */
export class CommandRouter {
  private readonly commands: ReadonlyMap<string, Command>;

  constructor(commands: readonly Command[] = defaultCommands()) {
    this.commands = new Map(commands.map((command) => [command.name, command]));
  }

  async run(argv: readonly string[]): Promise<number> {
    const [verb, ...rest] = argv;

    if (verb === undefined || verb === '--help' || verb === '-h' || verb === 'help') {
      this.printHelp();
      return verb === undefined ? 1 : 0;
    }
    if (verb === '--version' || verb === '-v') {
      process.stdout.write(`${VERSION}\n`);
      return 0;
    }

    const command = this.commands.get(verb);
    if (command === undefined) {
      process.stderr.write(`agent-guard: unknown command "${verb}"\n\n`);
      this.printHelp();
      return 1;
    }
    return command.execute(rest);
  }

  private printHelp(): void {
    const width = Math.max(...[...this.commands.values()].map((command) => command.usage.length));
    const lines = [
      'agent-guard — confine an AI coding agent to what it needs.',
      '',
      'Usage: agent-guard <command> [options]',
      '',
      ...[...this.commands.values()].map(
        (command) => `  ${command.usage.padEnd(width + 2)}${command.summary}`,
      ),
      '',
      '  --version                 Print the version',
      '',
      'Start with: agent-guard init',
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
  }
}

function defaultCommands(): readonly Command[] {
  return [
    new InitCommand(),
    new RunCommand(),
    new StatusCommand(),
    new ScanCommand(),
    new GrantsCommand(),
    new LogCommand(),
    new PauseCommand(),
    new HookCommand(),
    new DaemonCommand(),
    new UninstallCommand(),
  ];
}
