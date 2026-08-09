import { Container } from '../../../composition/Container.js';
import { UnsafeWorkspaceError } from '../../../domain/policy/PolicyBuilder.js';
import { Flags, type Command } from '../Command.js';

/**
 * `agentkeeper run -- <command>` (spec §4.6).
 *
 * Fail-closed. Every path out of here either starts the command under a policy
 * or prints why it did not; there is no path that starts it unprotected while
 * staying quiet about it.
 */
export class RunCommand implements Command {
  readonly name = 'run';
  readonly usage = 'run -- <command>';
  readonly summary = 'Run a command inside the isolation profile';

  async execute(args: readonly string[]): Promise<number> {
    const separator = args.indexOf('--');
    const target = separator === -1 ? args : args.slice(separator + 1);
    const flags = Flags.parse(separator === -1 ? [] : args.slice(0, separator));

    const [executable, ...rest] = target;
    if (executable === undefined) {
      process.stderr.write('Usage: agentkeeper run -- <command> [args...]\n');
      return 1;
    }

    const container = new Container();
    const config = await container.config();

    try {
      const useCase = await container.runSandboxed();
      const outcome = await useCase.execute({
        executable,
        args: rest,
        profile: await (await container.profiles()).load(flags.value('profile') ?? config.starterProfile),
        onUnavailable: config.onUnavailable,
      });
      return outcome.exitCode;
    } catch (error) {
      if (error instanceof UnsafeWorkspaceError) {
        process.stderr.write(`agentkeeper: ${error.message}\n`);
        return 78; // EX_CONFIG
      }
      process.stderr.write(`agentkeeper: ${(error as Error).message}\n`);
      return 1;
    }
  }
}
