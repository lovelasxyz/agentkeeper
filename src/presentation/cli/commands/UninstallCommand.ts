import { Container } from '../../../composition/Container.js';
import {
  ClaudeHookIntegration,
  DaemonIntegration,
  GitHookIntegration,
  ShellFunctionsIntegration,
} from '../../../infrastructure/install/integrations.js';
import { Palette, renderDiff } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';
import type { Integration, PlannedChange } from '../../../application/ports/Integration.js';

/**
 * `agent-guard uninstall` (spec §10.1).
 *
 * The exact inverse of `init`, verified by an end-to-end test. A security tool
 * that is hard to remove has the same shape as the thing it protects against,
 * and it does not get to claim otherwise.
 */
export class UninstallCommand implements Command {
  readonly name = 'uninstall';
  readonly usage = 'uninstall [--yes] [--purge]';
  readonly summary = 'Remove every integration and restore the originals';

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const container = new Container();
    const palette = Palette.forStream(process.stdout);
    const binary = process.argv[1] ?? 'agent-guard';

    const integrations: readonly Integration[] = [
      new ShellFunctionsIntegration(container.files, container.environment.home, container.stateDir),
      new ClaudeHookIntegration(container.files, container.environment.home, binary),
      new GitHookIntegration(container.files, container.stateDir, binary, null),
      new DaemonIntegration(
        container.files,
        container.environment.home,
        container.environment.platform,
        binary,
      ),
    ];

    const planned: PlannedChange[] = [];
    for (const integration of integrations) {
      for (const change of await integration.uninstallPlan()) {
        if (change.before === null) continue;
        planned.push(change);
      }
    }

    if (planned.length === 0) {
      process.stdout.write('Nothing installed.\n');
      return 0;
    }

    for (const change of planned) process.stdout.write(`${renderDiff(change, palette)}\n`);

    if (!flags.has('yes') && !(await container.prompter.confirm('Remove these?'))) {
      process.stdout.write('Nothing was changed.\n');
      return 1;
    }

    await container.applyChanges().execute(planned);

    if (flags.has('purge')) {
      await container.files.remove(container.stateDir);
      process.stdout.write('Removed ~/.agent-guard, including grants and the audit log.\n');
    } else {
      process.stdout.write(
        `${palette.green('✓')} Integrations removed. ` +
          `Grants and the log are still in ${container.stateDir.value} — use --purge to delete them.\n`,
      );
    }
    return 0;
  }
}
