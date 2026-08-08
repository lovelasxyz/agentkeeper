import { Container } from '../../../composition/Container.js';
import { SandboxRunnerFactory } from '../../../infrastructure/sandbox/SandboxRunnerFactory.js';
import {
  ClaudeHookIntegration,
  DaemonIntegration,
  GitHookIntegration,
  ShellFunctionsIntegration,
} from '../../../infrastructure/install/integrations.js';
import { BaselineCollector } from '../../daemon/BaselineCollector.js';
import { MESSAGES, Palette, renderDiff } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';
import type { Integration, PlannedChange } from '../../../application/ports/Integration.js';

/**
 * `agent-guard init` (spec §10.1).
 *
 * Shows every change before making it, and there is no `postinstall` anywhere
 * in this package — a dependency that writes itself into your configuration at
 * install time is indistinguishable from malware, and saying so is part of the
 * product.
 */
export class InitCommand implements Command {
  readonly name = 'init';
  readonly usage = 'init [--yes] [--profile web|python|infra|minimal]';
  readonly summary = 'Set up isolation, hooks and the watcher (asks before every change)';

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const container = new Container();
    const palette = Palette.forStream(process.stdout);
    const write = (text: string): void => void process.stdout.write(`${text}\n`);

    write(palette.bold('agent-guard init'));
    write('');

    // 1 — is isolation even possible here?
    const runner = await new SandboxRunnerFactory().forPlatform(container.environment.platform);
    if (runner === null) {
      write(`${palette.red('!')} ${MESSAGES.noMechanism}`);
      write(
        palette.dim(
          container.environment.platform === 'linux'
            ? '  Install bubblewrap (`apt install bubblewrap`) and run init again.'
            : '  Layer 1 is unavailable; only the rule layer will be installed.',
        ),
      );
      write('');
    } else {
      write(`${palette.green('✓')} Isolation available: ${palette.bold(runner.capabilities.mechanism)}`);
      write('');
    }

    // 2 — starter profile
    const profileId = flags.value('profile') ?? 'web';
    const profiles = container.profiles();
    const profile = await profiles.load(profileId);
    write(`Starter profile: ${palette.bold(profile.name)} — ${profile.description}`);
    write(palette.dim(`  Others: ${(await profiles.available()).join(', ')}`));
    write('');

    // 3 — plan every change, then show it
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
      const changes = await integration.plan();
      if (changes.length === 0) continue;
      write(`${palette.bold(integration.id)} — ${integration.description}`);
      for (const change of changes) {
        write(renderDiff(change, palette));
      }
      write('');
      planned.push(...changes);
    }

    if (planned.some((change) => change.path.basename.startsWith('.zshrc'))) {
      write(palette.dim(MESSAGES.shellIrony));
      write('');
    }

    // 4 — confirm
    if (!flags.has('yes')) {
      const approved = await container.prompter.confirm(
        `Apply ${planned.length} change(s)? Originals are saved to ${container.backupDir.value}.`,
      );
      if (!approved) {
        write('Nothing was changed.');
        return 1;
      }
    }

    await container.applyChanges().execute(planned);

    // 5 — the config file, and the trusted snapshot of zone B
    await container.files.write(
      container.stateDir.join('config.json'),
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

    const collector = new BaselineCollector(container.files, container.paths, container.clock);
    const snapshot = await collector.collect({
      home: container.environment.home,
      workspace: container.environment.cwd,
      platform: container.environment.platform,
    });
    await container.baseline.save(snapshot);

    write(`${palette.green('✓')} Done. ${snapshot.length} file(s) recorded as the trusted baseline.`);
    write('');
    write('Next: open a new shell, then run `claude` as usual. Check `agent-guard status`.');
    return 0;
  }
}
