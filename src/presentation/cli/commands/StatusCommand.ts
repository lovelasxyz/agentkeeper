import { Container } from '../../../composition/Container.js';
import { SandboxRunnerFactory } from '../../../infrastructure/sandbox/SandboxRunnerFactory.js';
import { Palette } from '../../messages/render.js';
import type { Command } from '../Command.js';

/**
 * `agent-guard status` (spec §14).
 *
 * Says plainly whether isolation is working and by what mechanism. This is the
 * screen where overstating a guarantee would do the most damage, so it reports
 * what is actually in place rather than what was configured.
 */
export class StatusCommand implements Command {
  readonly name = 'status';
  readonly usage = 'status';
  readonly summary = 'Show what is active, what is granted, and what is not enforced';

  async execute(): Promise<number> {
    const container = new Container();
    const palette = Palette.forStream(process.stdout);
    const lines: string[] = [];

    const config = await container.config();
    const runner = await new SandboxRunnerFactory().forPlatform(container.environment.platform);

    lines.push(palette.bold('Isolation (layer 1)'));
    if (!config.sandboxEnabled) {
      lines.push(`  ${palette.yellow('disabled')} in config.json — only the rule layer is active`);
    } else if (runner === null) {
      lines.push(
        `  ${palette.red('unavailable')} on ${container.environment.platform}: no supported mechanism`,
        `  ${palette.dim('Commands will refuse to start unless sandbox.onUnavailable is "warn".')}`,
      );
    } else {
      const capabilities = runner.capabilities;
      lines.push(
        `  ${palette.green('active')} via ${palette.bold(capabilities.mechanism)}`,
        `  ${palette.dim(`files: ${capabilities.fileModel}, network: ${capabilities.networkGranularity}`)}`,
      );
      if (capabilities.networkGranularity === 'all-or-nothing') {
        lines.push(
          `  ${palette.dim('Per-port network rules degrade to on/off on this mechanism.')}`,
        );
      }
    }

    lines.push('', palette.bold('Rules (layer 2)'));
    lines.push(
      `  starter profile: ${config.starterProfile}`,
      `  irreversible actions (family A): ${config.isEnabled('categoryA') ? 'on' : palette.dim('off — see README')}`,
      `  on hook failure: ${config.strictMode ? 'block (strict)' : 'allow (fail-open)'}`,
    );

    const grants = await container.grants.all();
    const runtime = grants.filter((grant) => grant.origin === 'runtime').length;
    lines.push('', palette.bold('Grants'));
    lines.push(
      `  ${grants.length} total — ${runtime} granted at runtime, ${grants.length - runtime} hand-written`,
      `  ${palette.dim(container.grants.location.value)}`,
    );

    const weekAgo = new Date(container.clock.now().getTime() - 7 * 24 * 3600 * 1000);
    const entries = await container.audit.since(weekAgo);
    const asked = entries.filter((entry) => entry.event === 'toolcall.ask').length;
    const blocked = entries.filter((entry) => entry.event === 'toolcall.blocked').length;

    lines.push('', palette.bold('Last 7 days'));
    lines.push(
      `  ${asked} question(s), ${blocked} refusal(s)`,
      `  ${palette.dim('Budget from the design: fewer than one question per week after the first.')}`,
    );

    process.stdout.write(`${lines.join('\n')}\n`);
    return 0;
  }
}
