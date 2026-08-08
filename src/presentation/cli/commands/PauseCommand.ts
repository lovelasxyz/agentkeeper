import { Container } from '../../../composition/Container.js';
import { parseDuration } from './LogCommand.js';
import type { Command } from '../Command.js';

/**
 * `agent-guard pause <duration>` / `resume` (spec §10.2).
 *
 * Pauses the *watching*, never the isolation. Layer 1 is a property of how the
 * process was started and cannot be suspended by a later command — which is
 * exactly why an injected "pause the guard" instruction buys nothing.
 */
export class PauseCommand implements Command {
  readonly name = 'pause';
  readonly usage = 'pause <30m|1h|today> | pause --resume';
  readonly summary = 'Silence notifications for a while (isolation stays on)';

  async execute(args: readonly string[]): Promise<number> {
    const container = new Container();
    const path = container.stateDir.join('pause.json');

    if (args[0] === '--resume' || args[0] === 'resume') {
      await container.files.remove(path);
      process.stdout.write('Resumed.\n');
      return 0;
    }

    const raw = args[0] ?? '1h';
    const until = new Date(
      container.clock.now().getTime() + (raw === 'today' ? 8 * 3600_000 : parseDuration(raw)),
    );

    await container.files.write(path, `${JSON.stringify({ until: until.toISOString() })}\n`);
    await container.audit.append({
      at: container.clock.now(),
      event: 'pause.set',
      details: { until: until.toISOString() },
    });

    process.stdout.write(
      `Notifications paused until ${until.toISOString()}.\n` +
        'Isolation is unaffected: it is fixed when a command starts and cannot be paused.\n',
    );
    return 0;
  }
}
