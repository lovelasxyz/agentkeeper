import { Container } from '../../../composition/Container.js';
import type { Command } from '../Command.js';

const MAX_PAUSE_MILLISECONDS = 24 * 60 * 60_000;

/**
 * `agentkeeper pause <duration>` / `resume` (spec §10.2).
 *
 * Pauses desktop notifications, never comparison, audit, pending incident
 * capture, or isolation. An injected "pause the guard" instruction therefore
 * cannot convert persistence drift into trusted state.
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
      await container.audit.append({
        at: container.clock.now(),
        event: 'pause.resumed',
        details: {},
      });
      process.stdout.write('Resumed.\n');
      return 0;
    }

    const raw = args[0] ?? '1h';
    const duration = parsePauseDuration(raw);
    if (duration === null) {
      container.logger.error('pause duration must be between 1 minute and 24 hours');
      return 2;
    }
    const until = new Date(container.clock.now().getTime() + duration);

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

export function parsePauseDuration(raw: string): number | null {
  if (raw === 'today') return 8 * 60 * 60_000;
  const match = /^(\d+)([mhd])$/.exec(raw.trim());
  if (match === null) return null;
  const amount = Number(match[1]);
  if (!Number.isSafeInteger(amount) || amount < 1) return null;
  const multiplier =
    match[2] === 'm' ? 60_000 : match[2] === 'h' ? 60 * 60_000 : 24 * 60 * 60_000;
  const milliseconds = amount * multiplier;
  return milliseconds <= MAX_PAUSE_MILLISECONDS ? milliseconds : null;
}
