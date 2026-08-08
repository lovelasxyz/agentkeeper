import { Container } from '../../../composition/Container.js';
import { Palette } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';

/** `agent-guard log [--since 24h]` — the append-only record (spec §10.2). */
export class LogCommand implements Command {
  readonly name = 'log';
  readonly usage = 'log [--since 24h|7d]';
  readonly summary = 'Show what agent-guard recorded';

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const container = new Container();
    const palette = Palette.forStream(process.stdout);

    const since = new Date(container.clock.now().getTime() - parseDuration(flags.value('since')));
    const entries = await container.audit.since(since);

    if (entries.length === 0) {
      process.stdout.write('Nothing recorded in that period.\n');
      return 0;
    }

    for (const entry of entries) {
      const details = Object.entries(entry.details)
        .filter(([, value]) => value !== null && value !== undefined)
        .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
        .join(' ');
      process.stdout.write(
        `${palette.dim(entry.at.toISOString())} ${palette.bold(entry.event)} ${details}\n`,
      );
    }
    return 0;
  }
}

/** Accepts `30m`, `24h`, `7d`. Defaults to a day. */
export function parseDuration(raw: string | null): number {
  if (raw === null) return 24 * 3600_000;
  const match = /^(\d+)([mhd])$/.exec(raw.trim());
  if (match === null) return 24 * 3600_000;

  const amount = Number(match[1]);
  const unit = match[2];
  if (unit === 'm') return amount * 60_000;
  if (unit === 'h') return amount * 3600_000;
  return amount * 24 * 3600_000;
}
