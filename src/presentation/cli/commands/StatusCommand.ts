import { DoctorCommand } from './DoctorCommand.js';
import type { Command } from '../Command.js';

/** Backwards-compatible concise entry point backed by the same real canary as doctor. */
export class StatusCommand implements Command {
  readonly name = 'status';
  readonly usage = 'status [--json]';
  readonly summary = 'Show the effective protection status from a fresh deny-canary';

  async execute(args: readonly string[]): Promise<number> {
    return new DoctorCommand().execute(args);
  }
}
