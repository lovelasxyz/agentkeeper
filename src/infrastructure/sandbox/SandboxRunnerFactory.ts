import { BubblewrapRunner } from './BubblewrapRunner.js';
import { NoopRunner } from './NoopRunner.js';
import { SeatbeltRunner } from './SeatbeltRunner.js';
import type { SandboxRunner } from '../../application/ports/SandboxRunner.js';
import type { Platform } from '../../domain/value-objects/Platform.js';

/**
 * Strategy selection by platform (spec §8.3).
 *
 * Returns `null` rather than silently falling back to `NoopRunner`: whether an
 * unprotected run is acceptable is the user's decision to make in config, not
 * this factory's to make by default.
 */
export class SandboxRunnerFactory {
  constructor(
    private readonly candidates: readonly SandboxRunner[] = [
      new SeatbeltRunner(),
      new BubblewrapRunner(),
    ],
  ) {}

  async forPlatform(_platform: Platform): Promise<SandboxRunner | null> {
    for (const candidate of this.candidates) {
      if (await candidate.isAvailable()) return candidate;
    }
    return null;
  }

  unconfined(): SandboxRunner {
    return new NoopRunner();
  }
}
