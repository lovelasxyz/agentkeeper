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
 *
 * Windows deliberately has no candidate: the AppContainer backend never
 * released its canary child (production-readiness P0.1), and shipping it
 * would be claiming a boundary that was never proven. The platform reports
 * UNPROTECTED until a backend passes its own deny canary on real hardware.
 */
export class SandboxRunnerFactory {
  constructor(
    private readonly candidates: readonly SandboxRunner[] = [
      new SeatbeltRunner(),
      new BubblewrapRunner(),
    ],
  ) {}

  async forPlatform(platform: Platform): Promise<SandboxRunner | null> {
    for (const candidate of this.candidates) {
      if (!matchesPlatform(candidate, platform)) continue;
      if (await candidate.isAvailable()) return candidate;
    }
    return null;
  }

  unconfined(): SandboxRunner {
    return new NoopRunner();
  }
}

function matchesPlatform(candidate: SandboxRunner, platform: Platform): boolean {
  switch (candidate.capabilities.mechanism) {
    case 'seatbelt':
      return platform === 'darwin';
    case 'bubblewrap':
      return platform === 'linux';
    case 'none':
      return false;
  }
}
