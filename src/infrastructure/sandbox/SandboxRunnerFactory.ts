import { BubblewrapRunner } from './BubblewrapRunner.js';
import { NoopRunner } from './NoopRunner.js';
import { SeatbeltRunner } from './SeatbeltRunner.js';
import { WindowsSandboxRunner } from './WindowsSandboxRunner.js';
import type { SandboxRunner } from '../../application/ports/SandboxRunner.js';
import type { Platform } from '../../domain/value-objects/Platform.js';

/**
 * Strategy selection by platform (spec §8.3).
 *
 * Returns `null` rather than silently falling back to `NoopRunner`: whether an
 * unprotected run is acceptable is the user's decision to make in config, not
 * this factory's to make by default.
 *
 * The Windows candidate exists, but the release package ships no native
 * helper while its deny canary has never passed (production-readiness P0.1):
 * `structuralSupport` then reports the helper missing and the platform stays
 * honestly UNPROTECTED. On CI runners the helper is built, so the suite
 * exercises the real boundary on real Windows hardware.
 */
export class SandboxRunnerFactory {
  constructor(
    private readonly candidates: readonly SandboxRunner[] = [
      new SeatbeltRunner(),
      new BubblewrapRunner(),
      new WindowsSandboxRunner(),
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
    case 'appcontainer':
      return platform === 'win32';
    case 'none':
      return false;
  }
}
