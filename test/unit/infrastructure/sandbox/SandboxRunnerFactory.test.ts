import { describe, expect, it } from 'vitest';
import type {
  SandboxCapabilities,
  SandboxCommand,
  SandboxRunResult,
  SandboxRunner,
} from '../../../../src/application/ports/SandboxRunner.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../../../src/domain/policy/SandboxPolicy.js';
import { SandboxRunnerFactory } from '../../../../src/infrastructure/sandbox/SandboxRunnerFactory.js';

class AvailableRunner implements SandboxRunner {
  calls = 0;

  constructor(readonly capabilities: SandboxCapabilities) {}

  async isAvailable(): Promise<boolean> {
    this.calls += 1;
    return true;
  }

  unenforceable(): readonly string[] {
    return [];
  }

  async run(
    _policy: SandboxPolicy,
    _context: PathContext,
    _command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    return { exitCode: 0, signal: null };
  }
}

describe('SandboxRunnerFactory platform selection', () => {
  it('does not select an available backend for the wrong OS', async () => {
    const linux = new AvailableRunner({
      mechanism: 'bubblewrap',
      fileModel: 'mount-namespace',
      networkGranularity: 'all-or-nothing',
    });
    const mac = new AvailableRunner({
      mechanism: 'seatbelt',
      fileModel: 'path-rules',
      networkGranularity: 'all-or-nothing',
    });
    const factory = new SandboxRunnerFactory([linux, mac]);

    await expect(factory.forPlatform('darwin')).resolves.toBe(mac);
    expect(linux.calls).toBe(0);
    expect(mac.calls).toBe(1);
  });

  it('offers no runner on Windows: the AppContainer backend is not shipped', async () => {
    // The AppContainer child never released its canary (production-readiness
    // P0.1), so the package ships no Windows backend rather than one that
    // fails its own proof. No runner is the honest answer there.
    await expect(new SandboxRunnerFactory().forPlatform('win32')).resolves.toBeNull();
  });
});
