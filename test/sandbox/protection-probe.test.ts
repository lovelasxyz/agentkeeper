import { describe, expect, it } from 'vitest';
import { AssessProtection } from '../../src/application/use-cases/AssessProtection.js';
import { SandboxPolicy } from '../../src/domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../src/domain/value-objects/ResourceRef.js';
import { NodeSandboxProbe } from '../../src/infrastructure/sandbox/NodeSandboxProbe.js';
import { SeatbeltRunner } from '../../src/infrastructure/sandbox/SeatbeltRunner.js';

const describeOnDarwin = process.platform === 'darwin' ? describe : describe.skip;

describeOnDarwin('protection status against the real macOS sandbox', () => {
  it('passes the deny canary but remains DEGRADED because Seatbelt broadly reads system paths', async () => {
    const workspace = AbsolutePath.of('/work');
    const policy = new SandboxPolicy({
      workspace,
      reads: [ResourceRef.subtree(workspace)],
      writes: [ResourceRef.subtree(workspace)],
      denies: [],
      overrides: [],
      network: [],
    });

    const status = await new AssessProtection(new NodeSandboxProbe()).execute({
      platform: 'darwin',
      runner: new SeatbeltRunner(),
      policy,
      context: {
        home: AbsolutePath.of('/Users/protection-status-test'),
        workspace,
        platform: 'darwin',
      },
    });

    expect(status.level, JSON.stringify(status)).toBe('DEGRADED');
    expect(status.capabilities.denyCanary).toBe('passed');
    expect(status.reasons.map((reason) => reason.code)).toContain(
      'seatbelt.broad-system-read',
    );
  });
});
