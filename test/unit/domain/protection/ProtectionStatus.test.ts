import { describe, expect, it } from 'vitest';
import {
  ProtectionStatus,
  type ProtectionCapabilities,
} from '../../../../src/domain/protection/ProtectionStatus.js';

const completeCapabilities: ProtectionCapabilities = {
  mechanism: 'bubblewrap',
  denyCanary: 'passed',
  filesystem: 'enforced',
  processTree: 'enforced',
  network: 'denied',
};

describe('ProtectionStatus', () => {
  it('allows PROTECTED only for a verified, complete effective boundary', () => {
    const status = ProtectionStatus.create({
      level: 'PROTECTED',
      capabilities: completeCapabilities,
      reasons: [],
    });

    expect(status.level).toBe('PROTECTED');
    expect(status.isProtected).toBe(true);
    expect(Object.isFrozen(status)).toBe(true);
    expect(Object.isFrozen(status.capabilities)).toBe(true);
    expect(Object.isFrozen(status.reasons)).toBe(true);
  });

  it.each([
    ['deny canary was not run', { denyCanary: 'not-run' }],
    ['deny canary failed', { denyCanary: 'failed' }],
    ['filesystem isolation is partial', { filesystem: 'partial' }],
    ['process-tree containment is unverified', { processTree: 'unverified' }],
    ['network access is only port-filtered', { network: 'port-only' }],
    ['network is unrestricted', { network: 'unrestricted' }],
  ] as const)('rejects a false PROTECTED claim when %s', (_label, override) => {
    expect(() =>
      ProtectionStatus.create({
        level: 'PROTECTED',
        capabilities: { ...completeCapabilities, ...override },
        reasons: [],
      }),
    ).toThrow(/PROTECTED requires/);
  });

  it('rejects a PROTECTED claim that still has a degradation reason', () => {
    expect(() =>
      ProtectionStatus.create({
        level: 'PROTECTED',
        capabilities: completeCapabilities,
        reasons: [
          {
            code: 'policy.unenforceable',
            area: 'policy',
            message: 'One policy rule cannot be enforced.',
          },
        ],
      }),
    ).toThrow(/PROTECTED requires/);
  });

  it.each(['DEGRADED', 'UNPROTECTED', 'BYPASSED'] as const)(
    'represents %s without converting it into a reassuring boolean',
    (level) => {
      const status = ProtectionStatus.create({
        level,
        capabilities: {
          mechanism: 'none',
          denyCanary: 'not-run',
          filesystem: 'none',
          processTree: 'none',
          network: 'none',
        },
        reasons: [
          {
            code: 'sandbox.not-active',
            area: 'sandbox',
            message: 'No effective sandbox boundary is active.',
          },
        ],
      });

      expect(status.level).toBe(level);
      expect(status.isProtected).toBe(false);
    },
  );
});
