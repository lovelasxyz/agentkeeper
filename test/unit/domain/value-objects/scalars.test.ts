import { describe, expect, it } from 'vitest';
import { AccessTier } from '../../../../src/domain/value-objects/AccessTier.js';
import { ContentHash } from '../../../../src/domain/value-objects/ContentHash.js';
import { Disposition } from '../../../../src/domain/value-objects/Disposition.js';
import { RuleId } from '../../../../src/domain/value-objects/RuleId.js';
import { Severity } from '../../../../src/domain/value-objects/Severity.js';

describe('Severity', () => {
  it('parses each known level', () => {
    for (const name of ['low', 'medium', 'high', 'critical'] as const) {
      expect(Severity.of(name).name).toBe(name);
    }
  });

  it('rejects an unknown level', () => {
    expect(() => Severity.of('catastrophic' as never)).toThrow(/severity/i);
  });

  it('orders levels', () => {
    expect(Severity.CRITICAL.isAtLeast(Severity.HIGH)).toBe(true);
    expect(Severity.LOW.isAtLeast(Severity.HIGH)).toBe(false);
    expect(Severity.HIGH.isAtLeast(Severity.HIGH)).toBe(true);
  });

  it('escalates one level, per spec §6.6', () => {
    expect(Severity.MEDIUM.escalated()).toBe(Severity.HIGH);
    expect(Severity.HIGH.escalated()).toBe(Severity.CRITICAL);
  });

  it('cannot escalate past critical', () => {
    expect(Severity.CRITICAL.escalated()).toBe(Severity.CRITICAL);
  });

  it('interns instances so identity comparison is safe', () => {
    expect(Severity.of('high')).toBe(Severity.HIGH);
  });
});

describe('Disposition', () => {
  it('parses each known disposition', () => {
    for (const name of ['block', 'ask', 'observe'] as const) {
      expect(Disposition.of(name).name).toBe(name);
    }
  });

  it('rejects an unknown disposition', () => {
    expect(() => Disposition.of('allow' as never)).toThrow(/disposition/i);
  });

  it('knows which dispositions interrupt the user', () => {
    expect(Disposition.ASK.interrupts).toBe(true);
    expect(Disposition.BLOCK.interrupts).toBe(false);
    expect(Disposition.OBSERVE.interrupts).toBe(false);
  });

  it('knows which dispositions stop the action', () => {
    expect(Disposition.BLOCK.stops).toBe(true);
    expect(Disposition.ASK.stops).toBe(false);
  });

  it('picks the strictest of several', () => {
    expect(Disposition.strictest([Disposition.OBSERVE, Disposition.BLOCK, Disposition.ASK])).toBe(
      Disposition.BLOCK,
    );
    expect(Disposition.strictest([Disposition.OBSERVE, Disposition.ASK])).toBe(Disposition.ASK);
  });

  it('defaults to observe when there is nothing to compare', () => {
    expect(Disposition.strictest([])).toBe(Disposition.OBSERVE);
  });
});

describe('AccessTier', () => {
  it('exposes the two tiers from spec §4.5', () => {
    expect(AccessTier.EVERYDAY.level).toBe(1);
    expect(AccessTier.DANGEROUS.level).toBe(2);
  });

  it('allows runtime grants only for tier 1', () => {
    expect(AccessTier.EVERYDAY.canBeGrantedAtRuntime).toBe(true);
    expect(AccessTier.DANGEROUS.canBeGrantedAtRuntime).toBe(false);
  });

  it('parses a numeric level', () => {
    expect(AccessTier.ofLevel(2)).toBe(AccessTier.DANGEROUS);
  });

  it('rejects an unknown level', () => {
    expect(() => AccessTier.ofLevel(3 as never)).toThrow(/tier/i);
  });
});

describe('RuleId', () => {
  it('accepts the documented format', () => {
    expect(RuleId.of('AG-H001').toString()).toBe('AG-H001');
  });

  it('exposes the category letter', () => {
    expect(RuleId.of('AG-P007').category).toBe('P');
  });

  it.each(['H001', 'AG-h001', 'AG-H1', 'AG-H0011', 'AG-HH01', ''])(
    'rejects malformed id %s',
    (raw) => {
      expect(() => RuleId.of(raw)).toThrow(/rule id/i);
    },
  );

  it('compares by value', () => {
    expect(RuleId.of('AG-B005').equals(RuleId.of('AG-B005'))).toBe(true);
    expect(RuleId.of('AG-B005').equals(RuleId.of('AG-B006'))).toBe(false);
  });
});

describe('ContentHash', () => {
  it('produces a prefixed sha-256 digest', () => {
    const hash = ContentHash.fromContent('hello');
    expect(hash.toString()).toBe(
      'sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    );
  });

  it('is deterministic', () => {
    expect(ContentHash.fromContent('x').equals(ContentHash.fromContent('x'))).toBe(true);
  });

  it('separates different content', () => {
    expect(ContentHash.fromContent('x').equals(ContentHash.fromContent('y'))).toBe(false);
  });

  it('hashes bytes and the equivalent string identically', () => {
    expect(
      ContentHash.fromContent(new TextEncoder().encode('hello')).equals(
        ContentHash.fromContent('hello'),
      ),
    ).toBe(true);
  });

  it('round-trips through its serialised form', () => {
    const hash = ContentHash.fromContent('payload');
    expect(ContentHash.parse(hash.toString()).equals(hash)).toBe(true);
  });

  it('rejects a malformed serialised form', () => {
    expect(() => ContentHash.parse('md5:abc')).toThrow(/hash/i);
    expect(() => ContentHash.parse('sha256:nothex')).toThrow(/hash/i);
  });

  it('offers a short form for terminal output', () => {
    expect(ContentHash.fromContent('hello').short).toBe('2cf24dba');
  });
});
