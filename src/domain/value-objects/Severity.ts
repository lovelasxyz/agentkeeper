export type SeverityName = 'low' | 'medium' | 'high' | 'critical';

const ORDER: readonly SeverityName[] = ['low', 'medium', 'high', 'critical'];

/** Interned ordinal value object, so `===` is a valid comparison everywhere. */
export class Severity {
  static readonly LOW = new Severity('low', 0);
  static readonly MEDIUM = new Severity('medium', 1);
  static readonly HIGH = new Severity('high', 2);
  static readonly CRITICAL = new Severity('critical', 3);

  private static readonly ALL: readonly Severity[] = [
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
  ];

  private constructor(
    readonly name: SeverityName,
    readonly rank: number,
  ) {
    Object.freeze(this);
  }

  static of(name: SeverityName): Severity {
    const found = Severity.ALL.find((severity) => severity.name === name);
    if (!found) throw new Error(`Unknown severity: ${JSON.stringify(name)}`);
    return found;
  }

  static values(): readonly Severity[] {
    return Severity.ALL;
  }

  isAtLeast(other: Severity): boolean {
    return this.rank >= other.rank;
  }

  /**
   * Spec §6.6: a persistence finding raised while the sandbox is active means
   * isolation was bypassed, which is strictly worse than the same finding on
   * an unprotected machine.
   */
  escalated(): Severity {
    const next = ORDER[Math.min(this.rank + 1, ORDER.length - 1)];
    return Severity.of(next ?? this.name);
  }

  toString(): string {
    return this.name;
  }

  toJSON(): SeverityName {
    return this.name;
  }
}
