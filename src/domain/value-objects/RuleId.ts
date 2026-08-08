const FORMAT = /^AG-([A-Z])(\d{3})$/;

/** Stable rule identifier, `AG-<category><number>` (spec §6). */
export class RuleId {
  private constructor(
    private readonly value: string,
    readonly category: string,
    readonly number: number,
  ) {
    Object.freeze(this);
  }

  static of(raw: string): RuleId {
    const match = FORMAT.exec(raw);
    if (!match) throw new Error(`Malformed rule id: ${JSON.stringify(raw)}`);
    return new RuleId(raw, match[1] as string, Number(match[2]));
  }

  equals(other: RuleId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }

  toJSON(): string {
    return this.value;
  }
}
