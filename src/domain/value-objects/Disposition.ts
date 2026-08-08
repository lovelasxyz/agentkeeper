export type DispositionName = 'block' | 'ask' | 'observe';

/**
 * What happens when a rule fires (spec §7).
 *
 * `block` is stricter than `ask` on purpose: a silent refusal cannot be talked
 * out of the user by an injected prompt, an interactive question can.
 */
export class Disposition {
  static readonly BLOCK = new Disposition('block', 2, true, false);
  static readonly ASK = new Disposition('ask', 1, false, true);
  static readonly OBSERVE = new Disposition('observe', 0, false, false);

  private static readonly ALL: readonly Disposition[] = [
    Disposition.BLOCK,
    Disposition.ASK,
    Disposition.OBSERVE,
  ];

  private constructor(
    readonly name: DispositionName,
    readonly strictness: number,
    /** The action is refused. */
    readonly stops: boolean,
    /** The user is interrupted with a question. */
    readonly interrupts: boolean,
  ) {
    Object.freeze(this);
  }

  static of(name: DispositionName): Disposition {
    const found = Disposition.ALL.find((disposition) => disposition.name === name);
    if (!found) throw new Error(`Unknown disposition: ${JSON.stringify(name)}`);
    return found;
  }

  static values(): readonly Disposition[] {
    return Disposition.ALL;
  }

  static strictest(dispositions: readonly Disposition[]): Disposition {
    return dispositions.reduce(
      (strictest, candidate) =>
        candidate.strictness > strictest.strictness ? candidate : strictest,
      Disposition.OBSERVE,
    );
  }

  toString(): string {
    return this.name;
  }

  toJSON(): DispositionName {
    return this.name;
  }
}
