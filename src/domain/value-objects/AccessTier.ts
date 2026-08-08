export type AccessTierLevel = 1 | 2;

/**
 * Spec §4.5 — the load-bearing distinction of the whole permission model.
 *
 * Tier 1 is everyday: a wrong "yes" costs little, so it may be asked for while
 * the agent is running. Tier 2 is credentials, persistence and history: an
 * injected prompt can produce the request at the exact moment the user is not
 * paying attention, so there is no runtime path to granting it at all. The gap
 * between "ask" and "receive" is what makes the model hold.
 */
export class AccessTier {
  static readonly EVERYDAY = new AccessTier(1, true);
  static readonly DANGEROUS = new AccessTier(2, false);

  private static readonly ALL: readonly AccessTier[] = [AccessTier.EVERYDAY, AccessTier.DANGEROUS];

  private constructor(
    readonly level: AccessTierLevel,
    readonly canBeGrantedAtRuntime: boolean,
  ) {
    Object.freeze(this);
  }

  static ofLevel(level: AccessTierLevel): AccessTier {
    const found = AccessTier.ALL.find((tier) => tier.level === level);
    if (!found) throw new Error(`Unknown access tier: ${JSON.stringify(level)}`);
    return found;
  }

  toString(): string {
    return `tier ${this.level}`;
  }

  toJSON(): AccessTierLevel {
    return this.level;
  }
}
