import { AccessTier } from '../value-objects/AccessTier.js';
import { Disposition } from '../value-objects/Disposition.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { ResourceRef } from '../value-objects/ResourceRef.js';
import type { PathContext } from '../paths/PathContext.js';
import type { Access, SensitivePath } from '../paths/SensitivePath.js';
import type { SensitivePathRegistry } from '../paths/SensitivePathRegistry.js';

/**
 * One question about one path, answered once.
 *
 * Every answer the security model gives about a (path, access) pair — its
 * tier, its disposition, which entry is responsible — derives from this
 * single match set. Computing them separately would ask the registry the same
 * question three times, and a second answer to the same question is how a
 * security model quietly loses. The match is computed in the constructor;
 * the getters only read it.
 */
export class AccessDecision {
  constructor(
    private readonly matches: readonly SensitivePath[],
    private readonly access: Access,
  ) {}

  get tier(): AccessTier {
    const dangerous = this.matches.some((entry) => entry.tierFor(this.access).level === 2);
    return dangerous ? AccessTier.DANGEROUS : AccessTier.EVERYDAY;
  }

  /** Strictest disposition the registry attaches to this path and operation. */
  get disposition(): Disposition {
    return Disposition.strictest(
      this.matches.map((entry) => entry.dispositionFor(this.access)),
    );
  }

  /** The registry entry responsible for the classification, for user-facing copy. */
  get explanation(): SensitivePath | null {
    return (
      this.matches.find((entry) => entry.tierFor(this.access).level === 2) ??
      this.matches[0] ??
      null
    );
  }
}

/**
 * Answers the one question spec §4.5 hangs on: may this resource be handed
 * over in response to a request made while the agent is running?
 *
 * Deliberately the *only* place that decision is made. Anything else that
 * wanted to reason about tiers would be a second answer to the same question,
 * and a second answer is how a security model quietly loses.
 */
export class AccessTierResolver {
  /**
   * Tier 2 anchors per (platform, access, home). The registry is frozen for
   * the process and a daemon's home never changes, so the anchors are
   * computed on first use and reused rather than allocated per tool call.
   */
  private readonly anchorCache = new Map<string, readonly AbsolutePath[]>();

  constructor(private readonly registry: SensitivePathRegistry) {}

  /** The match set for this (path, access), computed exactly once. */
  decide(path: AbsolutePath, access: Access, context: PathContext): AccessDecision {
    return new AccessDecision(this.registry.matching(path, context), access);
  }

  tierOf(path: AbsolutePath, access: Access, context: PathContext): AccessTier {
    return this.decide(path, access, context).tier;
  }

  /** Strictest disposition the registry attaches to this path and operation. */
  dispositionOf(path: AbsolutePath, access: Access, context: PathContext): Disposition {
    return this.decide(path, access, context).disposition;
  }

  /**
   * A subtree may not be granted when it is itself dangerous, or when it would
   * swallow the anchor of any pattern that is tier 2 for this operation —
   * granting `~` must not become a roundabout way of handing over `~/.ssh`.
   */
  canGrantAtRuntime(ref: ResourceRef, access: Access, context: PathContext): boolean {
    if (!this.decide(ref.path, access, context).tier.canBeGrantedAtRuntime) return false;
    if (ref.scope === 'file') return true;

    return !this.dangerousAnchors(access, context).some((anchor) => ref.path.contains(anchor));
  }

  /** The registry entry responsible for a classification, for user-facing copy. */
  explain(path: AbsolutePath, access: Access, context: PathContext): SensitivePath | null {
    return this.decide(path, access, context).explanation;
  }

  private dangerousAnchors(access: Access, context: PathContext): readonly AbsolutePath[] {
    const key = `${context.platform}:${access}:${context.home.value}`;
    const cached = this.anchorCache.get(key);
    if (cached !== undefined) return cached;
    const anchors = this.registry
      .dangerousFor(context.platform, access)
      .flatMap((entry) => {
        const anchor = entry.literalPrefix(context.home);
        return anchor === null ? [] : [anchor];
      });
    this.anchorCache.set(key, anchors);
    return anchors;
  }
}
