import { AccessTier } from '../value-objects/AccessTier.js';
import { Disposition } from '../value-objects/Disposition.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { ResourceRef } from '../value-objects/ResourceRef.js';
import type { PathContext } from '../paths/PathContext.js';
import type { Access, SensitivePath } from '../paths/SensitivePath.js';
import type { SensitivePathRegistry } from '../paths/SensitivePathRegistry.js';

/**
 * Answers the one question spec §4.5 hangs on: may this resource be handed
 * over in response to a request made while the agent is running?
 *
 * Deliberately the *only* place that decision is made. Anything else that
 * wanted to reason about tiers would be a second answer to the same question,
 * and a second answer is how a security model quietly loses.
 */
export class AccessTierResolver {
  constructor(private readonly registry: SensitivePathRegistry) {}

  tierOf(path: AbsolutePath, access: Access, context: PathContext): AccessTier {
    const dangerous = this.registry
      .matching(path, context)
      .some((entry) => entry.tierFor(access).level === 2);
    return dangerous ? AccessTier.DANGEROUS : AccessTier.EVERYDAY;
  }

  /** Strictest disposition the registry attaches to this path and operation. */
  dispositionOf(path: AbsolutePath, access: Access, context: PathContext): Disposition {
    return Disposition.strictest(
      this.registry.matching(path, context).map((entry) => entry.dispositionFor(access)),
    );
  }

  /**
   * A subtree may not be granted when it is itself dangerous, or when it would
   * swallow the anchor of any pattern that is tier 2 for this operation —
   * granting `~` must not become a roundabout way of handing over `~/.ssh`.
   */
  canGrantAtRuntime(ref: ResourceRef, access: Access, context: PathContext): boolean {
    if (!this.tierOf(ref.path, access, context).canBeGrantedAtRuntime) return false;
    if (ref.scope === 'file') return true;

    return !this.registry.dangerousFor(context.platform, access).some((entry) => {
      const anchor = entry.literalPrefix(context.home);
      return anchor !== null && ref.path.contains(anchor);
    });
  }

  /** The registry entry responsible for a classification, for user-facing copy. */
  explain(path: AbsolutePath, access: Access, context: PathContext): SensitivePath | null {
    const matches = this.registry.matching(path, context);
    return matches.find((entry) => entry.tierFor(access).level === 2) ?? matches[0] ?? null;
  }
}
