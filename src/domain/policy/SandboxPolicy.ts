import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { NetworkRule } from '../value-objects/NetworkRule.js';
import type { ResourceRef } from '../value-objects/ResourceRef.js';
import type { Access } from '../paths/SensitivePath.js';
import type { PathContext } from '../paths/PathContext.js';
import type { DenyRule } from './DenyRule.js';

/** An allow rule that deliberately outranks the deny list (hand-written grants only). */
export interface PolicyOverride {
  readonly ref: ResourceRef;
  readonly access: Access;
  readonly reason: string;
}

export interface SandboxPolicyProps {
  readonly workspace: AbsolutePath;
  readonly reads: readonly ResourceRef[];
  readonly writes: readonly ResourceRef[];
  readonly denies: readonly DenyRule[];
  readonly overrides: readonly PolicyOverride[];
  readonly network: readonly NetworkRule[];
}

/**
 * Platform-independent model of what the agent's world contains (spec §8.3).
 *
 * Knows nothing about Seatbelt syntax or bubblewrap flags — translation lives
 * in `infrastructure/sandbox`. That separation is what lets the entire policy
 * be tested without spawning a single process, and lets a new platform be added
 * without touching a line of policy logic.
 *
 * Evaluation order is `allow → deny → override`, mirroring exactly how the
 * generated profiles behave at runtime. If this method and the real sandbox
 * ever disagreed, every unit test in this project would be measuring fiction —
 * so the sandbox test suite (§9.3) re-checks the same expectations for real.
 */
export class SandboxPolicy {
  readonly workspace: AbsolutePath;
  readonly reads: readonly ResourceRef[];
  readonly writes: readonly ResourceRef[];
  readonly denies: readonly DenyRule[];
  readonly overrides: readonly PolicyOverride[];
  readonly network: readonly NetworkRule[];

  constructor(props: SandboxPolicyProps) {
    this.workspace = props.workspace;
    this.reads = Object.freeze([...props.reads]);
    this.writes = Object.freeze([...props.writes]);
    this.denies = Object.freeze([...props.denies]);
    this.overrides = Object.freeze([...props.overrides]);
    this.network = Object.freeze([...props.network]);
    Object.freeze(this);
  }

  allowsRef(access: Access): readonly ResourceRef[] {
    return access === 'read' ? this.reads : this.writes;
  }

  allows(access: Access, path: AbsolutePath, context: PathContext): boolean {
    if (this.isOverridden(access, path)) return true;
    if (this.isDenied(access, path, context)) return false;
    return this.allowsRef(access).some((ref) => ref.covers(path));
  }

  isDenied(access: Access, path: AbsolutePath, context: PathContext): boolean {
    return this.denies.some(
      (deny) => deny.access === access && deny.matches(path, context.home),
    );
  }

  private isOverridden(access: Access, path: AbsolutePath): boolean {
    return this.overrides.some(
      (override) => override.access === access && override.ref.covers(path),
    );
  }

  allowsNetwork(): boolean {
    return this.network.length > 0;
  }
}
