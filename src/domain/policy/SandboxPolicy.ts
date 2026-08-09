import { createHash } from 'node:crypto';
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
  readonly networkEnforcement?: NetworkEnforcement;
  /** Runtime grants, kept separate so a backend can reject shapes it cannot confine. */
  readonly runtimeRefs?: readonly ResourceRef[];
}

export type NetworkBrokerTransport =
  | { readonly kind: 'tcp-loopback'; readonly port: number }
  | {
      readonly kind: 'unix-socket-relay';
      readonly socketPath: AbsolutePath;
      readonly relayScript: AbsolutePath;
      readonly port: number;
    };

export type NetworkEnforcement =
  | { readonly kind: 'closed' }
  | { readonly kind: 'unconfigured' }
  | { readonly kind: 'brokered'; readonly transport: NetworkBrokerTransport };

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
  readonly networkEnforcement: NetworkEnforcement;
  readonly runtimeRefs: readonly ResourceRef[];
  /**
   * Identity of the capabilities this policy grants (spec §31).
   *
   * Audit entries and session records name a policy by this value, so it must
   * move whenever the boundary moves and stay still otherwise. The launch-time
   * broker transport is excluded deliberately: a fresh loopback port each run
   * would make every session look like a different policy.
   */
  readonly policyHash: string;

  constructor(props: SandboxPolicyProps) {
    this.workspace = props.workspace;
    this.reads = Object.freeze([...props.reads]);
    this.writes = Object.freeze([...props.writes]);
    this.denies = Object.freeze([...props.denies]);
    this.overrides = Object.freeze([...props.overrides]);
    this.network = Object.freeze([...props.network]);
    this.networkEnforcement = freezeNetworkEnforcement(
      props.networkEnforcement ??
        (props.network.length === 0 ? { kind: 'closed' } : { kind: 'unconfigured' }),
    );
    this.runtimeRefs = Object.freeze([...(props.runtimeRefs ?? [])]);
    this.policyHash = digest(this);
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

  withNetworkEnforcement(networkEnforcement: NetworkEnforcement): SandboxPolicy {
    return new SandboxPolicy({
      workspace: this.workspace,
      reads: this.reads,
      writes: this.writes,
      denies: this.denies,
      overrides: this.overrides,
      network: this.network,
      networkEnforcement,
      runtimeRefs: this.runtimeRefs,
    });
  }
}

/**
 * Canonical digest of everything that decides what the agent can reach.
 *
 * Each section is sorted so that two policies granting the same capabilities
 * hash alike regardless of the order the builder happened to assemble them,
 * and section labels keep a rule from one list impersonating a rule in another.
 */
function digest(policy: SandboxPolicy): string {
  const section = (label: string, values: readonly { toString(): string }[]): string =>
    `${label}\n${values.map((value) => value.toString()).sort().join('\n')}`;

  return `sha256:${createHash('sha256')
    .update(
      [
        `workspace\n${policy.workspace.value}`,
        section('read', policy.reads),
        section('write', policy.writes),
        section('deny', policy.denies),
        section('override', policy.overrides.map(describeOverride)),
        section('network', policy.network),
        section('runtime', policy.runtimeRefs),
      ].join('\n--\n'),
    )
    .digest('hex')}`;
}

function describeOverride(override: PolicyOverride): string {
  return `${override.access} ${override.ref.toString()} (${override.reason})`;
}

function freezeNetworkEnforcement(value: NetworkEnforcement): NetworkEnforcement {
  if (value.kind !== 'brokered') return Object.freeze({ ...value });
  return Object.freeze({ kind: 'brokered', transport: Object.freeze({ ...value.transport }) });
}
