export type ProtectionLevel = 'PROTECTED' | 'DEGRADED' | 'UNPROTECTED' | 'BYPASSED';

export type ProtectionMechanism = 'seatbelt' | 'bubblewrap' | 'appcontainer' | 'none';
export type DenyCanaryState = 'passed' | 'failed' | 'not-run';
export type EnforcementState = 'enforced' | 'partial' | 'unverified' | 'none';
export type NetworkProtection =
  | 'denied'
  | 'brokered'
  | 'port-only'
  | 'unrestricted'
  | 'none';

/** Effective guarantees, not features inferred from an installed executable. */
export interface ProtectionCapabilities {
  readonly mechanism: ProtectionMechanism;
  readonly denyCanary: DenyCanaryState;
  readonly filesystem: EnforcementState;
  readonly processTree: EnforcementState;
  readonly network: NetworkProtection;
}

export type ProtectionArea =
  | 'operator'
  | 'platform'
  | 'sandbox'
  | 'filesystem'
  | 'process'
  | 'network'
  | 'policy';

export interface ProtectionReason {
  readonly code: string;
  readonly area: ProtectionArea;
  readonly message: string;
}

export interface ProtectionStatusProps {
  readonly level: ProtectionLevel;
  readonly capabilities: ProtectionCapabilities;
  readonly reasons: readonly ProtectionReason[];
}

/**
 * Truthful result of assessing the currently effective protection boundary.
 *
 * `PROTECTED` is deliberately guarded here, at the domain boundary, so a CLI
 * or future adapter cannot turn an installed binary into a reassuring status.
 */
export class ProtectionStatus {
  readonly level: ProtectionLevel;
  readonly capabilities: ProtectionCapabilities;
  readonly reasons: readonly ProtectionReason[];

  private constructor(props: ProtectionStatusProps) {
    this.level = props.level;
    this.capabilities = Object.freeze({ ...props.capabilities });
    this.reasons = Object.freeze(
      props.reasons.map((reason) => Object.freeze({ ...reason })),
    );
    Object.freeze(this);
  }

  static create(props: ProtectionStatusProps): ProtectionStatus {
    if (props.level === 'PROTECTED' && !isComplete(props.capabilities, props.reasons)) {
      throw new Error(
        'PROTECTED requires a passed deny canary, complete filesystem and process-tree ' +
          'enforcement, denied or brokered network access, and no degradation reasons',
      );
    }
    return new ProtectionStatus(props);
  }

  get isProtected(): boolean {
    return this.level === 'PROTECTED';
  }
}

function isComplete(
  capabilities: ProtectionCapabilities,
  reasons: readonly ProtectionReason[],
): boolean {
  return (
    capabilities.mechanism !== 'none' &&
    capabilities.denyCanary === 'passed' &&
    capabilities.filesystem === 'enforced' &&
    capabilities.processTree === 'enforced' &&
    (capabilities.network === 'denied' || capabilities.network === 'brokered') &&
    reasons.length === 0
  );
}
