import type { NetworkEnforcement } from '../../domain/policy/SandboxPolicy.js';
import type { NetworkRule } from '../../domain/value-objects/NetworkRule.js';
import type { Platform } from '../../domain/value-objects/Platform.js';

export type NetworkProbeCode =
  | 'passed'
  /** The broker refused to start for this destination set, so egress stays closed. */
  | 'broker-unavailable'
  /** An approved tunnel could not be established end to end. */
  | 'allowed-destination-refused'
  /** Bytes did not survive the approved tunnel, so the transport is unusable. */
  | 'relay-failed'
  /** A destination outside the allowlist was accepted — the boundary is not real. */
  | 'arbitrary-destination-allowed'
  /** Cloud metadata was reachable through the broker. */
  | 'metadata-destination-allowed';

export interface NetworkProbeResult {
  readonly passed: boolean;
  readonly code: NetworkProbeCode;
  /**
   * Transport the canary actually established. Callers use it to judge the
   * policy in the shape a protected run would carry, not the unwired shape.
   */
  readonly enforcement?: Extract<NetworkEnforcement, { kind: 'brokered' }>;
}

export interface NetworkProbeRequest {
  readonly destinations: readonly NetworkRule[];
  readonly platform: Platform;
}

/**
 * Exercises the destination broker the way a compromised agent would.
 *
 * Status must not report `brokered` because a broker exists in the codebase.
 * This port answers the only question that matters: does the running broker
 * pass an approved destination and refuse an unapproved one right now.
 */
export interface NetworkProbe {
  probe(request: NetworkProbeRequest): Promise<NetworkProbeResult>;
}
