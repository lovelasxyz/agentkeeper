import type {
  NetworkEnforcement,
} from '../../domain/policy/SandboxPolicy.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { NetworkRule } from '../../domain/value-objects/NetworkRule.js';
import type { Platform } from '../../domain/value-objects/Platform.js';

export interface DestinationBrokerStartRequest {
  readonly destinations: readonly NetworkRule[];
  readonly platform: Platform;
  readonly scratch: AbsolutePath;
}

export interface DestinationBrokerSession {
  /** Standard proxy URL injected by the trusted launcher, never inherited. */
  readonly proxyUrl: string;
  /** Backend transport proving that direct egress remains closed. */
  readonly enforcement: Extract<NetworkEnforcement, { kind: 'brokered' }>;
  close(): Promise<void>;
}

export interface DestinationBroker {
  start(request: DestinationBrokerStartRequest): Promise<DestinationBrokerSession>;
}
