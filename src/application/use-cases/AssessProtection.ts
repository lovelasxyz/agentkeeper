import type { NetworkProbe, NetworkProbeCode } from '../ports/NetworkProbe.js';
import type { SandboxProbe, SandboxProbeCode } from '../ports/SandboxProbe.js';
import type { SandboxRunner } from '../ports/SandboxRunner.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { NetworkEnforcement, SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import {
  ProtectionStatus,
  type NetworkProtection,
  type ProtectionCapabilities,
  type ProtectionMechanism,
  type ProtectionReason,
} from '../../domain/protection/ProtectionStatus.js';
import type { Platform } from '../../domain/value-objects/Platform.js';

export interface AssessProtectionRequest {
  readonly platform: Platform;
  readonly runner: SandboxRunner | null;
  readonly policy: SandboxPolicy;
  readonly context: PathContext;
  readonly bypassed?: boolean;
  /**
   * Decided by a caller that already started the broker for this session.
   * When absent, the network probe decides; when absent too, egress is denied.
   */
  readonly destinationBrokerVerified?: boolean;
}

interface BrokerVerification {
  readonly verified: boolean;
  /** Transport proven by the canary, so gaps are judged against the runtime shape. */
  readonly enforcement?: Extract<NetworkEnforcement, { kind: 'brokered' }>;
  readonly reason?: ProtectionReason;
}

const INACTIVE_CAPABILITIES: ProtectionCapabilities = Object.freeze({
  mechanism: 'none',
  denyCanary: 'not-run',
  filesystem: 'none',
  processTree: 'none',
  network: 'none',
});

/** Produces an honest, risk-bearing status from a runtime canary and known backend limits. */
export class AssessProtection {
  constructor(
    private readonly probe: SandboxProbe,
    private readonly network: NetworkProbe | null = null,
  ) {}

  async execute(request: AssessProtectionRequest): Promise<ProtectionStatus> {
    if (request.bypassed === true) {
      return ProtectionStatus.create({
        level: 'BYPASSED',
        capabilities: INACTIVE_CAPABILITIES,
        reasons: [reason('operator.bypassed', 'operator', 'Sandbox protection was explicitly bypassed.')],
      });
    }

    if (request.context.platform !== request.platform) {
      return unprotected(
        'platform.context-mismatch',
        'platform',
        'The policy context platform does not match the platform being assessed.',
      );
    }

    if (request.runner === null) {
      const windows = request.platform === 'win32';
      return unprotected(
        windows ? 'platform.windows-runner-unavailable' : 'sandbox.runner-missing',
        'platform',
        windows
          ? 'No Windows sandbox backend is shipped: the AppContainer backend never completed its own deny canary, and an unproven boundary is not a boundary.'
          : 'No sandbox runner is available; no isolation boundary is active.',
      );
    }

    const mechanism = request.runner.capabilities.mechanism;
    if (mechanism === 'none') {
      return unprotected(
        'sandbox.mechanism-none',
        'sandbox',
        'The selected runner executes commands without an isolation mechanism.',
      );
    }

    if (!mechanismMatchesPlatform(mechanism, request.platform)) {
      return unprotected(
        'platform.runner-mismatch',
        'platform',
        `The ${mechanism} runner cannot provide a boundary on ${request.platform}.`,
      );
    }

    const probe = await this.probe.probe({ runner: request.runner, platform: request.platform });
    if (!probe.passed) {
      return ProtectionStatus.create({
        level: 'UNPROTECTED',
        capabilities: {
          mechanism,
          denyCanary: 'failed',
          filesystem: 'none',
          processTree: 'none',
          network: 'none',
        },
        reasons: [probeFailureReason(probe.code)],
      });
    }

    const egressRequested = request.policy.network.length > 0;
    const broker = await this.verifyBroker(request, egressRequested);
    // A protected run attaches the broker transport before the backend sees the
    // policy, so gaps must be judged against that shape rather than against a
    // policy whose egress has not been wired up yet.
    const policy =
      broker.enforcement === undefined
        ? request.policy
        : request.policy.withNetworkEnforcement(broker.enforcement);

    const gaps = request.runner.unenforceable(policy, request.context);
    const reasons: ProtectionReason[] = gaps.map((message) =>
      reason('policy.unenforceable', 'policy', message),
    );
    const filesystemGaps = gaps.filter((message) => /mount|wildcard|file|path/i.test(message));
    let filesystem: ProtectionCapabilities['filesystem'] =
      filesystemGaps.length === 0 ? 'enforced' : 'partial';

    if (mechanism === 'seatbelt') {
      filesystem = 'partial';
      reasons.push(
        reason(
          'seatbelt.broad-system-read',
          'filesystem',
          'The current Seatbelt profile permits broad reads outside user home directories.',
        ),
      );
    }

    // One network rule for every backend: egress exists only through a broker
    // that was proven to refuse unapproved destinations. Anything less is
    // denied, because every backend fails a protected run closed instead.
    let network: NetworkProtection = 'denied';
    if (egressRequested) {
      if (broker.verified) {
        network = 'brokered';
      } else {
        reasons.push(broker.reason ?? BROKER_REQUIRED);
      }
    }

    const capabilities: ProtectionCapabilities = {
      mechanism,
      denyCanary: 'passed',
      filesystem,
      processTree: probe.checks.childOutsideReadDenied ? 'enforced' : 'unverified',
      network,
    };
    if (capabilities.processTree !== 'enforced') {
      reasons.push(
        reason(
          'process.child-boundary-unverified',
          'process',
          'The deny canary was not verified in a child process.',
        ),
      );
    }

    return ProtectionStatus.create({
      level: reasons.length === 0 ? 'PROTECTED' : 'DEGRADED',
      capabilities,
      reasons,
    });
  }

  /**
   * Answers whether egress is actually brokered right now.
   *
   * A caller that already started the broker for this session states the fact
   * directly; otherwise the canary re-derives it, and the absence of both keeps
   * the answer negative. There is no path here that assumes protection.
   */
  private async verifyBroker(
    request: AssessProtectionRequest,
    egressRequested: boolean,
  ): Promise<BrokerVerification> {
    if (request.destinationBrokerVerified !== undefined) {
      return { verified: request.destinationBrokerVerified };
    }
    if (!egressRequested || this.network === null) return { verified: false };

    const result = await this.network.probe({
      destinations: request.policy.network,
      platform: request.platform,
    });
    if (result.passed) {
      return { verified: true, ...(result.enforcement === undefined ? {} : { enforcement: result.enforcement }) };
    }
    return {
      verified: false,
      reason: reason(`network.${result.code}`, 'network', NETWORK_PROBE_MESSAGES[result.code]),
    };
  }
}

const BROKER_REQUIRED: ProtectionReason = Object.freeze({
  code: 'network.broker-required',
  area: 'network' as const,
  message:
    'Requested egress stays denied and protected runs fail closed until a verified destination broker is available.',
});

const NETWORK_PROBE_MESSAGES: Readonly<Record<NetworkProbeCode, string>> = Object.freeze({
  passed: 'The destination broker canary passed.',
  'broker-unavailable':
    'The destination broker refused to start for the requested destinations, so egress stays closed.',
  'allowed-destination-refused':
    'The destination broker refused an approved destination, so protected runs would lose network access.',
  'relay-failed':
    'An approved tunnel was established but did not carry traffic, so the broker transport is unusable.',
  'arbitrary-destination-allowed':
    'The destination broker accepted a destination outside the allowlist; egress is not confined.',
  'metadata-destination-allowed':
    'The destination broker accepted the cloud metadata endpoint; egress is not confined.',
});

function mechanismMatchesPlatform(
  mechanism: Exclude<ProtectionMechanism, 'none'>,
  platform: Platform,
): boolean {
  return (
    (mechanism === 'seatbelt' && platform === 'darwin') ||
    (mechanism === 'bubblewrap' && platform === 'linux')
  );
}

function probeFailureReason(code: SandboxProbeCode): ProtectionReason {
  const messages: Readonly<Record<Exclude<SandboxProbeCode, 'passed'>, string>> = {
    'deny-canary-readable': 'The sandboxed process could read the outside deny canary.',
    'child-deny-canary-readable': 'A sandboxed child process could read the outside deny canary.',
    'workspace-unreadable': 'The sandbox denied the workspace allow canary, so the boundary is unusable.',
    'child-probe-failed': 'The child-process deny canary did not complete successfully.',
    'runner-failed': 'The sandbox runner could not start the canary process.',
    'canary-timed-out':
      'The sandbox canary did not finish in time, so the boundary could not be verified.',
    'unexpected-exit': 'The sandbox canary returned an unrecognised result.',
  };
  if (code === 'passed') {
    return reason(
      'sandbox.probe-inconsistent',
      'sandbox',
      'The sandbox probe reported failure with a passing result code.',
    );
  }
  return reason(`sandbox.${code}`, 'sandbox', messages[code]);
}

function unprotected(code: string, area: ProtectionReason['area'], message: string): ProtectionStatus {
  return ProtectionStatus.create({
    level: 'UNPROTECTED',
    capabilities: INACTIVE_CAPABILITIES,
    reasons: [reason(code, area, message)],
  });
}

function reason(
  code: string,
  area: ProtectionReason['area'],
  message: string,
): ProtectionReason {
  return { code, area, message };
}
