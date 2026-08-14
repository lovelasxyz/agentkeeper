import { describe, expect, it } from 'vitest';
import { AssessProtection } from '../../../src/application/use-cases/AssessProtection.js';
import type {
  SandboxProbe,
  SandboxProbeResult,
} from '../../../src/application/ports/SandboxProbe.js';
import type {
  NetworkProbe,
  NetworkProbeResult,
} from '../../../src/application/ports/NetworkProbe.js';
import type {
  SandboxCapabilities,
  SandboxCommand,
  SandboxRunResult,
  SandboxRunner,
} from '../../../src/application/ports/SandboxRunner.js';
import type { PathContext } from '../../../src/domain/paths/PathContext.js';
import { SandboxPolicy } from '../../../src/domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../../src/domain/value-objects/AbsolutePath.js';
import { NetworkRule } from '../../../src/domain/value-objects/NetworkRule.js';
import { ResourceRef } from '../../../src/domain/value-objects/ResourceRef.js';

const workspace = AbsolutePath.of('/work');
const context: PathContext = {
  home: AbsolutePath.of('/home/person'),
  workspace,
  platform: 'linux',
};

function policy(network = false): SandboxPolicy {
  return new SandboxPolicy({
    workspace,
    reads: [ResourceRef.subtree(workspace)],
    writes: [ResourceRef.subtree(workspace)],
    denies: [],
    overrides: [],
    network: network ? [NetworkRule.tcp(443)] : [],
  });
}

const passedProbe: SandboxProbeResult = {
  passed: true,
  code: 'passed',
  checks: {
    runnerStarted: true,
    workspaceReadAllowed: true,
    outsideReadDenied: true,
    childOutsideReadDenied: true,
  },
  exitCode: 0,
  signal: null,
};

class FixedProbe implements SandboxProbe {
  calls = 0;

  constructor(private readonly result: SandboxProbeResult = passedProbe) {}

  async probe(): Promise<SandboxProbeResult> {
    this.calls += 1;
    return this.result;
  }
}

/** A policy the broker can actually enforce: explicit destinations, not `any:443`. */
function brokerable(): SandboxPolicy {
  return new SandboxPolicy({
    workspace,
    reads: [ResourceRef.subtree(workspace)],
    writes: [ResourceRef.subtree(workspace)],
    denies: [],
    overrides: [],
    network: [NetworkRule.destination('api.anthropic.com', 443)],
  });
}

class FixedNetworkProbe implements NetworkProbe {
  calls = 0;

  constructor(private readonly result: NetworkProbeResult) {}

  async probe(): Promise<NetworkProbeResult> {
    this.calls += 1;
    return this.result;
  }
}

class FakeRunner implements SandboxRunner {
  constructor(
    readonly capabilities: SandboxCapabilities,
    private readonly gaps: readonly string[] = [],
  ) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  unenforceable(): readonly string[] {
    return this.gaps;
  }

  async run(
    _policy: SandboxPolicy,
    _context: PathContext,
    _command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    throw new Error('not used by the application unit test');
  }
}

const seatbelt = new FakeRunner({
  mechanism: 'seatbelt',
  fileModel: 'path-rules',
  networkGranularity: 'port',
});

const bubblewrap = new FakeRunner({
  mechanism: 'bubblewrap',
  fileModel: 'mount-namespace',
  networkGranularity: 'all-or-nothing',
});

describe('AssessProtection', () => {
  it('marks current Seatbelt as DEGRADED after a passing canary because system reads are broad', async () => {
    const probe = new FixedProbe();

    const status = await new AssessProtection(probe).execute({
      platform: 'darwin',
      runner: seatbelt,
      policy: policy(),
      context: { ...context, platform: 'darwin' },
    });

    expect(status.level).toBe('DEGRADED');
    expect(status.capabilities).toMatchObject({
      mechanism: 'seatbelt',
      denyCanary: 'passed',
      filesystem: 'partial',
    });
    expect(status.reasons.map((reason) => reason.code)).toContain(
      'seatbelt.broad-system-read',
    );
  });

  it('marks Windows UNPROTECTED when no actual runner exists and does not pretend to probe', async () => {
    const probe = new FixedProbe();

    const status = await new AssessProtection(probe).execute({
      platform: 'win32',
      runner: null,
      policy: policy(),
      context: {
        home: AbsolutePath.of('C:\\Users\\person'),
        workspace: AbsolutePath.of('C:\\work'),
        platform: 'win32',
      },
    });

    expect(status.level).toBe('UNPROTECTED');
    expect(status.capabilities).toEqual({
      mechanism: 'none',
      denyCanary: 'not-run',
      filesystem: 'none',
      processTree: 'none',
      network: 'none',
    });
    expect(status.reasons.map((reason) => reason.code)).toContain(
      'platform.windows-runner-unavailable',
    );
    expect(probe.calls).toBe(0);
  });

  it('marks another platform UNPROTECTED when runner selection produced no backend', async () => {
    const probe = new FixedProbe();

    const status = await new AssessProtection(probe).execute({
      platform: 'linux',
      runner: null,
      policy: policy(),
      context,
    });

    expect(status.level).toBe('UNPROTECTED');
    expect(status.reasons.map((reason) => reason.code)).toContain('sandbox.runner-missing');
    expect(probe.calls).toBe(0);
  });

  it('refuses to assess a policy context created for another platform', async () => {
    const probe = new FixedProbe();

    const status = await new AssessProtection(probe).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(),
      context: { ...context, platform: 'darwin' },
    });

    expect(status.level).toBe('UNPROTECTED');
    expect(status.reasons.map((reason) => reason.code)).toContain(
      'platform.context-mismatch',
    );
    expect(probe.calls).toBe(0);
  });

  it('refuses a backend that cannot run on the assessed platform', async () => {
    const probe = new FixedProbe();

    const status = await new AssessProtection(probe).execute({
      platform: 'linux',
      runner: seatbelt,
      policy: policy(),
      context,
    });

    expect(status.level).toBe('UNPROTECTED');
    expect(status.reasons.map((reason) => reason.code)).toContain('platform.runner-mismatch');
    expect(probe.calls).toBe(0);
  });

  it('does not mark Linux network rules PROTECTED without a verified broker', async () => {
    const status = await new AssessProtection(new FixedProbe()).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(true),
      context,
    });

    expect(status.level).toBe('DEGRADED');
    expect(status.capabilities.network).toBe('denied');
    expect(status.reasons.map((reason) => reason.code)).toContain('network.broker-required');
  });

  it('keeps Seatbelt egress denied without a broker, because the run would fail closed', async () => {
    const status = await new AssessProtection(new FixedProbe()).execute({
      platform: 'darwin',
      runner: seatbelt,
      policy: policy(true),
      context: { ...context, platform: 'darwin' },
    });

    expect(status.level).toBe('DEGRADED');
    expect(status.capabilities.network).toBe('denied');
    expect(status.reasons.map((reason) => reason.code)).toContain('network.broker-required');
  });

  it('verifies the broker itself when a network probe is available', async () => {
    const network = new FixedNetworkProbe({ passed: true, code: 'passed' });

    const status = await new AssessProtection(new FixedProbe(), network).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: brokerable(),
      context,
    });

    expect(network.calls).toBe(1);
    expect(status.level).toBe('PROTECTED');
    expect(status.capabilities.network).toBe('brokered');
  });

  it('keeps egress denied and names the failure when the broker canary fails', async () => {
    const network = new FixedNetworkProbe({
      passed: false,
      code: 'arbitrary-destination-allowed',
    });

    const status = await new AssessProtection(new FixedProbe(), network).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: brokerable(),
      context,
    });

    expect(status.level).toBe('DEGRADED');
    expect(status.capabilities.network).toBe('denied');
    expect(status.reasons.map((reason) => reason.code)).toContain(
      'network.arbitrary-destination-allowed',
    );
  });

  it('does not spend a broker canary when the policy requests no egress', async () => {
    const network = new FixedNetworkProbe({ passed: true, code: 'passed' });

    const status = await new AssessProtection(new FixedProbe(), network).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(),
      context,
    });

    expect(network.calls).toBe(0);
    expect(status.capabilities.network).toBe('denied');
  });

  it('lets a caller that already started the broker skip the canary', async () => {
    const network = new FixedNetworkProbe({ passed: false, code: 'broker-unavailable' });

    const status = await new AssessProtection(new FixedProbe(), network).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: brokerable(),
      context,
      destinationBrokerVerified: true,
    });

    expect(network.calls).toBe(0);
    expect(status.capabilities.network).toBe('brokered');
  });

  it('can call a network policy brokered only when the broker is explicitly verified', async () => {
    const status = await new AssessProtection(new FixedProbe()).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(true),
      context,
      destinationBrokerVerified: true,
    });

    expect(status.level).toBe('PROTECTED');
    expect(status.capabilities.network).toBe('brokered');
  });

  it('reports PROTECTED only after a real probe passes and the requested policy has no gaps', async () => {
    const probe = new FixedProbe();

    const status = await new AssessProtection(probe).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(),
      context,
    });

    expect(status.level).toBe('PROTECTED');
    expect(status.capabilities).toEqual({
      mechanism: 'bubblewrap',
      denyCanary: 'passed',
      filesystem: 'enforced',
      processTree: 'enforced',
      network: 'denied',
    });
    expect(status.reasons).toEqual([]);
    expect(probe.calls).toBe(1);
  });

  it('treats an available-looking runner as UNPROTECTED when the deny canary is readable', async () => {
    const probe = new FixedProbe({
      passed: false,
      code: 'deny-canary-readable',
      checks: {
        runnerStarted: true,
        workspaceReadAllowed: true,
        outsideReadDenied: false,
        childOutsideReadDenied: false,
      },
      exitCode: 42,
      signal: null,
    });

    const status = await new AssessProtection(probe).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(),
      context,
    });

    expect(status.level).toBe('UNPROTECTED');
    expect(status.capabilities.denyCanary).toBe('failed');
    expect(status.reasons.map((reason) => reason.code)).toContain(
      'sandbox.deny-canary-readable',
    );
  });

  it.each([
    'child-deny-canary-readable',
    'workspace-unreadable',
    'child-probe-failed',
    'runner-failed',
    'canary-timed-out',
    'unexpected-exit',
    'passed',
  ] as const)('maps a failed %s probe into an UNPROTECTED structured reason', async (code) => {
    const status = await new AssessProtection(
      new FixedProbe({
        passed: false,
        code,
        checks: {
          runnerStarted: code !== 'runner-failed',
          workspaceReadAllowed: false,
          outsideReadDenied: false,
          childOutsideReadDenied: false,
        },
        exitCode: null,
        signal: null,
      }),
    ).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(),
      context,
    });

    expect(status.level).toBe('UNPROTECTED');
    expect(status.reasons[0]?.area).toBe('sandbox');
  });

  it('downgrades a passing direct canary when child-process containment is unverified', async () => {
    const status = await new AssessProtection(
      new FixedProbe({
        ...passedProbe,
        checks: { ...passedProbe.checks, childOutsideReadDenied: false },
      }),
    ).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(),
      context,
    });

    expect(status.level).toBe('DEGRADED');
    expect(status.capabilities.processTree).toBe('unverified');
    expect(status.reasons.map((reason) => reason.code)).toContain(
      'process.child-boundary-unverified',
    );
  });

  it('reports policy translation gaps as structured degradation reasons', async () => {
    const runner = new FakeRunner(
      {
        mechanism: 'bubblewrap',
        fileModel: 'mount-namespace',
        networkGranularity: 'all-or-nothing',
      },
      ['A wildcard denial has no fixed mount anchor.'],
    );

    const status = await new AssessProtection(new FixedProbe()).execute({
      platform: 'linux',
      runner,
      policy: policy(),
      context,
    });

    expect(status.level).toBe('DEGRADED');
    expect(status.reasons).toContainEqual({
      code: 'policy.unenforceable',
      area: 'policy',
      message: 'A wildcard denial has no fixed mount anchor.',
    });
  });

  it('reports an explicit bypass without running the probe', async () => {
    const probe = new FixedProbe();

    const status = await new AssessProtection(probe).execute({
      platform: 'linux',
      runner: bubblewrap,
      policy: policy(),
      context,
      bypassed: true,
    });

    expect(status.level).toBe('BYPASSED');
    expect(status.capabilities.denyCanary).toBe('not-run');
    expect(status.reasons.map((reason) => reason.code)).toContain('operator.bypassed');
    expect(probe.calls).toBe(0);
  });

  it('never probes or trusts a no-op mechanism', async () => {
    const probe = new FixedProbe();
    const noop = new FakeRunner({
      mechanism: 'none',
      fileModel: 'none',
      networkGranularity: 'none',
    });

    const status = await new AssessProtection(probe).execute({
      platform: 'linux',
      runner: noop,
      policy: policy(),
      context,
    });

    expect(status.level).toBe('UNPROTECTED');
    expect(status.reasons.map((reason) => reason.code)).toContain('sandbox.mechanism-none');
    expect(probe.calls).toBe(0);
  });
});
