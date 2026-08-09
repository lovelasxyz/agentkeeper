import { access } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { NodeSandboxProbe } from '../../src/infrastructure/sandbox/NodeSandboxProbe.js';
import { NoopRunner } from '../../src/infrastructure/sandbox/NoopRunner.js';
import type {
  SandboxCapabilities,
  SandboxCommand,
  SandboxRunResult,
  SandboxRunner,
} from '../../src/application/ports/SandboxRunner.js';
import type { SandboxPolicy } from '../../src/domain/policy/SandboxPolicy.js';
import type { PathContext } from '../../src/domain/paths/PathContext.js';
import { isPlatform, type Platform } from '../../src/domain/value-objects/Platform.js';

function hostPlatform(): Platform {
  if (!isPlatform(process.platform)) {
    throw new Error(`Unsupported test platform: ${process.platform}`);
  }
  return process.platform;
}

class ThrowingRunner implements SandboxRunner {
  readonly capabilities: SandboxCapabilities = {
    mechanism: 'bubblewrap',
    fileModel: 'mount-namespace',
    networkGranularity: 'all-or-nothing',
  };

  async isAvailable(): Promise<boolean> {
    return true;
  }

  unenforceable(): readonly string[] {
    return [];
  }

  async run(): Promise<SandboxRunResult> {
    throw new Error('sandbox process could not start');
  }
}

class RecordingUnconfinedRunner extends NoopRunner {
  seenContext: PathContext | null = null;
  seenPolicy: SandboxPolicy | null = null;
  seenCommand: SandboxCommand | null = null;

  override async run(
    policy: SandboxPolicy,
    context: PathContext,
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    this.seenPolicy = policy;
    this.seenContext = context;
    this.seenCommand = command;
    return super.run(policy, context, command);
  }
}

class ResultRunner implements SandboxRunner {
  readonly capabilities: SandboxCapabilities = {
    mechanism: 'bubblewrap',
    fileModel: 'mount-namespace',
    networkGranularity: 'all-or-nothing',
  };

  constructor(private readonly result: SandboxRunResult) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  unenforceable(): readonly string[] {
    return [];
  }

  async run(): Promise<SandboxRunResult> {
    return this.result;
  }
}

describe('NodeSandboxProbe', () => {
  it('runs an actual outside-read canary and catches an unconfined runner', async () => {
    const runner = new RecordingUnconfinedRunner();

    const result = await new NodeSandboxProbe().probe({ runner, platform: hostPlatform() });

    expect(result).toMatchObject({
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
    expect(runner.seenCommand?.executable).toBe(process.execPath);
    expect(runner.seenPolicy?.network).toEqual([]);
    expect(runner.seenContext?.workspace.contains(runner.seenCommand!.cwd)).toBe(true);
  });

  it('removes all canary fixtures after the probe', async () => {
    const runner = new RecordingUnconfinedRunner();

    await new NodeSandboxProbe().probe({ runner, platform: hostPlatform() });

    const probeHome = runner.seenContext?.home.value;
    expect(probeHome).toBeDefined();
    await expect(access(probeHome!)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('returns a structured failure instead of mistaking a present runner for protection', async () => {
    const result = await new NodeSandboxProbe().probe({
      runner: new ThrowingRunner(),
      platform: hostPlatform(),
    });

    expect(result).toEqual({
      passed: false,
      code: 'runner-failed',
      checks: {
        runnerStarted: false,
        workspaceReadAllowed: false,
        outsideReadDenied: false,
        childOutsideReadDenied: false,
      },
      exitCode: null,
      signal: null,
    });
  });

  it('accepts only the probe protocol success code as a passing boundary', async () => {
    const result = await new NodeSandboxProbe().probe({
      runner: new ResultRunner({ exitCode: 0, signal: null }),
      platform: hostPlatform(),
    });

    expect(result).toEqual({
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
    });
  });

  it.each([
    [41, 'workspace-unreadable', false, false, false],
    [43, 'child-deny-canary-readable', true, true, false],
    [44, 'child-probe-failed', true, true, false],
    [99, 'unexpected-exit', false, false, false],
  ] as const)(
    'maps canary exit %i to %s without an optimistic default',
    async (exitCode, code, workspaceReadAllowed, outsideReadDenied, childOutsideReadDenied) => {
      const result = await new NodeSandboxProbe().probe({
        runner: new ResultRunner({ exitCode, signal: null }),
        platform: hostPlatform(),
      });

      expect(result).toMatchObject({
        passed: false,
        code,
        checks: {
          runnerStarted: true,
          workspaceReadAllowed,
          outsideReadDenied,
          childOutsideReadDenied,
        },
        exitCode,
        signal: null,
      });
    },
  );

  it('treats a signalled probe as an unexpected failure', async () => {
    const result = await new NodeSandboxProbe().probe({
      runner: new ResultRunner({ exitCode: 128, signal: 'SIGKILL' }),
      platform: hostPlatform(),
    });

    expect(result).toMatchObject({
      passed: false,
      code: 'unexpected-exit',
      exitCode: 128,
      signal: 'SIGKILL',
    });
  });

  it('uses a minimal fallback PATH rather than forwarding the ambient environment', async () => {
    const originalPath = process.env['PATH'];
    delete process.env['PATH'];
    try {
      const result = await new NodeSandboxProbe().probe({
        runner: new ResultRunner({ exitCode: 0, signal: null }),
        platform: hostPlatform(),
      });
      expect(result.passed).toBe(true);
    } finally {
      if (originalPath !== undefined) process.env['PATH'] = originalPath;
    }
  });
});
