import { describe, expect, it, vi } from 'vitest';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { DenyRule } from '../../../../src/domain/policy/DenyRule.js';
import { SandboxPolicy } from '../../../../src/domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { NetworkRule } from '../../../../src/domain/value-objects/NetworkRule.js';
import { PathPattern } from '../../../../src/domain/value-objects/PathPattern.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';
import {
  WindowsSandboxRunner,
  decodeWindowsSandboxRequest,
  resolveWindowsSandboxHelper,
  type WindowsSandboxInvocation,
  type WindowsSandboxRunnerDependencies,
} from '../../../../src/infrastructure/sandbox/WindowsSandboxRunner.js';
import { WindowsPolicyTranslator } from '../../../../src/infrastructure/sandbox/WindowsPolicyTranslator.js';
import { WindowsReadDenyScanner } from '../../../../src/infrastructure/sandbox/WindowsReadDenyScanner.js';

const home = AbsolutePath.of(String.raw`C:\Users\Dev`);
const workspace = home.join('projects', 'app');
const context = { home, workspace, platform: 'win32' as const };

function policy(overrides: {
  network?: boolean;
  denies?: readonly DenyRule[];
  reads?: readonly ResourceRef[];
} = {}): SandboxPolicy {
  return new SandboxPolicy({
    workspace,
    reads: overrides.reads ?? [ResourceRef.subtree(workspace)],
    writes: [ResourceRef.subtree(workspace)],
    denies: overrides.denies ?? [],
    overrides: [],
    network: overrides.network === true ? [NetworkRule.tcp(443)] : [],
  });
}

function dependencies(
  overrides: Partial<WindowsSandboxRunnerDependencies> = {},
): WindowsSandboxRunnerDependencies {
  return {
    platform: 'win32',
    architecture: 'x64',
    helperPath: String.raw`C:\agentkeeper\agentkeeper-sandbox.exe`,
    canAccess: vi.fn(async () => true),
    makeTemporaryDirectory: vi.fn(async () => String.raw`C:\Temp\agentkeeper-123`),
    makeDirectory: vi.fn(async () => undefined),
    writeFile: vi.fn(async () => undefined),
    removeDirectory: vi.fn(async () => undefined),
    invoke: vi.fn(async () => ({ exitCode: 0, signal: null })),
    ...overrides,
  };
}

describe('WindowsSandboxRunner contract', () => {
  it('resolves the packaged helper from source, emitted-library and bundled layouts', () => {
    const root = process.cwd();
    const expected = join(root, 'dist', 'native', 'win32-x64', 'agentkeeper-sandbox.exe');

    expect(
      resolveWindowsSandboxHelper(
        pathToFileURL(join(root, 'src', 'infrastructure', 'sandbox', 'WindowsSandboxRunner.js')).href,
        'x64',
      ),
    ).toBe(expected);
    expect(
      resolveWindowsSandboxHelper(
        pathToFileURL(join(root, 'dist', 'infrastructure', 'sandbox', 'WindowsSandboxRunner.js')).href,
        'x64',
      ),
    ).toBe(expected);
    expect(
      resolveWindowsSandboxHelper(pathToFileURL(join(root, 'dist', 'cli.js')).href, 'x64'),
    ).toBe(expected);
  });

  it('is structurally unavailable on non-Windows and never probes a helper', async () => {
    const invoke = vi.fn(async () => ({ exitCode: 0, signal: null }));
    const runner = new WindowsSandboxRunner(
      dependencies({ platform: 'linux', invoke }),
    );

    await expect(runner.diagnose()).resolves.toMatchObject({
      level: 'unsupported',
      code: 'windows.platform-unsupported',
    });
    await expect(runner.isAvailable()).resolves.toBe(false);
    expect(invoke).not.toHaveBeenCalled();
  });

  it('reports a missing prebuilt helper as structured unsupported, never as unconfined', async () => {
    const invoke = vi.fn(async () => ({ exitCode: 0, signal: null }));
    const runner = new WindowsSandboxRunner(
      dependencies({ canAccess: async () => false, invoke }),
    );

    await expect(runner.diagnose()).resolves.toMatchObject({
      level: 'unsupported',
      code: 'windows.helper-missing',
    });
    await expect(runner.isAvailable()).resolves.toBe(false);
    expect(invoke).not.toHaveBeenCalled();
  });

  it('requires the native AppContainer API preflight and reports its failure code', async () => {
    const runner = new WindowsSandboxRunner(
      dependencies({ invoke: async () => ({ exitCode: 201, signal: null }) }),
    );

    await expect(runner.diagnose()).resolves.toMatchObject({
      level: 'unsupported',
      code: 'windows.appcontainer-profile-failed',
    });
    await expect(runner.isAvailable()).resolves.toBe(false);
  });

  it('describes the stable AppContainer boundary as degraded until a real canary assesses it', async () => {
    const runner = new WindowsSandboxRunner(dependencies());

    await expect(runner.diagnose()).resolves.toMatchObject({
      level: 'degraded',
      code: 'windows.appcontainer-compatibility-surface',
      mechanism: 'appcontainer',
    });
    await expect(runner.isAvailable()).resolves.toBe(true);
    expect(runner.capabilities).toEqual({
      mechanism: 'appcontainer',
      fileModel: 'appcontainer-allowlist',
      networkGranularity: 'all-or-nothing',
    });
  });

  it('fails closed when the policy requests any network access', () => {
    const runner = new WindowsSandboxRunner(dependencies());

    expect(runner.unenforceable(policy({ network: true }), context)).toContainEqual(
      expect.stringMatching(/network.*denied/i),
    );
  });

  it('accepts read-only wildcard overlap because it is compiled into exact deny ACEs', () => {
    const parent = home.join('projects');
    const deny = new DenyRule(
      'env-outside-workspace',
      PathPattern.of('**/.env'),
      'read',
      'credential file',
      workspace,
    );
    const runner = new WindowsSandboxRunner(dependencies());

    expect(
      runner.unenforceable(
        policy({ reads: [ResourceRef.subtree(parent)], denies: [deny] }),
        context,
      ),
    ).toEqual([]);
  });

  it('does not invent a gap for a deny that lies outside every granted path', () => {
    const deny = new DenyRule(
      'ssh-keys',
      PathPattern.of('~/.ssh/**'),
      'read',
      'private keys',
    );
    const runner = new WindowsSandboxRunner(dependencies());

    expect(runner.unenforceable(policy({ denies: [deny] }), context)).toEqual([]);
  });

  it('serializes only the explicit command and allowlist and invokes the helper with sanitized env', async () => {
    let request: Buffer | undefined;
    let invocation: WindowsSandboxInvocation | undefined;
    const deps = dependencies({
      writeFile: async (_path, content) => {
        request = content;
      },
      invoke: async (_helper, args, options) => {
        if (args[0] === '--diagnose') return { exitCode: 0, signal: null };
        invocation = options;
        return { exitCode: 17, signal: null };
      },
    });
    const runner = new WindowsSandboxRunner(deps);
    const command = {
      executable: String.raw`C:\Program Files\nodejs\node.exe`,
      args: ['-e', 'process.exit(17)', 'argument with spaces'],
      cwd: workspace,
      env: { SystemRoot: String.raw`C:\Windows`, HOME: home.value, SAFE: '1' },
    };

    await expect(runner.run(policy(), context, command)).resolves.toEqual({
      exitCode: 17,
      signal: null,
    });
    expect(request).toBeDefined();
    expect(decodeWindowsSandboxRequest(request as Buffer)).toEqual({
      executable: command.executable,
      cwd: workspace.value,
      args: command.args,
      reads: [
        { scope: 'subtree', path: workspace.value },
        { scope: 'subtree', path: 'C:/temp/agentkeeper-123/profile/home' },
      ],
      writes: [
        { scope: 'subtree', path: workspace.value },
        { scope: 'subtree', path: 'C:/temp/agentkeeper-123/profile/home' },
      ],
      denies: [],
    });
    expect(invocation).toMatchObject({
      cwd: workspace.value,
      env: {
        ...command.env,
        HOME: 'C:/temp/agentkeeper-123/profile/home',
        USERPROFILE: 'C:/temp/agentkeeper-123/profile/home',
        TMPDIR: 'C:/temp/agentkeeper-123/profile/home/tmp',
        TMP: 'C:/temp/agentkeeper-123/profile/home/tmp',
        TEMP: 'C:/temp/agentkeeper-123/profile/home/tmp',
      },
      stdio: 'inherit',
    });
    expect(deps.makeDirectory).toHaveBeenCalledTimes(7);
    expect(deps.removeDirectory).toHaveBeenCalledWith(String.raw`C:\Temp\agentkeeper-123`);
  });

  it('serializes discovered read exclusions as exact native deny ACEs', async () => {
    const secret = home.join('.env');
    let request: Buffer | undefined;
    const deny = new DenyRule(
      'env-outside-workspace',
      PathPattern.of('**/.env'),
      'read',
      'credential file',
      workspace,
    );
    const deps = dependencies({
      writeFile: async (_path, content) => {
        request = content;
      },
    });
    const scanner = new WindowsReadDenyScanner(async () => [
      { path: home, directory: true },
      { path: secret, directory: false },
    ]);
    const runner = new WindowsSandboxRunner(deps, new WindowsPolicyTranslator(), scanner);

    await runner.run(
      policy({ reads: [ResourceRef.subtree(home)], denies: [deny] }),
      context,
      {
        executable: String.raw`C:\Program Files\nodejs\node.exe`,
        args: ['--version'],
        cwd: workspace,
        env: { SystemRoot: String.raw`C:\Windows` },
      },
    );

    expect(request).toBeDefined();
    expect(decodeWindowsSandboxRequest(request as Buffer).denies).toEqual([
      { scope: 'file', path: secret.value, access: 'read' },
    ]);
  });

  it('turns native setup failures into typed errors instead of returning a child result', async () => {
    const runner = new WindowsSandboxRunner(
      dependencies({
        invoke: async (_helper, args) =>
          args[0] === '--diagnose'
            ? { exitCode: 0, signal: null }
            : { exitCode: 203, signal: null },
      }),
    );

    await expect(
      runner.run(policy(), context, {
        executable: String.raw`C:\Windows\System32\cmd.exe`,
        args: ['/c', 'exit', '0'],
        cwd: workspace,
        env: { SystemRoot: String.raw`C:\Windows` },
      }),
    ).rejects.toMatchObject({
      name: 'WindowsSandboxBackendError',
      code: 'windows.acl-setup-failed',
    });
  });
});
