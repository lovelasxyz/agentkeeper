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
  decodeWindowsSandboxResult,
  decodeWindowsSandboxRequest,
  encodeWindowsSandboxRequest,
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
  let lastExit = 0;
  const invoke = overrides.invoke ?? (async () => ({ exitCode: 0, signal: null }));
  return {
    platform: 'win32',
    architecture: 'x64',
    helperPath: String.raw`C:\agentkeeper\agentkeeper-sandbox.exe`,
    canAccess: vi.fn(async () => true),
    makeTemporaryDirectory: vi.fn(async () => String.raw`C:\Temp\agentkeeper-123`),
    makeDirectory: vi.fn(async () => undefined),
    writeFile: vi.fn(async () => undefined),
    readFile: vi.fn(async () => lastExit >= 200 && lastExit <= 210
      ? nativeResult(lastExit, 0) : nativeResult(0, lastExit)),
    removeDirectory: vi.fn(async () => undefined),
    ...overrides,
    invoke: vi.fn(async (...args: Parameters<typeof invoke>) => {
      const result = await invoke(...args);
      lastExit = result.exitCode;
      return args[1][0] === '--diagnose' ? result : { exitCode: 0, signal: result.signal };
    }),
  };
}

function nativeResult(error: number, childExit: number): Buffer {
  const result = Buffer.alloc(16);
  result.write('AKSRES01', 'ascii');
  result.writeUInt32LE(error, 8);
  result.writeUInt32LE(childExit, 12);
  return result;
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

  it('bounds the preflight so a hung helper degrades instead of hanging the CLI', async () => {
    // A native helper that never returns must not freeze `doctor` or `run`.
    // Waiting forever is indistinguishable from a boundary that is working.
    const runner = new WindowsSandboxRunner(
      dependencies({
        invoke: (_helper, _args, invocation) =>
          new Promise((_resolve, reject) => {
            expect(invocation.timeoutMs).toBeGreaterThan(0);
            setTimeout(() => reject(new Error('preflight timed out')), 1).unref();
          }),
      }),
    );

    await expect(runner.diagnose()).resolves.toMatchObject({
      level: 'unsupported',
      code: 'windows.helper-probe-failed',
    });
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
    expect(deps.makeDirectory).toHaveBeenCalledTimes(9);
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

  it.each([200, 203, 208, 0xffff_ffff])('preserves child exit %i through the separate result channel', async (exitCode) => {
    const runner = new WindowsSandboxRunner(dependencies({
      readFile: async () => nativeResult(0, exitCode),
    }));
    await expect(runner.run(policy(), context, {
      executable: String.raw`C:\Program Files\nodejs\node.exe`,
      args: [], cwd: workspace, env: {},
    })).resolves.toEqual({ exitCode, signal: null });
  });

  it('refuses a missing result even when the helper exits successfully', async () => {
    const runner = new WindowsSandboxRunner(dependencies({
      readFile: async () => { throw new Error('ENOENT'); },
    }));
    await expect(runner.run(policy(), context, {
      executable: String.raw`C:\Program Files\nodejs\node.exe`,
      args: [], cwd: workspace, env: {},
    })).rejects.toMatchObject({ code: 'windows.helper-probe-failed' });
  });

  it('keeps Windows application data in the disposable home and removes case aliases', async () => {
    const deps = dependencies();
    await new WindowsSandboxRunner(deps).run(policy(), context, {
      executable: String.raw`C:\Program Files\nodejs\node.exe`,
      args: [], cwd: workspace,
      env: { home: home.value, UserProfile: home.value, appdata: home.join('AppData/Roaming').value, localappdata: home.join('AppData/Local').value },
    });
    const invocation = vi.mocked(deps.invoke).mock.calls[0]![2];
    expect(invocation.env).toMatchObject({
      APPDATA: 'C:/temp/agentkeeper-123/profile/home/appdata/roaming',
      LOCALAPPDATA: 'C:/temp/agentkeeper-123/profile/home/appdata/local',
    });
    for (const alias of ['home', 'UserProfile', 'appdata', 'localappdata']) {
      expect(invocation.env).not.toHaveProperty(alias);
    }
  });
});

describe('native Windows result protocol', () => {
  it('distinguishes native errors from child exits', () => {
    expect(decodeWindowsSandboxResult(nativeResult(203, 0))).toEqual({ nativeError: 203, childExitCode: 0 });
    expect(decodeWindowsSandboxResult(nativeResult(0, 203))).toEqual({ nativeError: 0, childExitCode: 203 });
  });
  it.each([Buffer.alloc(0), Buffer.alloc(16), nativeResult(999, 0), Buffer.concat([nativeResult(0, 0), Buffer.from([0])])])('rejects malformed or unknown native results', (bytes) => {
    expect(() => decodeWindowsSandboxResult(bytes)).toThrow();
  });
  it('compares result magic as bytes, without ASCII masking high bits', () => {
    const result = nativeResult(0, 0);
    result[0] = result[0]! | 0x80;
    expect(() => decodeWindowsSandboxResult(result)).toThrow();
  });
});

describe('native Windows probe deadline', () => {
  it.each([0, -1, 1.5, Number.POSITIVE_INFINITY, 0xffff_ffff])('rejects a deadline %s that cannot bound the native wait', (timeoutMs) => {
    expect(() => encodeWindowsSandboxRequest({
      timeoutMs, executable: String.raw`C:\node\node.exe`, cwd: workspace.value,
      args: [], reads: [], writes: [], denies: [],
    })).toThrow(/deadline/i);
  });
  it('rejects a forged INFINITE timeout in the binary request', () => {
    const request = encodeWindowsSandboxRequest({
      timeoutMs: 100, executable: String.raw`C:\node\node.exe`, cwd: workspace.value,
      args: [], reads: [], writes: [], denies: [],
    });
    request.writeUInt32LE(0xffff_ffff, 12);
    expect(() => decodeWindowsSandboxRequest(request)).toThrow(/deadline/i);
  });
});
