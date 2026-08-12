import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  SandboxProbe,
  SandboxProbeCode,
  SandboxProbeRequest,
  SandboxProbeResult,
} from '../../application/ports/SandboxProbe.js';
import type { SandboxRunResult } from '../../application/ports/SandboxRunner.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../domain/value-objects/ResourceRef.js';

const EXIT_WORKSPACE_UNREADABLE = 41;
const EXIT_DENY_CANARY_READABLE = 42;
const EXIT_CHILD_DENY_CANARY_READABLE = 43;
const EXIT_CHILD_PROBE_FAILED = 44;

/**
 * Black-box boundary probe. It creates a disposable home, confirms the
 * workspace is usable, then attempts the same forbidden read both directly
 * and from a child process launched inside the runner.
 */
export class NodeSandboxProbe implements SandboxProbe {
  async probe(request: SandboxProbeRequest): Promise<SandboxProbeResult> {
    // macOS exposes the temporary directory through `/var`, while Seatbelt
    // evaluates the kernel-resolved `/private/var` path. Compile canonical
    // paths or every apparently precise rule silently matches nothing.
    const createdRoot = await mkdtemp(join(tmpdir(), 'agentkeeper-probe-'));
    const root = await realpath(createdRoot);
    try {
      return await this.runCanary(root, request);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

  private async runCanary(
    root: string,
    request: SandboxProbeRequest,
  ): Promise<SandboxProbeResult> {
    const home = AbsolutePath.of(join(root, 'home'));
    const workspace = home.join('workspace');
    const outsideDirectory = home.join('private');
    const allowedCanary = workspace.join('allowed.canary');
    const deniedCanary = outsideDirectory.join('denied.canary');
    const probeTemp = workspace.join('tmp');

    await mkdir(workspace.value, { recursive: true, mode: 0o700 });
    await mkdir(outsideDirectory.value, { recursive: true, mode: 0o700 });
    await mkdir(probeTemp.value, { recursive: true, mode: 0o700 });
    await writeFile(allowedCanary.value, 'allowed', { mode: 0o600 });
    await writeFile(deniedCanary.value, 'denied', { mode: 0o600 });

    const context: PathContext = { home, workspace, platform: request.platform };
    const runtimeRoot = AbsolutePath.of(process.execPath).parent.parent;
    const policy = new SandboxPolicy({
      workspace,
      reads: [ResourceRef.subtree(workspace), ResourceRef.subtree(runtimeRoot)],
      writes: [ResourceRef.subtree(workspace)],
      denies: [],
      overrides: [],
      network: [],
    });

    let timedOut = false;
    try {
      const result = await withDeadline(request.runner.run(policy, context, {
        executable: process.execPath,
        args: ['-e', canaryScript(allowedCanary.value, deniedCanary.value)],
        cwd: workspace,
        env: {
          HOME: home.value,
          TMPDIR: probeTemp.value,
          PATH: process.env['PATH'] ?? '/usr/bin:/bin',
          ...(request.platform === 'win32'
            ? windowsProbeEnvironment(home.value, probeTemp.value)
            : {}),
        },
      }), CANARY_TIMEOUT_MS, () => {
        timedOut = true;
      });
      return interpret(result);
    } catch {
      // A canary that never returns is not a boundary that works: `doctor`
      // must say the protection is unverified instead of hanging forever.
      return failure(
        timedOut ? 'canary-timed-out' : 'runner-failed',
        false,
        false,
        false,
        false,
        null,
        null,
      );
    }
  }
}

/** A canary is a few milliseconds of work; anything near this is stuck. */
const CANARY_TIMEOUT_MS = 30_000;

function withDeadline<T>(
  work: Promise<T>,
  milliseconds: number,
  onTimeout: () => void,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      onTimeout();
      reject(new Error(`The sandbox canary did not finish within ${milliseconds} ms`));
    }, milliseconds);
    timer.unref();
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

function windowsProbeEnvironment(
  home: string,
  temporaryDirectory: string,
): Readonly<Record<string, string>> {
  const inherited = Object.fromEntries(
    ['SystemRoot', 'WINDIR', 'ComSpec', 'PATHEXT']
      .map((name) => [name, process.env[name]] as const)
      .filter((entry): entry is readonly [string, string] => entry[1] !== undefined),
  );
  return {
    ...inherited,
    USERPROFILE: home,
    TEMP: temporaryDirectory,
    TMP: temporaryDirectory,
  };
}

function canaryScript(allowedPath: string, deniedPath: string): string {
  return [
    "const fs = require('node:fs');",
    "const cp = require('node:child_process');",
    `const allowed = ${JSON.stringify(allowedPath)};`,
    `const denied = ${JSON.stringify(deniedPath)};`,
    `try { fs.readFileSync(allowed); } catch { process.exit(${EXIT_WORKSPACE_UNREADABLE}); }`,
    `try { fs.readFileSync(denied); process.exit(${EXIT_DENY_CANARY_READABLE}); } catch {}`,
    "const childScript = \"const fs=require('node:fs');try{fs.readFileSync(process.argv[1]);process.exit(42)}catch{process.exit(0)}\";",
    "const child = cp.spawnSync(process.execPath, ['-e', childScript, denied], { stdio: 'ignore' });",
    `if (child.status === ${EXIT_DENY_CANARY_READABLE}) process.exit(${EXIT_CHILD_DENY_CANARY_READABLE});`,
    `if (child.status !== 0) process.exit(${EXIT_CHILD_PROBE_FAILED});`,
    'process.exit(0);',
  ].join('');
}

function interpret(result: SandboxRunResult): SandboxProbeResult {
  if (result.signal !== null) {
    return failure('unexpected-exit', true, false, false, false, result.exitCode, result.signal);
  }
  switch (result.exitCode) {
    case 0:
      return {
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
    case EXIT_WORKSPACE_UNREADABLE:
      return failure('workspace-unreadable', true, false, false, false, result.exitCode, null);
    case EXIT_DENY_CANARY_READABLE:
      return failure('deny-canary-readable', true, true, false, false, result.exitCode, null);
    case EXIT_CHILD_DENY_CANARY_READABLE:
      return failure(
        'child-deny-canary-readable',
        true,
        true,
        true,
        false,
        result.exitCode,
        null,
      );
    case EXIT_CHILD_PROBE_FAILED:
      return failure('child-probe-failed', true, true, true, false, result.exitCode, null);
    default:
      return failure('unexpected-exit', true, false, false, false, result.exitCode, null);
  }
}

function failure(
  code: Exclude<SandboxProbeCode, 'passed'>,
  runnerStarted: boolean,
  workspaceReadAllowed: boolean,
  outsideReadDenied: boolean,
  childOutsideReadDenied: boolean,
  exitCode: number | null,
  signal: NodeJS.Signals | null,
): SandboxProbeResult {
  return {
    passed: false,
    code,
    checks: {
      runnerStarted,
      workspaceReadAllowed,
      outsideReadDenied,
      childOutsideReadDenied,
    },
    exitCode,
    signal,
  };
}
