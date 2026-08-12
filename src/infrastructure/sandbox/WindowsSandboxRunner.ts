import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type {
  SandboxCapabilities,
  SandboxCommand,
  SandboxRunResult,
  SandboxRunner,
} from '../../application/ports/SandboxRunner.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { ResourceRef, ResourceScope } from '../../domain/value-objects/ResourceRef.js';
import {
  WindowsPolicyDiscoveryError,
  WindowsReadDenyScanner,
  type WindowsDeniedResource,
} from './WindowsReadDenyScanner.js';
import { WindowsPolicyTranslator } from './WindowsPolicyTranslator.js';

/** Creating and deleting one AppContainer profile is fast; anything slower is stuck. */
const PREFLIGHT_TIMEOUT_MS = 15_000;
const REQUEST_MAGIC = Buffer.from('AKSBOX01', 'ascii');
const REQUEST_VERSION = 2;
const MAX_REQUEST_BYTES = 16 * 1024 * 1024;
const MAX_COLLECTION_ITEMS = 100_000;
const NATIVE_ERROR_CODES = Object.freeze({
  200: 'windows.request-invalid',
  201: 'windows.appcontainer-profile-failed',
  202: 'windows.appcontainer-sid-failed',
  203: 'windows.acl-setup-failed',
  204: 'windows.job-setup-failed',
  205: 'windows.process-launch-failed',
  206: 'windows.cleanup-failed',
  207: 'windows.child-wait-failed',
} as const);

type NativeErrorExitCode = keyof typeof NATIVE_ERROR_CODES;
export type WindowsSandboxErrorCode =
  | (typeof NATIVE_ERROR_CODES)[NativeErrorExitCode]
  | 'windows.platform-unsupported'
  | 'windows.architecture-unsupported'
  | 'windows.helper-missing'
  | 'windows.helper-probe-failed'
  | 'windows.policy-discovery-failed';

export type WindowsSandboxSupport =
  | {
      readonly level: 'degraded';
      readonly code: 'windows.appcontainer-compatibility-surface';
      readonly mechanism: 'appcontainer';
      readonly message: string;
    }
  | {
      readonly level: 'unsupported';
      readonly code: WindowsSandboxErrorCode;
      readonly mechanism: 'none';
      readonly message: string;
    };

type UnsupportedWindowsSandbox = Extract<WindowsSandboxSupport, { readonly level: 'unsupported' }>;

export interface WindowsSandboxInvocation {
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly stdio: 'ignore' | 'inherit';
  /** Ends the helper, and with it the Job Object that holds the sandbox. */
  readonly signal?: AbortSignal;
  /**
   * Bound for a preflight only. A real agent session runs as long as the user
   * needs it, but a probe that never returns is worse than one that fails:
   * the CLI would hang while looking exactly like a working boundary.
   */
  readonly timeoutMs?: number;
}

export interface WindowsSandboxRunnerDependencies {
  readonly platform: NodeJS.Platform;
  readonly architecture: string;
  readonly helperPath: string;
  readonly canAccess: (path: string) => Promise<boolean>;
  readonly makeTemporaryDirectory: (prefix: string) => Promise<string>;
  readonly makeDirectory: (path: string) => Promise<void>;
  readonly writeFile: (path: string, content: Buffer) => Promise<void>;
  readonly removeDirectory: (path: string) => Promise<void>;
  readonly invoke: (
    helper: string,
    args: readonly string[],
    invocation: WindowsSandboxInvocation,
  ) => Promise<SandboxRunResult>;
}

export interface WindowsEncodedResource {
  readonly scope: ResourceScope;
  readonly path: string;
}

export interface WindowsSandboxRequest {
  readonly executable: string;
  readonly cwd: string;
  readonly args: readonly string[];
  readonly reads: readonly WindowsEncodedResource[];
  readonly writes: readonly WindowsEncodedResource[];
  readonly denies: readonly WindowsDeniedResource[];
}

/** A native setup failure is never confused with a confined child exit. */
export class WindowsSandboxBackendError extends Error {
  constructor(
    readonly code: WindowsSandboxErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'WindowsSandboxBackendError';
  }
}

/**
 * Windows isolation backed by a native AppContainer launcher.
 *
 * The helper is mandatory. It creates an ephemeral AppContainer profile,
 * grants that package SID only the policy's explicit paths, starts the child
 * with zero network capabilities and no inherited handles, then assigns the
 * suspended child to a kill-on-close Job Object. ACL entries are capabilities
 * for the AppContainer token, never a fallback boundary: any token/profile,
 * ACL, process or Job setup failure aborts before an ordinary process can run.
 */
export class WindowsSandboxRunner implements SandboxRunner {
  readonly capabilities: SandboxCapabilities = {
    mechanism: 'appcontainer',
    fileModel: 'appcontainer-allowlist',
    networkGranularity: 'all-or-nothing',
  };

  private readonly dependencies: WindowsSandboxRunnerDependencies;

  constructor(
    dependencies: WindowsSandboxRunnerDependencies = defaultDependencies(),
    private readonly translator: WindowsPolicyTranslator = new WindowsPolicyTranslator(),
    private readonly denyScanner: WindowsReadDenyScanner = new WindowsReadDenyScanner(),
  ) {
    this.dependencies = dependencies;
  }

  async diagnose(): Promise<WindowsSandboxSupport> {
    const structural = await this.structuralSupport();
    if (structural !== null) return structural;

    let result: SandboxRunResult;
    try {
      result = await this.dependencies.invoke(
        this.dependencies.helperPath,
        ['--diagnose'],
        {
          cwd: dirname(this.dependencies.helperPath),
          env: definedEnvironment(process.env),
          stdio: 'ignore',
          timeoutMs: PREFLIGHT_TIMEOUT_MS,
        },
      );
    } catch (error) {
      return unsupported(
        'windows.helper-probe-failed',
        `The native AppContainer preflight could not start: ${errorMessage(error)}.`,
      );
    }

    if (result.signal !== null) {
      return unsupported(
        'windows.helper-probe-failed',
        `The native AppContainer preflight was terminated by ${result.signal}.`,
      );
    }
    const nativeCode = nativeErrorCode(result.exitCode);
    if (nativeCode !== null) {
      return unsupported(nativeCode, nativeErrorMessage(nativeCode));
    }
    if (result.exitCode !== 0) {
      return unsupported(
        'windows.helper-probe-failed',
        `The native AppContainer preflight returned exit code ${result.exitCode}.`,
      );
    }

    // Stable AppContainer is a real kernel boundary, but unlike LPAC it has a
    // documented compatibility surface for common system resources. Doctor
    // must retain that caveat even after the deny canary succeeds.
    return {
      level: 'degraded',
      code: 'windows.appcontainer-compatibility-surface',
      mechanism: 'appcontainer',
      message:
        'The stable AppContainer boundary is available with default-deny network access; ' +
        'its documented common-system compatibility surface remains visible.',
    };
  }

  async isAvailable(): Promise<boolean> {
    return (await this.diagnose()).level !== 'unsupported';
  }

  unenforceable(policy: SandboxPolicy, context: PathContext): readonly string[] {
    const placeholder = context.home.join(
      'AppData',
      'Local',
      'Temp',
      'agentkeeper-policy-profile',
      'home',
    );
    return this.translator.plan(policy, context, placeholder).gaps;
  }

  async run(
    policy: SandboxPolicy,
    context: PathContext,
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    const structural = await this.structuralSupport();
    if (structural !== null) {
      throw new WindowsSandboxBackendError(structural.code, structural.message);
    }

    const gaps = this.unenforceable(policy, context);
    if (gaps.length > 0) {
      throw new WindowsSandboxBackendError(
        'windows.request-invalid',
        `Refusing a Windows sandbox policy with unenforceable rules: ${gaps.join(' ')}`,
      );
    }

    const directory = await this.dependencies.makeTemporaryDirectory('agentkeeper-win-');
    const requestPath = join(directory, 'request.aksb');
    try {
      const overlayHome = AbsolutePath.of(join(directory, 'profile', 'home'));
      const plan = this.translator.plan(policy, context, overlayHome);
      await Promise.all(
        plan.overlay.directories.map((path) => this.dependencies.makeDirectory(path.value)),
      );

      let denies: readonly WindowsDeniedResource[];
      try {
        denies = await this.denyScanner.scan(plan.readDenyScans, policy, context);
      } catch (error) {
        if (error instanceof WindowsPolicyDiscoveryError) {
          throw new WindowsSandboxBackendError(error.code, error.message);
        }
        throw error;
      }
      const request: WindowsSandboxRequest = {
        executable: command.executable,
        cwd: command.cwd.value,
        args: [...command.args],
        reads: plan.reads.map(encodeResource),
        writes: plan.writes.map(encodeResource),
        denies,
      };
      await this.dependencies.writeFile(requestPath, encodeWindowsSandboxRequest(request));

      let result: SandboxRunResult;
      try {
        result = await this.dependencies.invoke(
          this.dependencies.helperPath,
          ['--request', requestPath],
          {
            cwd: command.cwd.value,
            env: {
              ...command.env,
              HOME: overlayHome.value,
              USERPROFILE: overlayHome.value,
              TMPDIR: overlayHome.join('tmp').value,
              TMP: overlayHome.join('tmp').value,
              TEMP: overlayHome.join('tmp').value,
            },
            stdio: 'inherit',
            ...(command.signal === undefined ? {} : { signal: command.signal }),
          },
        );
      } catch (error) {
        throw new WindowsSandboxBackendError(
          'windows.helper-probe-failed',
          `The native AppContainer launcher could not start: ${errorMessage(error)}.`,
        );
      }

      const nativeCode = nativeErrorCode(result.exitCode);
      if (nativeCode !== null) {
        throw new WindowsSandboxBackendError(nativeCode, nativeErrorMessage(nativeCode));
      }
      if (result.signal !== null) {
        throw new WindowsSandboxBackendError(
          'windows.helper-probe-failed',
          `The native AppContainer launcher was terminated by ${result.signal}.`,
        );
      }
      return result;
    } finally {
      await this.dependencies.removeDirectory(directory);
    }
  }

  private async structuralSupport(): Promise<UnsupportedWindowsSandbox | null> {
    if (this.dependencies.platform !== 'win32') {
      return unsupported(
        'windows.platform-unsupported',
        'The AppContainer launcher is available only on Windows.',
      );
    }
    if (!['x64', 'arm64'].includes(this.dependencies.architecture)) {
      return unsupported(
        'windows.architecture-unsupported',
        `No AppContainer helper is packaged for ${this.dependencies.architecture}.`,
      );
    }
    if (!(await this.dependencies.canAccess(this.dependencies.helperPath))) {
      return unsupported(
        'windows.helper-missing',
        `The native AppContainer helper is missing at ${this.dependencies.helperPath}.`,
      );
    }
    return null;
  }
}

export function encodeWindowsSandboxRequest(request: WindowsSandboxRequest): Buffer {
  const writer = new BinaryWriter();
  writer.bytes(REQUEST_MAGIC);
  writer.uint32(REQUEST_VERSION);
  writer.string(request.executable);
  writer.string(request.cwd);
  writer.strings(request.args);
  writer.resources(request.reads);
  writer.resources(request.writes);
  writer.denies(request.denies);
  const result = writer.finish();
  if (result.byteLength > MAX_REQUEST_BYTES) {
    throw new Error(`Windows sandbox request exceeds ${MAX_REQUEST_BYTES} bytes`);
  }
  return result;
}

/** Decoder kept beside the encoder so its binary contract can be unit-tested off Windows. */
export function decodeWindowsSandboxRequest(content: Buffer): WindowsSandboxRequest {
  if (content.byteLength > MAX_REQUEST_BYTES) throw new Error('Windows sandbox request is too large');
  const reader = new BinaryReader(content);
  if (!reader.bytes(REQUEST_MAGIC.byteLength).equals(REQUEST_MAGIC)) {
    throw new Error('Invalid Windows sandbox request magic');
  }
  if (reader.uint32() !== REQUEST_VERSION) {
    throw new Error('Unsupported Windows sandbox request version');
  }
  const request: WindowsSandboxRequest = {
    executable: reader.string(),
    cwd: reader.string(),
    args: reader.strings(),
    reads: reader.resources(),
    writes: reader.resources(),
    denies: reader.denies(),
  };
  reader.assertFinished();
  return request;
}

function encodeResource(ref: ResourceRef): WindowsEncodedResource {
  return { scope: ref.scope, path: ref.path.value };
}

function defaultDependencies(): WindowsSandboxRunnerDependencies {
  return {
    platform: process.platform,
    architecture: process.arch,
    helperPath: resolveWindowsSandboxHelper(import.meta.url, process.arch),
    canAccess: async (path) => {
      try {
        await access(path);
        return true;
      } catch {
        return false;
      }
    },
    makeTemporaryDirectory: async (prefix) => mkdtemp(join(tmpdir(), prefix)),
    makeDirectory: async (path) => {
      await mkdir(path, { recursive: true });
    },
    writeFile: async (path, content) => writeFile(path, content, { mode: 0o600 }),
    removeDirectory: async (path) => rm(path, { recursive: true, force: true }),
    invoke: invokeNativeHelper,
  };
}

export function resolveWindowsSandboxHelper(moduleUrl: string, architecture: string): string {
  const moduleDirectory = dirname(fileURLToPath(moduleUrl));
  const relative = join('native', `win32-${architecture}`, 'agentkeeper-sandbox.exe');
  const bundledCandidate = resolve(moduleDirectory, relative);
  if (!moduleDirectory.endsWith(`${join('infrastructure', 'sandbox')}`)) {
    return bundledCandidate;
  }
  const emittedRoot = resolve(moduleDirectory, '..', '..');
  return basename(emittedRoot) === 'src'
    ? resolve(emittedRoot, '..', 'dist', relative)
    : resolve(emittedRoot, relative);
}

function invokeNativeHelper(
  helper: string,
  args: readonly string[],
  invocation: WindowsSandboxInvocation,
): Promise<SandboxRunResult> {
  return new Promise((resolveResult, reject) => {
    const child = spawn(helper, [...args], {
      cwd: invocation.cwd,
      env: { ...invocation.env },
      stdio: invocation.stdio,
      windowsHide: false,
      shell: false,
    });
    const timer =
      invocation.timeoutMs === undefined
        ? null
        : setTimeout(() => {
            child.kill();
            reject(
              new Error(
                `the native helper did not answer within ${invocation.timeoutMs ?? 0} ms`,
              ),
            );
          }, invocation.timeoutMs);
    timer?.unref();

    // The helper binds its child to a Job Object with kill-on-close, so ending
    // the helper reclaims the whole AppContainer tree.
    const abort = (): void => {
      child.kill();
    };
    invocation.signal?.addEventListener('abort', abort, { once: true });
    const settle = (): void => {
      if (timer !== null) clearTimeout(timer);
      invocation.signal?.removeEventListener('abort', abort);
    };
    if (invocation.signal?.aborted === true) abort();

    child.once('error', (error) => {
      settle();
      reject(error);
    });
    child.once('exit', (code, signal) => {
      settle();
      resolveResult({ exitCode: code ?? (signal ? 128 : 1), signal: signal ?? null });
    });
  });
}

function definedEnvironment(source: NodeJS.ProcessEnv): Readonly<Record<string, string>> {
  return Object.fromEntries(
    Object.entries(source).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}

function unsupported(code: WindowsSandboxErrorCode, message: string): UnsupportedWindowsSandbox {
  return { level: 'unsupported', code, mechanism: 'none', message };
}

function nativeErrorCode(exitCode: number): WindowsSandboxErrorCode | null {
  return Object.prototype.hasOwnProperty.call(NATIVE_ERROR_CODES, exitCode)
    ? NATIVE_ERROR_CODES[exitCode as NativeErrorExitCode]
    : null;
}

function nativeErrorMessage(code: WindowsSandboxErrorCode): string {
  const messages: Readonly<Partial<Record<WindowsSandboxErrorCode, string>>> = {
    'windows.request-invalid': 'The native launcher rejected the sandbox request.',
    'windows.appcontainer-profile-failed':
      'Windows could not create or validate an AppContainer profile.',
    'windows.appcontainer-sid-failed': 'Windows could not derive the AppContainer package SID.',
    'windows.acl-setup-failed':
      'The native launcher could not grant the AppContainer its explicit path capabilities.',
    'windows.job-setup-failed':
      'The native launcher could not attach the suspended child to its lifecycle Job Object.',
    'windows.process-launch-failed':
      'Windows refused to create the child with the AppContainer security capabilities.',
    'windows.cleanup-failed':
      'The native launcher could not remove every temporary AppContainer capability.',
    'windows.child-wait-failed': 'The native launcher could not observe the confined child exit.',
    'windows.policy-discovery-failed':
      'The Windows policy compiler could not resolve every read-only deny rule safely.',
  };
  return messages[code] ?? 'The native AppContainer launcher failed its security precondition.';
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

class BinaryWriter {
  private readonly chunks: Buffer[] = [];

  bytes(value: Buffer): void {
    this.chunks.push(value);
  }

  uint32(value: number): void {
    const chunk = Buffer.allocUnsafe(4);
    chunk.writeUInt32LE(value, 0);
    this.chunks.push(chunk);
  }

  string(value: string): void {
    if (value.includes('\0')) throw new Error('Windows sandbox strings cannot contain NUL bytes');
    const encoded = Buffer.from(value, 'utf8');
    this.uint32(encoded.byteLength);
    this.bytes(encoded);
  }

  strings(values: readonly string[]): void {
    this.count(values.length);
    for (const value of values) this.string(value);
  }

  resources(values: readonly WindowsEncodedResource[]): void {
    this.count(values.length);
    for (const value of values) {
      this.uint32(value.scope === 'subtree' ? 1 : 0);
      this.string(value.path);
    }
  }

  denies(values: readonly WindowsDeniedResource[]): void {
    this.count(values.length);
    for (const value of values) {
      this.uint32(value.scope === 'subtree' ? 1 : 0);
      this.uint32(value.access === 'read' ? 0 : 1);
      this.string(value.path);
    }
  }

  finish(): Buffer {
    return Buffer.concat(this.chunks);
  }

  private count(value: number): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > MAX_COLLECTION_ITEMS) {
      throw new Error(`Invalid Windows sandbox collection size: ${value}`);
    }
    this.uint32(value);
  }
}

class BinaryReader {
  private offset = 0;

  constructor(private readonly content: Buffer) {}

  bytes(length: number): Buffer {
    if (length < 0 || this.offset + length > this.content.byteLength) {
      throw new Error('Truncated Windows sandbox request');
    }
    const value = this.content.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  uint32(): number {
    const value = this.bytes(4).readUInt32LE(0);
    return value;
  }

  string(): string {
    const length = this.uint32();
    const value = this.bytes(length).toString('utf8');
    if (value.includes('\0')) throw new Error('Windows sandbox strings cannot contain NUL bytes');
    return value;
  }

  strings(): readonly string[] {
    const count = this.collectionCount();
    return Array.from({ length: count }, () => this.string());
  }

  resources(): readonly WindowsEncodedResource[] {
    const count = this.collectionCount();
    return Array.from({ length: count }, () => {
      const scope = this.uint32();
      if (scope !== 0 && scope !== 1) throw new Error('Invalid Windows sandbox resource scope');
      return { scope: scope === 1 ? 'subtree' : 'file', path: this.string() };
    });
  }

  denies(): readonly WindowsDeniedResource[] {
    const count = this.collectionCount();
    return Array.from({ length: count }, () => {
      const scope = this.uint32();
      const access = this.uint32();
      if (scope !== 0 && scope !== 1) throw new Error('Invalid Windows sandbox deny scope');
      if (access !== 0 && access !== 1) throw new Error('Invalid Windows sandbox deny access');
      return {
        scope: scope === 1 ? 'subtree' : 'file',
        path: this.string(),
        // The current translator emits read denies. Reserving 1 makes a future
        // exact write deny explicit rather than ABI-breaking.
        access: access === 0 ? 'read' : 'write',
      };
    });
  }

  assertFinished(): void {
    if (this.offset !== this.content.byteLength) {
      throw new Error('Trailing data in Windows sandbox request');
    }
  }

  private collectionCount(): number {
    const count = this.uint32();
    if (count > MAX_COLLECTION_ITEMS) {
      throw new Error(`Windows sandbox collection exceeds ${MAX_COLLECTION_ITEMS} items`);
    }
    return count;
  }
}
