import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { access, constants } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SeatbeltProfileCompiler } from './SeatbeltProfileCompiler.js';
import type {
  SandboxCapabilities,
  SandboxCommand,
  SandboxRunResult,
  SandboxRunner,
} from '../../application/ports/SandboxRunner.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';

const SANDBOX_EXEC = '/usr/bin/sandbox-exec';
const FORWARDED_SIGNALS: readonly NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'];

/**
 * macOS isolation via Seatbelt (spec §4.1).
 *
 * `sandbox-exec` is formally deprecated by Apple and still the only built-in
 * way to confine a process without installing anything. The risk is stated in
 * the README rather than hidden, and the compiler is separated from the runner
 * so a replacement mechanism means one new class, not a rewrite.
 */
export class SeatbeltRunner implements SandboxRunner {
  readonly capabilities: SandboxCapabilities = {
    mechanism: 'seatbelt',
    fileModel: 'path-rules',
    networkGranularity: 'port',
  };

  constructor(private readonly compiler: SeatbeltProfileCompiler = new SeatbeltProfileCompiler()) {}

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'darwin') return false;
    try {
      await access(SANDBOX_EXEC, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  }

  /** Seatbelt expresses every rule this policy can produce. */
  unenforceable(): readonly string[] {
    return [];
  }

  /** Exposed for `agent-guard status --explain` and for the sandbox test suite. */
  compile(policy: SandboxPolicy, context: PathContext): string {
    return this.compiler.compile(policy, context);
  }

  async run(
    policy: SandboxPolicy,
    context: PathContext,
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    const directory = await mkdtemp(join(tmpdir(), 'agent-guard-'));
    const profilePath = join(directory, 'policy.sb');
    await writeFile(profilePath, this.compiler.compile(policy, context), { mode: 0o600 });

    try {
      return await this.spawnConfined(profilePath, command);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }

  private spawnConfined(
    profilePath: string,
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(
        SANDBOX_EXEC,
        ['-f', profilePath, command.executable, ...command.args],
        {
          cwd: command.cwd.value,
          env: { ...command.env },
          // Inherited stdio is what keeps the wrapper invisible: the TTY, its
          // colours and its interactive input all belong to the child directly.
          stdio: 'inherit',
        },
      );

      const forward = (signal: NodeJS.Signals) => (): void => {
        child.kill(signal);
      };
      const handlers = FORWARDED_SIGNALS.map((signal) => {
        const handler = forward(signal);
        process.on(signal, handler);
        return [signal, handler] as const;
      });
      const detach = (): void => {
        for (const [signal, handler] of handlers) process.off(signal, handler);
      };

      child.once('error', (error) => {
        detach();
        reject(error);
      });
      child.once('exit', (code, signal) => {
        detach();
        resolve({ exitCode: code ?? (signal ? 128 : 1), signal: signal ?? null });
      });
    });
  }
}
