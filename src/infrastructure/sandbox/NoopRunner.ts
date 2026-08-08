import { spawn } from 'node:child_process';
import type {
  SandboxCapabilities,
  SandboxCommand,
  SandboxRunResult,
  SandboxRunner,
} from '../../application/ports/SandboxRunner.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';

/**
 * Null Object for platforms with no supported mechanism (spec §8.3).
 *
 * It exists so the rest of the system has no `if (sandbox)` branches — not so
 * that an unprotected run can happen quietly. `unenforceable()` returns the
 * whole policy, and `RunSandboxed` refuses to use this runner unless the user
 * has explicitly configured `onUnavailable: "warn"`.
 */
export class NoopRunner implements SandboxRunner {
  readonly capabilities: SandboxCapabilities = {
    mechanism: 'none',
    fileModel: 'none',
    networkGranularity: 'none',
  };

  async isAvailable(): Promise<boolean> {
    return true;
  }

  unenforceable(policy: SandboxPolicy, _context: PathContext): readonly string[] {
    return [
      'No isolation mechanism is available on this platform: the command runs ' +
        `with your full user permissions. ${policy.denies.length} refusals and ` +
        `${policy.reads.length} read rules are not enforced. Only layer 2 is active.`,
    ];
  }

  async run(
    _policy: SandboxPolicy,
    _context: PathContext,
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(command.executable, [...command.args], {
        cwd: command.cwd.value,
        env: { ...command.env },
        stdio: 'inherit',
      });
      child.once('error', reject);
      child.once('exit', (code, signal) =>
        resolve({ exitCode: code ?? (signal ? 128 : 1), signal: signal ?? null }),
      );
    });
  }
}
