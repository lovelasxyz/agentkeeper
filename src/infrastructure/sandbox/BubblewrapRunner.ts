import { spawn } from 'node:child_process';
import { access, constants } from 'node:fs/promises';
import { BubblewrapArgumentBuilder } from './BubblewrapArgumentBuilder.js';
import type {
  SandboxCapabilities,
  SandboxCommand,
  SandboxRunResult,
  SandboxRunner,
} from '../../application/ports/SandboxRunner.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';

const CANDIDATES = ['/usr/bin/bwrap', '/bin/bwrap', '/usr/local/bin/bwrap'];
const FORWARDED_SIGNALS: readonly NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT'];

/**
 * Linux isolation via bubblewrap (spec §4.1).
 *
 * The model is different from Seatbelt's in a way that matters: bubblewrap
 * builds a mount namespace instead of evaluating per-path rules. There is no
 * "deny this pattern" — a path is absent because it was never mounted. That
 * makes anchored refusals free and pattern refusals impossible, and it makes
 * networking all-or-nothing rather than per-port. Both gaps are reported by
 * `unenforceable()` rather than papered over.
 */
export class BubblewrapRunner implements SandboxRunner {
  readonly capabilities: SandboxCapabilities = {
    mechanism: 'bubblewrap',
    fileModel: 'mount-namespace',
    networkGranularity: 'all-or-nothing',
  };

  private executable: string | null = null;

  constructor(private readonly args: BubblewrapArgumentBuilder = new BubblewrapArgumentBuilder()) {}

  async isAvailable(): Promise<boolean> {
    if (process.platform !== 'linux') return false;
    return (await this.locate()) !== null;
  }

  unenforceable(policy: SandboxPolicy, context: PathContext): readonly string[] {
    const gaps: string[] = [];

    for (const deny of policy.denies) {
      if (deny.pattern.literalPrefix(context.home) === null) {
        gaps.push(
          `${deny.sourceId}: "${deny.pattern.raw}" has no fixed anchor, and a mount ` +
            'namespace cannot express a wildcard refusal. Layer 2 still blocks it.',
        );
      }
    }

    const ports = policy.network.filter((rule) => rule.port !== '*');
    if (ports.length > 0) {
      gaps.push(
        `network is on or off here, so ${ports.map(String).join(', ')} becomes ` +
          'unrestricted outbound access.',
      );
    }
    return gaps;
  }

  buildArgs(policy: SandboxPolicy, context: PathContext, command: SandboxCommand): string[] {
    return this.args.build(policy, context, command);
  }

  async run(
    policy: SandboxPolicy,
    context: PathContext,
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    const executable = await this.locate();
    if (executable === null) {
      throw new Error('bubblewrap (bwrap) is not installed; refusing to run unconfined');
    }
    return this.spawnConfined(executable, this.buildArgs(policy, context, command), command);
  }

  private async locate(): Promise<string | null> {
    if (this.executable !== null) return this.executable;
    for (const candidate of CANDIDATES) {
      try {
        await access(candidate, constants.X_OK);
        this.executable = candidate;
        return candidate;
      } catch {
        continue;
      }
    }
    return null;
  }

  private spawnConfined(
    executable: string,
    args: readonly string[],
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, [...args], {
        cwd: command.cwd.value,
        env: { ...command.env },
        stdio: 'inherit',
      });

      const handlers = FORWARDED_SIGNALS.map((signal) => {
        const handler = (): void => {
          child.kill(signal);
        };
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
