import { spawn } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
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
        // Outside-workspace wildcard denies are enforced by the empty-home
        // topology: nothing outside the workspace exists unless a profile or
        // runtime grant mounted it. Bundled profile roots are reviewed as part
        // of the TCB. A broad runtime subtree is not, so it remains a loud gap.
        if (
          deny.exceptWithin !== null &&
          policy.runtimeRefs.every(
            (ref) => ref.scope === 'file' || context.workspace.contains(ref.path),
          )
        ) {
          continue;
        }
        gaps.push(
          `${deny.sourceId}: "${deny.pattern.raw}" has no fixed anchor, and a mount ` +
            'namespace cannot express a wildcard refusal. Layer 2 still blocks it.',
        );
      }
    }

    if (
      policy.network.length > 0 &&
      !(
        policy.networkEnforcement.kind === 'brokered' &&
        policy.networkEnforcement.transport.kind === 'unix-socket-relay'
      )
    ) {
      gaps.push(
        `bubblewrap has no verified Unix-relay network broker for ${policy.network.map(String).join(', ')}; ` +
          'the network namespace remains isolated and outbound traffic stays blocked.',
      );
    }
    return gaps;
  }

  buildArgs(policy: SandboxPolicy, context: PathContext, command: SandboxCommand): string[] {
    return this.args.build(policy, context, this.withNetworkRelay(policy, command));
  }

  async run(
    policy: SandboxPolicy,
    context: PathContext,
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    const gaps = this.unenforceable(policy, context);
    if (gaps.length > 0) {
      throw new Error(`Refusing an unenforceable bubblewrap policy: ${gaps.join(' ')}`);
    }
    const executable = await this.locate();
    if (executable === null) {
      throw new Error('bubblewrap (bwrap) is not installed; refusing to run unconfined');
    }
    return this.spawnConfined(executable, this.buildArgs(policy, context, command), command);
  }

  private withNetworkRelay(policy: SandboxPolicy, command: SandboxCommand): SandboxCommand {
    if (
      policy.networkEnforcement.kind !== 'brokered' ||
      policy.networkEnforcement.transport.kind !== 'unix-socket-relay'
    ) {
      return command;
    }
    const transport = policy.networkEnforcement.transport;
    return {
      executable: process.execPath,
      args: [
        transport.relayScript.value,
        transport.socketPath.value,
        String(transport.port),
        command.executable,
        ...command.args,
      ],
      cwd: command.cwd,
      env: command.env,
    };
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
          // bwrap forks rather than execs, and `--new-session` — the flag that
          // stops a compromised agent injecting keystrokes into the terminal —
          // puts the sandbox in its own session. Signalling bwrap alone kills
          // the tree through `--die-with-parent` without the agent ever seeing
          // the signal, so it never gets to shut down cleanly. Deliver it to
          // the confined tree first, then to bwrap: the agent sits below an
          // in-namespace init, and below the network relay when egress is
          // brokered, so only a full walk reaches it.
          for (const descendant of descendantsOf(child.pid)) {
            try {
              process.kill(descendant, signal);
            } catch {
              // Already gone: the tree is collapsing, which is the intent.
            }
          }
          child.kill(signal);
        };
        process.on(signal, handler);
        return [signal, handler] as const;
      });
      // `--die-with-parent` takes the namespace down with bwrap, so killing it
      // is enough to reclaim the whole confined tree.
      const abort = (): void => {
        child.kill('SIGKILL');
      };
      command.signal?.addEventListener('abort', abort, { once: true });
      const detach = (): void => {
        for (const [signal, handler] of handlers) process.off(signal, handler);
        command.signal?.removeEventListener('abort', abort);
      };
      if (command.signal?.aborted === true) abort();

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

/**
 * Every descendant of a process, as the host PID namespace sees them.
 *
 * A nested PID namespace is fully visible from the host, but the tree is
 * deeper than it looks: bwrap runs an init as PID 1 inside the namespace and
 * the agent below it, with the network relay in between when egress is
 * brokered. Signalling only the direct child hits that init, which ignores
 * signals it has no handler for — so the walk has to reach the whole tree.
 *
 * Built from `/proc/<pid>/stat` rather than `.../children`, which is optional
 * kernel configuration; the parent field always exists.
 */
function descendantsOf(pid: number | undefined): readonly number[] {
  if (pid === undefined || process.platform !== 'linux') return [];

  const parents = new Map<number, number>();
  let entries: string[];
  try {
    entries = readdirSync('/proc');
  } catch {
    return [];
  }
  for (const entry of entries) {
    const candidate = Number.parseInt(entry, 10);
    if (!Number.isInteger(candidate) || String(candidate) !== entry) continue;
    try {
      const stat = readFileSync(`/proc/${candidate}/stat`, 'utf8');
      // `pid (comm) state ppid ...`, and comm may contain spaces or parens.
      const afterName = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      const parent = Number.parseInt(afterName[1] ?? '', 10);
      if (Number.isInteger(parent)) parents.set(candidate, parent);
    } catch {
      // The process exited while we were reading; it needs no signal.
    }
  }

  const found: number[] = [];
  const queue = [pid];
  while (queue.length > 0) {
    const current = queue.shift() as number;
    for (const [child, parent] of parents) {
      if (parent !== current || found.includes(child)) continue;
      found.push(child);
      queue.push(child);
    }
  }
  return found;
}
