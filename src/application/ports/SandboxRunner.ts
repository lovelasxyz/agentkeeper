import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

export type SandboxMechanism = 'seatbelt' | 'bubblewrap' | 'appcontainer' | 'none';

/**
 * What a given mechanism can actually promise. Reported verbatim by
 * `agentkeeper status`, because a security tool that overstates its guarantees
 * is worse than no tool: the user stops taking their own precautions.
 */
export interface SandboxCapabilities {
  readonly mechanism: SandboxMechanism;
  /** How file access is expressed: rules, a mount namespace, or AppContainer path capabilities. */
  readonly fileModel: 'path-rules' | 'mount-namespace' | 'appcontainer-allowlist' | 'none';
  /** `port` = per-port rules, `all-or-nothing` = on/off, `none` = not confined. */
  readonly networkGranularity: 'port' | 'all-or-nothing' | 'none';
}

export interface SandboxCommand {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: AbsolutePath;
  readonly env: Readonly<Record<string, string>>;
  /**
   * Terminates the confined process tree when the caller stops waiting.
   *
   * A probe that times out must take its process with it. Abandoning one
   * leaves a sandboxed orphan holding its workspace, which is how a stuck
   * canary shows up as a cleanup error instead of an honest failure. Agent
   * sessions pass no signal: they run for as long as the user needs.
   */
  readonly signal?: AbortSignal;
}

export interface SandboxRunResult {
  readonly exitCode: number;
  readonly signal: NodeJS.Signals | null;
}

/**
 * The isolation layer, as the application sees it.
 *
 * `prepare` is separate from `run` so a policy can be compiled, inspected and
 * tested without spawning anything.
 */
export interface SandboxRunner {
  readonly capabilities: SandboxCapabilities;

  isAvailable(): Promise<boolean>;

  /**
   * Parts of the policy this mechanism cannot express, as human-readable lines.
   * Empty means the policy is enforced in full.
   */
  unenforceable(policy: SandboxPolicy, context: PathContext): readonly string[];

  run(
    policy: SandboxPolicy,
    context: PathContext,
    command: SandboxCommand,
  ): Promise<SandboxRunResult>;
}
