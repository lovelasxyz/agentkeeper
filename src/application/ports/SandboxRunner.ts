import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

export type SandboxMechanism = 'seatbelt' | 'bubblewrap' | 'none';

/**
 * What a given mechanism can actually promise. Reported verbatim by
 * `agent-guard status`, because a security tool that overstates its guarantees
 * is worse than no tool: the user stops taking their own precautions.
 */
export interface SandboxCapabilities {
  readonly mechanism: SandboxMechanism;
  /** How file access is expressed: per-path rules, or a constructed mount namespace. */
  readonly fileModel: 'path-rules' | 'mount-namespace' | 'none';
  /** `port` = per-port rules, `all-or-nothing` = on/off, `none` = not confined. */
  readonly networkGranularity: 'port' | 'all-or-nothing' | 'none';
}

export interface SandboxCommand {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: AbsolutePath;
  readonly env: Readonly<Record<string, string>>;
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
