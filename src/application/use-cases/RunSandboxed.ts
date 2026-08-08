import { PolicyBuilder, UnsafeWorkspaceError } from '../../domain/policy/PolicyBuilder.js';
import { WorkspaceId } from '../../domain/value-objects/WorkspaceId.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { StarterProfile } from '../../domain/policy/StarterProfile.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import type {
  AuditLog,
  Clock,
  Environment,
  FileSystem,
  GrantStore,
  Logger,
  SandboxRunner,
} from '../ports/index.js';

export interface RunRequest {
  readonly executable: string;
  readonly args: readonly string[];
  readonly profile: StarterProfile;
  /** `fail` refuses to run unconfined; `warn` runs and says so loudly. */
  readonly onUnavailable: 'fail' | 'warn';
}

export interface RunOutcome {
  readonly exitCode: number;
  readonly policy: SandboxPolicy;
  readonly mechanism: string;
  readonly warnings: readonly string[];
}

/**
 * `agent-guard run -- <command>` (spec §4.6).
 *
 * Fail-closed: if a policy cannot be built, or no mechanism is available and
 * the user did not explicitly accept that, the command does not start. A quiet
 * unconfined launch is the one outcome this use case must never produce —
 * the user would believe they were protected, which is worse than knowing they
 * are not.
 */
export class RunSandboxed {
  constructor(
    private readonly runner: SandboxRunner | null,
    private readonly unconfined: SandboxRunner,
    private readonly policies: PolicyBuilder,
    private readonly grants: GrantStore,
    private readonly environment: Environment,
    private readonly files: FileSystem,
    private readonly audit: AuditLog,
    private readonly clock: Clock,
    private readonly logger: Logger,
  ) {}

  async execute(request: RunRequest): Promise<RunOutcome> {
    const context = this.resolveContext();
    const policy = await this.buildPolicy(request.profile, context);
    const runner = this.selectRunner(request.onUnavailable);

    const warnings = [...runner.unenforceable(policy, context)];
    for (const warning of warnings) this.logger.warn(warning);

    await this.audit.append({
      at: this.clock.now(),
      event: 'run.start',
      details: {
        mechanism: runner.capabilities.mechanism,
        workspace: context.workspace.value,
        executable: request.executable,
        unenforced: warnings.length,
      },
    });

    const result = await runner.run(policy, context, {
      executable: request.executable,
      args: request.args,
      cwd: context.workspace,
      env: { ...this.environment.variables, AGENT_GUARD_ACTIVE: '1' },
    });

    await this.audit.append({
      at: this.clock.now(),
      event: 'run.finish',
      details: { exitCode: result.exitCode, signal: result.signal },
    });

    return {
      exitCode: result.exitCode,
      policy,
      mechanism: runner.capabilities.mechanism,
      warnings,
    };
  }

  /**
   * Every path entering a policy is resolved first. On macOS `/var` is a
   * symlink to `/private/var`, and the kernel matches rules against the
   * resolved path — an unresolved one produces rules that quietly match
   * nothing.
   */
  private resolveContext(): PathContext {
    return {
      home: this.files.realPath(this.environment.home),
      workspace: this.files.realPath(this.environment.cwd),
      platform: this.environment.platform,
    };
  }

  private async buildPolicy(
    profile: StarterProfile,
    context: PathContext,
  ): Promise<SandboxPolicy> {
    try {
      const { policy, rejected } = this.policies.build({
        profile,
        grants: await this.grants.all(),
        context,
        workspaceId: WorkspaceId.fromPath(context.workspace),
        toolchainRoots: this.resolveAll(this.environment.toolchainRoots()),
        stateDir: this.files.realPath(this.environment.home.join('.agent-guard')),
        agentStateDirs: this.resolveAll(this.agentStateDirs()),
        tempDirs: this.resolveAll([this.environment.tempDir]),
      });

      for (const entry of rejected) {
        this.logger.warn(
          `Not granted: ${entry.resource} (${entry.access}) — ${entry.detail}`,
        );
      }
      return policy;
    } catch (error) {
      if (error instanceof UnsafeWorkspaceError) throw error;
      throw new Error(
        `Could not build a sandbox policy: ${(error as Error).message}. ` +
          'Refusing to start the command unconfined.',
      );
    }
  }

  private selectRunner(onUnavailable: 'fail' | 'warn'): SandboxRunner {
    if (this.runner !== null) return this.runner;
    if (onUnavailable === 'fail') {
      throw new Error(
        'No isolation mechanism is available on this platform. Refusing to run: without ' +
          'layer 1 the command would have your full permissions. Set sandbox.onUnavailable ' +
          'to "warn" in ~/.agent-guard/config.json to accept that deliberately.',
      );
    }
    this.logger.warn(
      'Running WITHOUT isolation: no supported mechanism was found. Only layer 2 is active.',
    );
    return this.unconfined;
  }

  private agentStateDirs(): readonly AbsolutePath[] {
    const home = this.environment.home;
    return ['.claude', '.gemini', '.cursor', '.codex', '.config/claude'].map((relative) =>
      home.join(relative),
    );
  }

  private resolveAll(paths: readonly AbsolutePath[]): readonly AbsolutePath[] {
    return paths.map((path) => this.files.realPath(path));
  }
}
