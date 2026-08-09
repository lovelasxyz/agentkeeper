import { PolicyBuilder, UnsafeWorkspaceError } from '../../domain/policy/PolicyBuilder.js';
import { EnvironmentPolicy } from '../../domain/policy/EnvironmentPolicy.js';
import { EnvironmentSanitizer } from '../../domain/policy/EnvironmentSanitizer.js';
import { WorkspaceId } from '../../domain/value-objects/WorkspaceId.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { StarterProfile } from '../../domain/policy/StarterProfile.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import type {
  AuditLog,
  Clock,
  DestinationBroker,
  DestinationBrokerSession,
  Environment,
  FileSystem,
  GrantStore,
  Logger,
  SandboxMechanism,
  SandboxRunner,
} from '../ports/index.js';

export interface RunRequest {
  readonly executable: string;
  readonly args: readonly string[];
  readonly profile: StarterProfile;
  /**
   * Deprecated compatibility field. Both values fail closed when no backend
   * can enforce the policy; an unconfined launch is never selected here.
   */
  readonly onUnavailable: 'fail' | 'warn';
}

export interface RunOutcome {
  readonly exitCode: number;
  readonly policy: SandboxPolicy;
  readonly mechanism: string;
  readonly warnings: readonly string[];
}

export type UnenforceablePolicyReason = 'backend-unavailable' | 'policy-gap';

/** Machine-readable refusal returned before an unconfined process can spawn. */
export class UnenforceablePolicyError extends Error {
  readonly code = 'AG_UNENFORCEABLE_POLICY' as const;
  readonly gaps: readonly string[];

  constructor(
    readonly mechanism: SandboxMechanism,
    readonly reason: UnenforceablePolicyReason,
    gaps: readonly string[],
  ) {
    const summary =
      reason === 'backend-unavailable'
        ? 'no supported isolation backend is available'
        : `${mechanism} cannot enforce the complete sandbox policy`;
    const detail = gaps.length > 0 ? ` ${gaps.join(' ')}` : '';
    super(`Refusing to run: ${summary}.${detail}`);
    this.name = 'UnenforceablePolicyError';
    this.gaps = Object.freeze([...gaps]);
  }
}

/**
 * `agentkeeper run -- <command>` (spec §4.6).
 *
 * Fail-closed: if a policy cannot be built, no mechanism is available, or the
 * selected mechanism cannot enforce the complete policy, the command does not
 * start. Unconfined execution and emergency bypass are deliberately outside
 * this use case so legacy configuration cannot quietly weaken the boundary.
 */
export class RunSandboxed {
  constructor(
    private readonly runner: SandboxRunner | null,
    _unconfined: SandboxRunner,
    private readonly policies: PolicyBuilder,
    private readonly grants: GrantStore,
    private readonly environment: Environment,
    private readonly files: FileSystem,
    private readonly audit: AuditLog,
    private readonly clock: Clock,
    private readonly logger: Logger,
    private readonly destinationBroker: DestinationBroker | null = null,
    private readonly environmentSanitizer: EnvironmentSanitizer = new EnvironmentSanitizer(),
  ) {}

  async execute(request: RunRequest): Promise<RunOutcome> {
    const context = this.resolveContext();
    const runner = this.selectRunner();
    const scratch = await this.files.makeTemporaryDirectory(
      this.trustedTemporaryRoot(context),
      'agentkeeper-',
    );
    let brokerSession: DestinationBrokerSession | null = null;

    try {
      let policy = await this.buildPolicy(
        request.profile,
        context,
        scratch,
        request.executable,
      );
      if (policy.network.length > 0) {
        if (this.destinationBroker === null) {
          throw new UnenforceablePolicyError(
            runner.capabilities.mechanism,
            'policy-gap',
            ['Destination-controlled network was requested, but no broker is configured.'],
          );
        }
        try {
          brokerSession = await this.destinationBroker.start({
            destinations: policy.network,
            platform: context.platform,
            scratch,
          });
        } catch (error) {
          throw new UnenforceablePolicyError(
            runner.capabilities.mechanism,
            'policy-gap',
            [`Destination broker could not start: ${(error as Error).message}`],
          );
        }
        policy = policy.withNetworkEnforcement(brokerSession.enforcement);
      }
      const gaps = runner.unenforceable(policy, context);
      if (gaps.length > 0) {
        throw new UnenforceablePolicyError(
          runner.capabilities.mechanism,
          'policy-gap',
          gaps,
        );
      }

      const sanitizedEnvironment = this.environmentSanitizer.sanitize(
        this.environment.variables,
        EnvironmentPolicy.forExecutable(request.executable),
      );
      const commandEnvironment = Object.freeze({
        ...sanitizedEnvironment.environment,
        // Identity and writable scratch paths are launcher-owned. Keeping
        // caller-provided HOME/TMPDIR would let a forged environment move the
        // deny boundary or re-open an arbitrary directory.
        HOME: context.home.value,
        PWD: context.workspace.value,
        TMPDIR: scratch.value,
        TMP: scratch.value,
        TEMP: scratch.value,
        ...(context.platform === 'win32' ? { USERPROFILE: context.home.value } : {}),
        // Launcher-owned marker: an inherited value was removed above, so the
        // child cannot spoof or disable it through the caller's environment.
        AGENTKEEPER_ACTIVE: '1',
        ...(brokerSession === null
          ? {}
          : {
              // Launcher-owned proxy variables. Direct network syscalls remain
              // closed by the OS backend, so ignoring these variables does not
              // turn into an egress bypass.
              HTTP_PROXY: brokerSession.proxyUrl,
              HTTPS_PROXY: brokerSession.proxyUrl,
              ALL_PROXY: brokerSession.proxyUrl,
              http_proxy: brokerSession.proxyUrl,
              https_proxy: brokerSession.proxyUrl,
              all_proxy: brokerSession.proxyUrl,
              npm_config_proxy: brokerSession.proxyUrl,
              npm_config_https_proxy: brokerSession.proxyUrl,
              NO_PROXY: '',
              no_proxy: '',
              NODE_USE_ENV_PROXY: '1',
              AGENTKEEPER_BROKER_ACTIVE: '1',
            }),
      });

      const warnings: readonly string[] = Object.freeze([]);

      await this.audit.append({
        at: this.clock.now(),
        event: 'run.start',
        details: {
          mechanism: runner.capabilities.mechanism,
          workspace: context.workspace.value,
          executable: request.executable,
          unenforced: warnings.length,
          environmentRemovedCount: sanitizedEnvironment.removedCount,
          environmentRemovedNames: sanitizedEnvironment.removedNames,
          networkDestinationCount: policy.network.length,
          networkEnforcement: policy.networkEnforcement.kind,
        },
      });

      const result = await runner.run(policy, context, {
        executable: request.executable,
        args: request.args,
        cwd: context.workspace,
        env: commandEnvironment,
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
    } finally {
      // Scratch can contain generated source or transient credentials. It is
      // private while the command runs and removed on every exit path.
      try {
        if (brokerSession !== null) await brokerSession.close();
      } finally {
        await this.files.remove(scratch);
      }
    }
  }

  private trustedTemporaryRoot(context: PathContext): AbsolutePath {
    switch (context.platform) {
      case 'darwin':
        return AbsolutePath.of('/private/tmp');
      case 'linux':
        return AbsolutePath.of('/tmp');
      case 'win32':
        return context.home.join('AppData', 'Local', 'Temp');
    }
  }

  private assertCallerHomeDoesNotContainWorkspace(context: PathContext): void {
    const callerHome = this.files.realPath(this.environment.home);
    if (!callerHome.equals(context.home) && context.workspace.contains(callerHome)) {
      throw new UnsafeWorkspaceError(
        context.workspace,
        callerHome.join('.ssh'),
        'caller-home',
      );
    }
  }

  /**
   * Every path entering a policy is resolved first. On macOS `/var` is a
   * symlink to `/private/var`, and the kernel matches rules against the
   * resolved path — an unresolved one produces rules that quietly match
   * nothing.
   */
  private resolveContext(): PathContext {
    const context = {
      home: this.files.realPath(this.environment.identityHome),
      workspace: this.files.realPath(this.environment.cwd),
      platform: this.environment.platform,
    };
    this.assertCallerHomeDoesNotContainWorkspace(context);
    return context;
  }

  private async buildPolicy(
    profile: StarterProfile,
    context: PathContext,
    scratch: AbsolutePath,
    executable: string,
  ): Promise<SandboxPolicy> {
    try {
      const callerHome = this.files.realPath(this.environment.home);
      const storedGrants = await this.grants.all();
      // A forged HOME may point at an attacker-authored allowlist. Runtime
      // grants are still tier-checked; hand-written tier-2 overrides are
      // accepted only from the canonical identity home.
      const grants = callerHome.equals(context.home)
        ? storedGrants
        : storedGrants.filter((grant) => grant.origin !== 'manual');
      if (grants.length !== storedGrants.length) {
        this.logger.warn('Ignored hand-written grants from a non-canonical HOME.');
      }

      const { policy, rejected } = this.policies.build({
        profile,
        grants,
        context,
        workspaceId: WorkspaceId.fromPath(context.workspace),
        toolchainRoots: this.resolveAll(this.environment.toolchainRoots()),
        stateDir: this.files.realPath(context.home.join('.agentkeeper')),
        agentStateDirs: this.resolveAll(
          this.agentStateDirs(context.home, executableName(executable)),
        ),
        tempDirs: [scratch],
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

  private selectRunner(): SandboxRunner {
    if (this.runner !== null) return this.runner;
    throw new UnenforceablePolicyError(
      'none',
      'backend-unavailable',
      [
        'No supported OS sandbox backend is available; without layer 1 the command ' +
          'would have full user permissions.',
      ],
    );
  }

  private agentStateDirs(home: AbsolutePath, executable: string): readonly AbsolutePath[] {
    const relative = (() => {
      switch (executable) {
        case 'claude':
        case 'claude-code':
          return ['.claude', '.config/claude'];
        case 'codex':
          return ['.codex'];
        case 'gemini':
          return ['.gemini'];
        case 'opencode':
          return ['.config/opencode', '.local/share/opencode', '.cache/opencode'];
        case 'cursor-agent':
          return ['.cursor'];
        default:
          return [];
      }
    })();
    return relative.map((entry) => home.join(entry));
  }

  private resolveAll(paths: readonly AbsolutePath[]): readonly AbsolutePath[] {
    return paths.map((path) => this.files.realPath(path));
  }
}

function executableName(executable: string): string {
  const basename = executable.replace(/\\/g, '/').split('/').at(-1) ?? '';
  return basename.toLowerCase().replace(/\.(exe|cmd|bat|ps1)$/i, '');
}
