declare const __AGENTKEEPER_VERSION__: string;

import { AccessTierResolver } from '../domain/policy/AccessTierResolver.js';
import { PolicyBuilder } from '../domain/policy/PolicyBuilder.js';
import { SensitivePathRegistry } from '../domain/paths/SensitivePathRegistry.js';

import { NodeFileSystem } from '../infrastructure/fs/NodeFileSystem.js';
import { JsonDaemonRuntime } from '../infrastructure/store/JsonDaemonRuntime.js';
import {
  JsonBaselineStore,
  JsonDecisionStore,
  JsonGrantStore,
  JsonlAuditLog,
} from '../infrastructure/store/stores.js';
import {
  ConsoleLogger,
  DesktopNotifier,
  ProcessEnvironment,
  SilentLogger,
  SilentPrompter,
  SystemClock,
  TerminalPrompter,
} from '../infrastructure/adapters.js';
import { Configuration } from '../infrastructure/config/Configuration.js';

import { GrantAccess } from '../application/use-cases/GrantAccess.js';
import { ApplyChanges } from '../application/use-cases/ApplyChanges.js';

import { AbsolutePath } from '../domain/value-objects/AbsolutePath.js';
import type { ScanEngine } from '../domain/services/ScanEngine.js';
import type { RunSandboxed } from '../application/use-cases/RunSandboxed.js';
import type { EvaluateToolCall } from '../application/use-cases/EvaluateToolCall.js';
import type { ScanWorkspace } from '../application/use-cases/ScanWorkspace.js';
import type { ReviewFindings } from '../application/use-cases/ReviewFindings.js';
import type { ProfileLoader } from '../infrastructure/config/ProfileLoader.js';
import type { DesktopNotifier as Notifier } from '../infrastructure/adapters.js';
import type { Artifact } from '../domain/entities/Artifact.js';
import type { BaselineChange } from '../domain/entities/BaselineChange.js';
import type { ToolCall } from '../domain/entities/ToolCall.js';
import type { Logger, Prompter, SandboxRunner } from '../application/ports/index.js';
import type { TransactionalProtectionInstallationExecutor } from '../application/use-cases/ExecuteProtectionInstallation.js';
import type {
  ManagedAgent,
} from '../infrastructure/install/ManagedInstallation.js';
import type { ProtectionInstallationPlanner } from '../infrastructure/install/ProtectionInstallation.js';

export interface ContainerOptions {
  /** Hooks write structured JSON to stdout; a stray log line would corrupt it. */
  readonly quiet?: boolean;
  readonly interactive?: boolean;
}

export interface ManagedInstallationComponents {
  readonly planner: ProtectionInstallationPlanner;
  readonly executor: TransactionalProtectionInstallationExecutor;
  readonly agents: readonly ManagedAgent[];
  /** Recorded launch path, which a background service must be able to read. */
  readonly entrypoint: AbsolutePath;
}

/**
 * Manual dependency injection, in one place (spec §8.3).
 *
 * No decorator framework and no reflection, for a measured reason: the hook has
 * a 50 ms cold-start budget and the wrapper 100 ms, and metadata-driven
 * containers spend a meaningful slice of that before any work begins. Wiring by
 * hand costs a few dozen lines and stays legible.
 */
export class Container {
  readonly environment = new ProcessEnvironment();
  readonly clock = new SystemClock();
  readonly files = new NodeFileSystem();
  readonly logger: Logger;
  readonly prompter: Prompter;

  readonly paths: SensitivePathRegistry;
  readonly tiers: AccessTierResolver;
  readonly policies: PolicyBuilder;

  readonly grants: JsonGrantStore;
  readonly decisions: JsonDecisionStore;
  readonly baseline: JsonBaselineStore;
  readonly audit: JsonlAuditLog;

  private configuration: Configuration | null = null;

  constructor(private readonly options: ContainerOptions = {}) {
    this.logger = options.quiet === true ? new SilentLogger() : new ConsoleLogger();
    this.prompter = options.interactive === false ? new SilentPrompter() : new TerminalPrompter();

    this.paths = SensitivePathRegistry.default();
    this.tiers = new AccessTierResolver(this.paths);
    this.policies = new PolicyBuilder(this.tiers, this.paths);

    this.grants = new JsonGrantStore(this.files, this.stateDir, this.environment.identityHome);
    this.decisions = new JsonDecisionStore(this.files, this.stateDir);
    this.baseline = new JsonBaselineStore(this.files, this.stateDir);
    this.audit = new JsonlAuditLog(this.files, this.stateDir);
  }

  get stateDir(): AbsolutePath {
    return this.environment.identityHome.join('.agentkeeper');
  }

  get backupDir(): AbsolutePath {
    return this.stateDir.join('backups');
  }

  /**
   * The published version, injected at build time.
   *
   * Declared here as well as on the router because the router resolves
   * `--version` without ever building a container, and must not pull the whole
   * composition graph onto the hook path to do it.
   */
  get version(): string {
    return typeof __AGENTKEEPER_VERSION__ === 'string' ? __AGENTKEEPER_VERSION__ : '0.0.0-dev';
  }

  get daemonRuntime(): JsonDaemonRuntime {
    return new JsonDaemonRuntime(this.files, this.stateDir);
  }

  async config(): Promise<Configuration> {
    this.configuration ??= await Configuration.load(this.files, this.stateDir);
    return this.configuration;
  }

  async profiles(): Promise<ProfileLoader> {
    const { ProfileLoader } = await import('../infrastructure/config/ProfileLoader.js');
    return new ProfileLoader(this.files);
  }

  notifier(): Notifier {
    return new DesktopNotifier(this.environment.platform, this.logger);
  }

  async sandboxRunner(): Promise<SandboxRunner | null> {
    const config = await this.config();
    if (!config.sandboxEnabled) return null;
    const { SandboxRunnerFactory } = await import(
      '../infrastructure/sandbox/SandboxRunnerFactory.js'
    );
    return new SandboxRunnerFactory().forPlatform(this.environment.platform);
  }

  async artifactScanner(): Promise<ScanEngine<Artifact>> {
    const [{ ScanEngine }, { RuleRegistry }, { ARTIFACT_RULES }] = await Promise.all([
      import('../domain/services/ScanEngine.js'),
      import('../domain/rules/RuleRegistry.js'),
      import('../domain/rules/artifact/index.js'),
    ]);
    return new ScanEngine(RuleRegistry.of(ARTIFACT_RULES));
  }

  async toolCallScanner(includeActions: boolean): Promise<ScanEngine<ToolCall>> {
    const [{ ScanEngine }, { RuleRegistry }, toolcall] = await Promise.all([
      import('../domain/services/ScanEngine.js'),
      import('../domain/rules/RuleRegistry.js'),
      import('../domain/rules/toolcall/index.js'),
    ]);
    const rules = includeActions
      ? [...toolcall.blockingRules(this.tiers), ...toolcall.actionRules()]
      : toolcall.blockingRules(this.tiers);
    return new ScanEngine(RuleRegistry.of(rules));
  }

  async persistenceScanner(): Promise<ScanEngine<BaselineChange>> {
    const [{ ScanEngine }, { RuleRegistry }, { PERSISTENCE_RULES }] = await Promise.all([
      import('../domain/services/ScanEngine.js'),
      import('../domain/rules/RuleRegistry.js'),
      import('../domain/rules/persistence/index.js'),
    ]);
    return new ScanEngine(RuleRegistry.of(PERSISTENCE_RULES));
  }

  async runSandboxed(): Promise<RunSandboxed> {
    const [{ RunSandboxed }, { SandboxRunnerFactory }, { NodeDestinationBroker }] = await Promise.all([
      import('../application/use-cases/RunSandboxed.js'),
      import('../infrastructure/sandbox/SandboxRunnerFactory.js'),
      import('../infrastructure/network/NodeDestinationBroker.js'),
    ]);
    return new RunSandboxed(
      await this.sandboxRunner(),
      new SandboxRunnerFactory().unconfined(),
      this.policies,
      this.grants,
      this.environment,
      this.files,
      this.audit,
      this.clock,
      this.logger,
      new NodeDestinationBroker(),
    );
  }

  async evaluateToolCall(): Promise<EvaluateToolCall> {
    const [{ EvaluateToolCall }, config] = await Promise.all([
      import('../application/use-cases/EvaluateToolCall.js'),
      this.config(),
    ]);
    return new EvaluateToolCall(
      await this.toolCallScanner(config.isEnabled('categoryA')),
      this.decisions,
      this.audit,
      this.clock,
      config,
    );
  }

  async scanWorkspace(): Promise<ScanWorkspace> {
    const { ScanWorkspace } = await import('../application/use-cases/ScanWorkspace.js');
    return new ScanWorkspace(
      this.files,
      await this.artifactScanner(),
      this.decisions,
      await this.config(),
      this.clock,
    );
  }

  async reviewFindings(): Promise<ReviewFindings> {
    const { ReviewFindings } = await import('../application/use-cases/ReviewFindings.js');
    return new ReviewFindings(this.prompter, this.decisions, this.audit, this.clock);
  }

  grantAccess(): GrantAccess {
    return new GrantAccess(this.grants, this.tiers, this.audit, this.clock);
  }

  applyChanges(): ApplyChanges {
    return new ApplyChanges(this.files, this.backupDir, this.audit, this.clock);
  }

  /** Resolves original agent binaries before managed shims are placed on PATH. */
  async managedInstallation(): Promise<ManagedInstallationComponents> {
    const [
      { resolve },
      { ExecutableResolver },
      managed,
      fileExecution,
      protection,
      protectionExecution,
      system,
    ] = await Promise.all([
      import('node:path'),
      import('../infrastructure/system/ExecutableResolver.js'),
      import('../infrastructure/install/ManagedInstallation.js'),
      import('../application/use-cases/ExecuteInstallationPlan.js'),
      import('../infrastructure/install/ProtectionInstallation.js'),
      import('../application/use-cases/ExecuteProtectionInstallation.js'),
      import('../infrastructure/install/SystemIntegrationAdapters.js'),
    ]);
    const home = this.files.realPath(this.environment.identityHome);
    const stateDir = home.join('.agentkeeper');
    const shimRoot = stateDir.join('shims');
    const resolver = new ExecutableResolver();
    const resolved = await resolver.resolveMany(
      managed.MANAGED_AGENTS,
      this.environment.variables['PATH'] ?? '',
      [shimRoot],
    );
    const agentExecutables = Object.fromEntries(
      managed.MANAGED_AGENTS.flatMap((agent) => {
        const target = resolved[agent];
        return target === undefined ? [] : [[agent, target]];
      }),
    ) as Readonly<Partial<Record<ManagedAgent, AbsolutePath>>>;
    const binaryArgument = process.argv[1];
    if (binaryArgument === undefined) {
      throw new Error('Cannot resolve the agentkeeper CLI entry point.');
    }
    const agentkeeperEntrypoint = this.files.realPath(AbsolutePath.of(resolve(binaryArgument)));
    const runtimeExecutable = this.files.realPath(AbsolutePath.of(process.execPath));
    const powershell = this.environment.platform === 'win32';
    const profiles = powershell
      ? [
          home.join('Documents/PowerShell/Microsoft.PowerShell_profile.ps1'),
          home.join('Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1'),
        ]
      : [home.join('.zshrc'), home.join('.bashrc')];
    const baseOptions = {
      home,
      stateDir,
      shell: powershell ? 'powershell' : 'posix',
      runtimeExecutable,
      agentkeeperEntrypoint,
      agentExecutables,
      profiles,
      claudeSettings: home.join('.claude/settings.json'),
    } as const;
    const processes = new system.NodeInstallationProcessExecutor();
    const git = new system.ProcessGitConfigurationController(processes);
    const service = new system.PlatformServiceController(processes, {
      ...(this.environment.platform === 'darwin' && typeof process.getuid === 'function'
        ? { launchdDomain: `gui/${process.getuid()}` }
        : {}),
    });
    const planner = new protection.ProtectionInstallationPlanner(
      this.files,
      baseOptions,
      this.environment.platform,
      service,
      git,
    );
    return {
      planner,
      executor: new protectionExecution.TransactionalProtectionInstallationExecutor(
        new fileExecution.TransactionalInstallationExecutor(this.files),
        service,
        git,
      ),
      entrypoint: agentkeeperEntrypoint,
      agents: Object.freeze(
        managed.MANAGED_AGENTS.filter((agent) => agentExecutables[agent] !== undefined),
      ),
    };
  }
}
