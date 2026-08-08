import { AccessTierResolver } from '../domain/policy/AccessTierResolver.js';
import { PolicyBuilder } from '../domain/policy/PolicyBuilder.js';
import { SensitivePathRegistry } from '../domain/paths/SensitivePathRegistry.js';
import { RuleRegistry } from '../domain/rules/RuleRegistry.js';
import { ScanEngine } from '../domain/services/ScanEngine.js';
import { ARTIFACT_RULES } from '../domain/rules/artifact/index.js';
import { actionRules, blockingRules } from '../domain/rules/toolcall/index.js';
import { PERSISTENCE_RULES } from '../domain/rules/persistence/index.js';

import { NodeFileSystem } from '../infrastructure/fs/NodeFileSystem.js';
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
import { SandboxRunnerFactory } from '../infrastructure/sandbox/SandboxRunnerFactory.js';
import { Configuration } from '../infrastructure/config/Configuration.js';
import { ProfileLoader } from '../infrastructure/config/ProfileLoader.js';

import { RunSandboxed } from '../application/use-cases/RunSandboxed.js';
import { EvaluateToolCall } from '../application/use-cases/EvaluateToolCall.js';
import { ScanWorkspace } from '../application/use-cases/ScanWorkspace.js';
import { GrantAccess } from '../application/use-cases/GrantAccess.js';
import { ApplyChanges } from '../application/use-cases/ApplyChanges.js';

import type { AbsolutePath } from '../domain/value-objects/AbsolutePath.js';
import type { Artifact } from '../domain/entities/Artifact.js';
import type { BaselineChange } from '../domain/entities/BaselineChange.js';
import type { ToolCall } from '../domain/entities/ToolCall.js';
import type { Logger, Prompter, SandboxRunner } from '../application/ports/index.js';

export interface ContainerOptions {
  /** Hooks write structured JSON to stdout; a stray log line would corrupt it. */
  readonly quiet?: boolean;
  readonly interactive?: boolean;
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

    this.grants = new JsonGrantStore(this.files, this.stateDir, this.environment.home);
    this.decisions = new JsonDecisionStore(this.files, this.stateDir);
    this.baseline = new JsonBaselineStore(this.files, this.stateDir);
    this.audit = new JsonlAuditLog(this.files, this.stateDir);
  }

  get stateDir(): AbsolutePath {
    return this.environment.home.join('.agent-guard');
  }

  get backupDir(): AbsolutePath {
    return this.stateDir.join('backups');
  }

  async config(): Promise<Configuration> {
    this.configuration ??= await Configuration.load(this.files, this.stateDir);
    return this.configuration;
  }

  profiles(): ProfileLoader {
    return new ProfileLoader(this.files);
  }

  notifier(): DesktopNotifier {
    return new DesktopNotifier(this.environment.platform, this.logger);
  }

  async sandboxRunner(): Promise<SandboxRunner | null> {
    const config = await this.config();
    if (!config.sandboxEnabled) return null;
    return new SandboxRunnerFactory().forPlatform(this.environment.platform);
  }

  artifactScanner(): ScanEngine<Artifact> {
    return new ScanEngine(RuleRegistry.of(ARTIFACT_RULES));
  }

  toolCallScanner(includeActions: boolean): ScanEngine<ToolCall> {
    const rules = includeActions
      ? [...blockingRules(this.tiers), ...actionRules()]
      : blockingRules(this.tiers);
    return new ScanEngine(RuleRegistry.of(rules));
  }

  persistenceScanner(): ScanEngine<BaselineChange> {
    return new ScanEngine(RuleRegistry.of(PERSISTENCE_RULES));
  }

  async runSandboxed(): Promise<RunSandboxed> {
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
    );
  }

  async evaluateToolCall(): Promise<EvaluateToolCall> {
    const config = await this.config();
    return new EvaluateToolCall(
      this.toolCallScanner(config.isEnabled('categoryA')),
      this.decisions,
      this.audit,
      this.clock,
      config,
    );
  }

  async scanWorkspace(): Promise<ScanWorkspace> {
    return new ScanWorkspace(
      this.files,
      this.artifactScanner(),
      this.decisions,
      await this.config(),
    );
  }

  grantAccess(): GrantAccess {
    return new GrantAccess(this.grants, this.tiers, this.audit, this.clock);
  }

  applyChanges(): ApplyChanges {
    return new ApplyChanges(this.files, this.backupDir, this.audit, this.clock);
  }
}
