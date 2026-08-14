import type { FileSystem } from '../../application/ports/index.js';
import type {
  GitConfigurationController,
  GitHooksPathTransition,
  ProtectionHealth,
  ProtectionInstallationPlan,
  ServiceController,
  ServiceRegistration,
  ServiceStatus,
  ServiceTransition,
  SystemIntegrationTransition,
} from '../../application/ports/SystemIntegration.js';
import type {
  InstallationConflict,
  InstallationOperation,
  InstallationPlan,
} from '../../application/ports/InstallationLifecycle.js';
import type { Platform } from '../../domain/value-objects/Platform.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import {
  ManagedInstallationPlanner,
  type ManagedInstallationOptions,
  type ManagedOwnedArtifact,
} from './ManagedInstallation.js';

interface GitIntegrationState {
  readonly schema: 'dev.agentkeeper.git-integration';
  readonly version: 1;
  readonly originalHooksPath: string | null;
  readonly managedHooksPath: string;
}

interface PlanningSnapshot {
  readonly manifestRaw: string | null;
  readonly primaryStateRaw: string | null;
  readonly replicaStateRaw: string | null;
  readonly gitHooksPath: string | null;
  readonly service: ServiceStatus;
  /** Version the resident watcher announced; null when it never has. */
  readonly runningWatcherVersion: string | null;
}

const GIT_STATE_SCHEMA = 'dev.agentkeeper.git-integration';

/**
 * The watcher's own report of what it is running. Supplying it lets `plan`
 * turn "installed but running an older build" into a restart instead of a
 * green light; omitting it keeps planning service-state-only.
 */
export interface WatcherVersionObservation {
  readonly installedVersion: string;
  readRunningVersion(): Promise<string | null>;
}

/**
 * Adds reboot-persistent monitoring and Git entry points to ManagedInstallation.
 * All descriptor/hook bytes live in its checksum manifest; only activation of
 * those bytes crosses the ServiceController/GitConfigurationController ports.
 */
export class ProtectionInstallationPlanner {
  constructor(
    private readonly files: FileSystem,
    private readonly base: ManagedInstallationOptions,
    private readonly platform: Platform,
    private readonly services: ServiceController,
    private readonly git: GitConfigurationController,
    private readonly watcher: WatcherVersionObservation | null = null,
  ) {}

  async plan(operation: InstallationOperation): Promise<ProtectionInstallationPlan> {
    const registration = serviceRegistration(this.base, this.platform);
    const [manifestRaw, primaryStateRaw, replicaStateRaw, gitHooksPath, service, runningWatcherVersion] =
      await Promise.all([
        this.files.read(this.manifestPath),
        this.files.read(this.gitStatePath),
        this.files.read(this.gitStateReplicaPath),
        this.git.readGlobalHooksPath(),
        this.services.inspect(registration),
        this.watcher?.readRunningVersion() ?? Promise.resolve(null),
      ]);
    const snapshot: PlanningSnapshot = {
      manifestRaw,
      primaryStateRaw,
      replicaStateRaw,
      gitHooksPath,
      service,
      runningWatcherVersion,
    };
    const installed = manifestRaw !== null;

    if (!installed && operation !== 'activate') {
      const filePlan = await new ManagedInstallationPlanner(this.files, this.base).plan(operation);
      return {
        operation,
        installed: false,
        healthy: false,
        filePlan,
        externalChanges: [],
        conflicts: filePlan.conflicts,
      };
    }

    const state = installed
      ? selectGitState(primaryStateRaw, replicaStateRaw, this.managedHooksPath.value)
      : this.newGitState(gitHooksPath);
    if (state === null) {
      const conflict = this.conflict(
        'invalid-managed-state',
        this.gitStatePath,
        'Both managed Git state copies are missing, malformed, or disagree; refusing to guess the original core.hooksPath',
      );
      return this.conflictedPlan(operation, installed, conflict);
    }

    const additionalOwnedArtifacts = [
      ...(this.base.additionalOwnedArtifacts ?? []),
      ...this.protectionArtifacts(state, registration),
    ];
    const filePlan = await new ManagedInstallationPlanner(this.files, {
      ...this.base,
      additionalOwnedArtifacts,
    }).plan(operation);

    const conflicts: InstallationConflict[] = [...filePlan.conflicts];
    const gitTransition = this.gitTransition(operation, installed, state, snapshot, conflicts);
    const serviceTransition = this.serviceTransition(
      operation,
      installed,
      registration,
      snapshot,
      conflicts,
    );
    const externalChanges = orderTransitions(operation, gitTransition, serviceTransition);
    const healthy =
      installed &&
      conflicts.length === 0 &&
      filePlan.changes.length === 0 &&
      externalChanges.length === 0 &&
      snapshot.gitHooksPath === this.managedHooksPath.value &&
      snapshot.service.registered &&
      snapshot.service.active &&
      snapshot.service.healthy;

    if (conflicts.length > 0) {
      return {
        operation,
        installed,
        healthy: false,
        filePlan: { operation, changes: [], conflicts },
        externalChanges: [],
        conflicts,
      };
    }
    return {
      operation,
      installed,
      healthy,
      filePlan,
      externalChanges,
      conflicts: [],
    };
  }

  async health(): Promise<ProtectionHealth> {
    const plan = await this.plan('repair');
    return {
      installed: plan.installed,
      healthy: plan.healthy,
      conflicts: plan.conflicts,
      repairsNeeded: plan.filePlan.changes.length + plan.externalChanges.length,
    };
  }

  private get manifestPath(): AbsolutePath {
    return this.base.stateDir.join('installation/manifest.json');
  }

  private get gitStatePath(): AbsolutePath {
    return this.base.stateDir.join('installation/git-state.json');
  }

  private get gitStateReplicaPath(): AbsolutePath {
    return this.base.stateDir.join('installation/git-state.replica.json');
  }

  private get managedHooksPath(): AbsolutePath {
    return this.base.stateDir.join('git-hooks');
  }

  private newGitState(originalHooksPath: string | null): GitIntegrationState {
    return {
      schema: GIT_STATE_SCHEMA,
      version: 1,
      originalHooksPath,
      managedHooksPath: this.managedHooksPath.value,
    };
  }

  private protectionArtifacts(
    state: GitIntegrationState,
    registration: ServiceRegistration,
  ): readonly ManagedOwnedArtifact[] {
    const stateContent = `${JSON.stringify(state, null, 2)}\n`;
    const hooks = (['pre-commit', 'post-checkout', 'post-merge'] as const).map((name) => ({
      id: `protection:git-hook:${name}`,
      path: this.managedHooksPath.join(name),
      content: renderGitHook(
        name,
        this.base.runtimeExecutable,
        this.base.agentkeeperEntrypoint,
        state.originalHooksPath,
      ),
      mode: 0o700,
    }));
    return [
      {
        id: 'protection:git-state:primary',
        path: this.gitStatePath,
        content: stateContent,
        mode: 0o600,
      },
      {
        id: 'protection:git-state:replica',
        path: this.gitStateReplicaPath,
        content: stateContent,
        mode: 0o600,
      },
      ...hooks,
      {
        id: `protection:service:${this.platform}`,
        path: registration.descriptorPath,
        content: renderServiceDescriptor(this.base, this.platform),
        mode: 0o600,
      },
    ];
  }

  private gitTransition(
    operation: InstallationOperation,
    installed: boolean,
    state: GitIntegrationState,
    snapshot: PlanningSnapshot,
    conflicts: InstallationConflict[],
  ): GitHooksPathTransition | null {
    const current = snapshot.gitHooksPath;
    const managed = state.managedHooksPath;
    const original = state.originalHooksPath;

    if (!installed && current !== null && this.hooksPathPointsToManaged(current)) {
      conflicts.push(
        this.conflict(
          'external-state-drift',
          this.base.home.join('.gitconfig'),
          'core.hooksPath already points at agentkeeper without a manifest proving ownership',
        ),
      );
      return null;
    }

    const desired = operation === 'deactivate' ? original : managed;
    if (current === desired) return null;
    const safeBefore = operation === 'deactivate' ? managed : original;
    if (current !== safeBefore) {
      conflicts.push(
        this.conflict(
          'external-state-drift',
          this.base.home.join('.gitconfig'),
          `core.hooksPath changed independently to ${JSON.stringify(current)}; it will not be overwritten`,
        ),
      );
      return null;
    }
    return {
      kind: 'git-hooks-path',
      before: current,
      after: desired,
      summary:
        operation === 'deactivate'
          ? 'Restore the exact previous global core.hooksPath value'
          : 'Route global Git hooks through the checksum-managed chain directory',
    };
  }

  private hooksPathPointsToManaged(raw: string): boolean {
    try {
      const candidate =
        raw === '~'
          ? this.base.home
          : raw.startsWith('~/') || raw.startsWith('~\\')
            ? this.base.home.join(raw.slice(2))
            : AbsolutePath.of(raw);
      return candidate.equals(this.managedHooksPath);
    } catch {
      return false;
    }
  }

  private serviceTransition(
    operation: InstallationOperation,
    installed: boolean,
    registration: ServiceRegistration,
    snapshot: PlanningSnapshot,
    conflicts: InstallationConflict[],
  ): ServiceTransition | null {
    const current = snapshot.service;
    if (!installed && current.registered) {
      conflicts.push(
        this.conflict(
          'service-id-collision',
          registration.descriptorPath,
          `Service identifier ${registration.id} already exists without an agentkeeper manifest`,
        ),
      );
      return null;
    }
    if (operation === 'deactivate') {
      return current.registered
        ? {
            kind: 'service',
            registration,
            before: current,
            after: 'absent',
            summary: 'Stop and unregister the agentkeeper watcher',
          }
        : null;
    }
    if (current.registered && current.active && current.healthy) {
      if (this.watcherIsStale(snapshot)) {
        return {
          kind: 'service',
          registration,
          before: current,
          after: 'active',
          restart: true,
          summary:
            'Restart the watcher so it runs the installed version instead of the one it booted with',
        };
      }
      return null;
    }
    return {
      kind: 'service',
      registration,
      before: current,
      after: 'active',
      summary: 'Register, start, and enable the agentkeeper watcher at login',
    };
  }

  /**
   * An upgrade replaces the entrypoint on disk while the resident daemon keeps
   * executing the code it booted with. A watcher that announced a different
   * version than the installed one is running stale code behind a healthy
   * service state, so activation must restart it rather than answer "already
   * active". No announcement means there is nothing to restart from.
   */
  private watcherIsStale(snapshot: PlanningSnapshot): boolean {
    if (this.watcher === null || snapshot.runningWatcherVersion === null) return false;
    return snapshot.runningWatcherVersion !== this.watcher.installedVersion;
  }

  private conflictedPlan(
    operation: InstallationOperation,
    installed: boolean,
    conflict: InstallationConflict,
  ): ProtectionInstallationPlan {
    const filePlan: InstallationPlan = { operation, changes: [], conflicts: [conflict] };
    return {
      operation,
      installed,
      healthy: false,
      filePlan,
      externalChanges: [],
      conflicts: [conflict],
    };
  }

  private conflict(
    code: InstallationConflict['code'],
    path: AbsolutePath,
    message: string,
  ): InstallationConflict {
    return { code, path, message };
  }
}

function orderTransitions(
  operation: InstallationOperation,
  git: GitHooksPathTransition | null,
  service: ServiceTransition | null,
): readonly SystemIntegrationTransition[] {
  const ordered = operation === 'deactivate' ? [service, git] : [git, service];
  return ordered.filter((transition): transition is SystemIntegrationTransition => transition !== null);
}

function selectGitState(
  primaryRaw: string | null,
  replicaRaw: string | null,
  managedHooksPath: string,
): GitIntegrationState | null {
  const primary = parseGitState(primaryRaw, managedHooksPath);
  const replica = parseGitState(replicaRaw, managedHooksPath);
  if (primary !== null && replica !== null) {
    return sameGitState(primary, replica) ? primary : null;
  }
  return primary ?? replica;
}

function parseGitState(raw: string | null, managedHooksPath: string): GitIntegrationState | null {
  if (raw === null) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      Array.isArray(parsed) ||
      !('schema' in parsed) ||
      !('version' in parsed) ||
      !('originalHooksPath' in parsed) ||
      !('managedHooksPath' in parsed)
    ) {
      return null;
    }
    const candidate = parsed as Record<string, unknown>;
    if (
      candidate['schema'] !== GIT_STATE_SCHEMA ||
      candidate['version'] !== 1 ||
      (candidate['originalHooksPath'] !== null &&
        typeof candidate['originalHooksPath'] !== 'string') ||
      candidate['managedHooksPath'] !== managedHooksPath ||
      candidate['originalHooksPath'] === managedHooksPath
    ) {
      return null;
    }
    return {
      schema: GIT_STATE_SCHEMA,
      version: 1,
      originalHooksPath: candidate['originalHooksPath'] as string | null,
      managedHooksPath,
    };
  } catch {
    return null;
  }
}

function sameGitState(left: GitIntegrationState, right: GitIntegrationState): boolean {
  return (
    left.originalHooksPath === right.originalHooksPath &&
    left.managedHooksPath === right.managedHooksPath
  );
}

function serviceRegistration(
  options: ManagedInstallationOptions,
  platform: Platform,
): ServiceRegistration {
  switch (platform) {
    case 'darwin':
      return {
        platform,
        id: 'dev.agentkeeper.watcher',
        descriptorPath: options.home.join(
          'Library/LaunchAgents/dev.agentkeeper.watcher.plist',
        ),
      };
    case 'linux':
      return {
        platform,
        id: 'agentkeeper.service',
        descriptorPath: options.home.join('.config/systemd/user/agentkeeper.service'),
      };
    case 'win32':
      return {
        platform,
        id: 'AgentkeeperWatcher',
        descriptorPath: options.stateDir.join('services/agentkeeper-watcher.xml'),
      };
  }
}

function renderServiceDescriptor(options: ManagedInstallationOptions, platform: Platform): string {
  switch (platform) {
    case 'darwin':
      return renderLaunchdPlist(options);
    case 'linux':
      return renderSystemdUnit(options);
    case 'win32':
      return renderScheduledTask(options);
  }
}

function renderLaunchdPlist(options: ManagedInstallationOptions): string {
  const runtime = xmlEscape(options.runtimeExecutable.value);
  const entrypoint = xmlEscape(options.agentkeeperEntrypoint.value);
  const state = xmlEscape(options.stateDir.value);
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.agentkeeper.watcher</string>
  <key>ProgramArguments</key>
  <array><string>${runtime}</string><string>${entrypoint}</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>${state}/watcher.stdout.log</string>
  <key>StandardErrorPath</key><string>${state}/watcher.stderr.log</string>
</dict>
</plist>
`;
}

function renderSystemdUnit(options: ManagedInstallationOptions): string {
  return `[Unit]
Description=agentkeeper persistence watcher
After=default.target

[Service]
Type=simple
ExecStart=${systemdArgument(options.runtimeExecutable.value)} ${systemdArgument(options.agentkeeperEntrypoint.value)} daemon
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${systemdArgument(options.stateDir.value)}

[Install]
WantedBy=default.target
`;
}

function renderScheduledTask(options: ManagedInstallationOptions): string {
  const command = xmlEscape(options.runtimeExecutable.value);
  const actionArguments = xmlEscape(
    `${windowsCommandLineArgument(options.agentkeeperEntrypoint.value)} daemon`,
  );
  return `<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>${command}</Command><Arguments>${actionArguments}</Arguments></Exec></Actions>
</Task>
`;
}

type GitHookName = 'pre-commit' | 'post-checkout' | 'post-merge';

function renderGitHook(
  name: GitHookName,
  runtime: AbsolutePath,
  entrypoint: AbsolutePath,
  previousHooksPath: string | null,
): string {
  const chain =
    previousHooksPath === null
      ? [
          '_agentkeeper_git_dir=$(git rev-parse --git-dir 2>/dev/null) || _agentkeeper_git_dir=',
          `_agentkeeper_existing_hook="\${_agentkeeper_git_dir}/hooks/${name}"`,
        ]
      : [
          `_agentkeeper_previous_hooks=${posixQuote(previousHooksPath)}`,
          'case "$_agentkeeper_previous_hooks" in',
          "  '~/'*) _agentkeeper_hook_dir=\"${HOME}/${_agentkeeper_previous_hooks#~/}\" ;;",
          '  /*|[A-Za-z]:/*) _agentkeeper_hook_dir="$_agentkeeper_previous_hooks" ;;',
          '  *) _agentkeeper_hook_dir="$_agentkeeper_previous_hooks" ;;',
          'esac',
          `_agentkeeper_existing_hook="\${_agentkeeper_hook_dir}/${name}"`,
        ];
  const scan = `${posixQuote(runtime.value)} ${posixQuote(entrypoint.value)} scan --quiet --source ${posixQuote(`git-${name}`)}`;
  return [
    '#!/bin/sh',
    '# Generated and checksum-managed by agentkeeper.',
    'set -u',
    ...chain,
    'if [ -n "${_agentkeeper_existing_hook:-}" ] && [ -x "$_agentkeeper_existing_hook" ] && [ "$_agentkeeper_existing_hook" != "$0" ]; then',
    '  "$_agentkeeper_existing_hook" "$@"',
    '  _agentkeeper_chain_status=$?',
    '  [ "$_agentkeeper_chain_status" -eq 0 ] || exit "$_agentkeeper_chain_status"',
    'fi',
    name === 'pre-commit' ? `exec ${scan}` : `${scan} || true`,
    '',
  ].join('\n');
}

function posixQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function xmlEscape(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function systemdArgument(value: string): string {
  const escaped = value
    .replace(/%/g, '%%')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t');
  return `"${escaped}"`;
}

/** Quotes one argv element using the CommandLineToArgvW backslash rules. */
function windowsCommandLineArgument(value: string): string {
  return `"${value
    .replace(/(\\*)"/g, '$1$1\\"')
    .replace(/(\\+)$/g, '$1$1')}"`;
}
