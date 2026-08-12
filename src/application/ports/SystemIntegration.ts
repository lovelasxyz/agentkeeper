import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { Platform } from '../../domain/value-objects/Platform.js';
import type {
  InstallationConflict,
  InstallationOperation,
  InstallationPlan,
} from './InstallationLifecycle.js';

export interface ServiceRegistration {
  readonly platform: Platform;
  readonly id: string;
  readonly descriptorPath: AbsolutePath;
}

export interface ServiceStatus {
  readonly registered: boolean;
  readonly active: boolean;
  readonly healthy: boolean;
}

/**
 * User-level resident activation boundary.
 *
 * Implementations may use launchctl, systemctl --user, or Task Scheduler, but
 * planning and tests never invoke those commands. `restore` is deliberately
 * explicit so an activation that partially fails can return to its exact
 * inspected state.
 */
export interface ServiceController {
  inspect(registration: ServiceRegistration): Promise<ServiceStatus>;
  setDesired(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
    expected?: ServiceStatus,
  ): Promise<void>;
  restore(registration: ServiceRegistration, status: ServiceStatus): Promise<void>;
}

/** Narrow port for the one global git setting agentkeeper owns temporarily. */
export interface GitConfigurationController {
  readGlobalHooksPath(): Promise<string | null>;
  /** `null` means remove the global key, restoring Git's default hook lookup. */
  writeGlobalHooksPath(path: string | null, expected?: string | null): Promise<void>;
}

export interface GitHooksPathTransition {
  readonly kind: 'git-hooks-path';
  readonly before: string | null;
  readonly after: string | null;
  readonly summary: string;
}

export interface ServiceTransition {
  readonly kind: 'service';
  readonly registration: ServiceRegistration;
  readonly before: ServiceStatus;
  readonly after: 'active' | 'absent';
  readonly summary: string;
}

export type SystemIntegrationTransition = GitHooksPathTransition | ServiceTransition;

export interface ProtectionInstallationPlan {
  readonly operation: InstallationOperation;
  readonly installed: boolean;
  readonly healthy: boolean;
  readonly filePlan: InstallationPlan;
  readonly externalChanges: readonly SystemIntegrationTransition[];
  readonly conflicts: readonly InstallationConflict[];
}

export interface ProtectionHealth {
  readonly installed: boolean;
  readonly healthy: boolean;
  readonly conflicts: readonly InstallationConflict[];
  readonly repairsNeeded: number;
}

export interface ProtectionInstallationExecutionResult {
  readonly filesApplied: number;
  readonly externalApplied: number;
  /**
   * Optional activation steps that were refused by the host and skipped.
   *
   * The resident watcher is an observer, never the boundary, so a machine
   * without a usable user-level service manager still gets the interception it
   * installed — degraded and named, rather than no protection at all.
   */
  readonly degraded: readonly string[];
}

export interface InstallationProcessResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

/** No-shell process boundary used by concrete Git/service controllers. */
export interface InstallationProcessExecutor {
  execute(
    executable: string,
    args: readonly string[],
  ): Promise<InstallationProcessResult>;
}
