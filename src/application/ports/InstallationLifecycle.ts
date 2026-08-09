import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

export type InstallationOperation = 'activate' | 'deactivate' | 'repair';

export type InstallationConflictCode =
  | 'backup-drift'
  | 'configuration-mismatch'
  | 'concurrent-change'
  | 'external-state-drift'
  | 'invalid-manifest'
  | 'invalid-managed-state'
  | 'invalid-shared-config'
  | 'managed-file-drift'
  | 'managed-marker-collision'
  | 'owned-path-exists'
  | 'service-id-collision'
  | 'shared-file-drift';

export interface InstallationConflict {
  readonly code: InstallationConflictCode;
  readonly path: AbsolutePath;
  readonly message: string;
}

/**
 * A byte-exact, compare-before-swap filesystem mutation.
 *
 * `before` is a precondition, not merely diff context. Executors must refuse
 * the complete plan if the file changed between planning and execution.
 */
export interface InstallationChange {
  readonly path: AbsolutePath;
  readonly before: string | null;
  readonly after: string | null;
  readonly summary: string;
  readonly mode?: number;
}

export interface InstallationPlan {
  readonly operation: InstallationOperation;
  readonly changes: readonly InstallationChange[];
  readonly conflicts: readonly InstallationConflict[];
}

export interface InstallationExecutionResult {
  readonly applied: number;
  readonly dryRun: boolean;
}

/** Boundary used by the CLI: real and dry-run execution are interchangeable. */
export interface InstallationExecutor {
  execute(plan: InstallationPlan): Promise<InstallationExecutionResult>;
}
