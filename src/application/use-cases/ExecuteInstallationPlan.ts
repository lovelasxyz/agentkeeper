import type { FileSystem } from '../ports/index.js';
import type {
  InstallationChange,
  InstallationExecutionResult,
  InstallationExecutor,
  InstallationPlan,
} from '../ports/InstallationLifecycle.js';

/** Raised before mutation when planning found something owned by the user. */
export class InstallationPlanConflictError extends Error {
  constructor(readonly plan: InstallationPlan) {
    super(
      `Installation ${plan.operation} has ${plan.conflicts.length} conflict(s): ${plan.conflicts
        .map((conflict) => `${conflict.path.value}: ${conflict.message}`)
        .join('; ')}`,
    );
    this.name = 'InstallationPlanConflictError';
  }
}

/** Raised when a planned precondition no longer matches the filesystem. */
export class InstallationConcurrentChangeError extends Error {
  constructor(readonly change: InstallationChange) {
    super(`Refusing stale installation plan; ${change.path.value} changed after planning`);
    this.name = 'InstallationConcurrentChangeError';
  }
}

/**
 * Applies the whole plan or restores every already-touched path byte-for-byte.
 *
 * The manifest is deliberately just another change, and planners put it last.
 * A process therefore cannot report an installed state after an ordinary I/O
 * failure half-way through activation.
 */
export class TransactionalInstallationExecutor implements InstallationExecutor {
  constructor(private readonly files: FileSystem) {}

  async execute(plan: InstallationPlan): Promise<InstallationExecutionResult> {
    if (plan.conflicts.length > 0) throw new InstallationPlanConflictError(plan);

    // Validate every precondition before the first write. Each one is checked
    // again immediately before mutation to close the planning/execution gap.
    for (const change of plan.changes) {
      if ((await this.files.read(change.path)) !== change.before) {
        throw new InstallationConcurrentChangeError(change);
      }
    }

    const attempted: InstallationChange[] = [];
    let appliedCount = 0;
    try {
      for (const change of plan.changes) {
        if ((await this.files.read(change.path)) !== change.before) {
          throw new InstallationConcurrentChangeError(change);
        }
        // Include the in-flight operation in rollback. The FileSystem contract
        // makes writes atomic, but this also protects alternative adapters whose
        // remove implementation mutates and then reports an I/O failure.
        attempted.push(change);
        await this.apply(change);
        appliedCount += 1;
      }
    } catch (error) {
      const rollbackErrors: unknown[] = [];
      for (const change of [...attempted].reverse()) {
        try {
          await this.restore(change);
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
      }
      if (rollbackErrors.length > 0) {
        throw new AggregateError(
          [error, ...rollbackErrors],
          'Installation transaction failed and could not be rolled back completely',
        );
      }
      throw error;
    }

    return { applied: appliedCount, dryRun: false };
  }

  private async apply(change: InstallationChange): Promise<void> {
    if (change.after === null) {
      await this.files.remove(change.path);
      return;
    }
    if (change.mode === undefined) await this.files.write(change.path, change.after);
    else await this.files.write(change.path, change.after, change.mode);
  }

  private async restore(change: InstallationChange): Promise<void> {
    if (change.before === null) {
      await this.files.remove(change.path);
      return;
    }
    // Modes of shared user files are intentionally not guessed. Managed files
    // did not exist before activation, so this branch is only for shared files
    // and transactionally replaced state such as the manifest.
    await this.files.write(change.path, change.before);
  }
}

/** Explicit test/dry-run adapter: records intent and performs zero I/O. */
export class DryRunInstallationExecutor implements InstallationExecutor {
  private readonly plans: InstallationPlan[] = [];

  get executedPlans(): readonly InstallationPlan[] {
    return this.plans;
  }

  async execute(plan: InstallationPlan): Promise<InstallationExecutionResult> {
    this.plans.push(plan);
    return { applied: 0, dryRun: true };
  }
}
