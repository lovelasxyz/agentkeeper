import type {
  GitConfigurationController,
  GitHooksPathTransition,
  ProtectionInstallationExecutionResult,
  ProtectionInstallationPlan,
  ServiceController,
  ServiceStatus,
  ServiceTransition,
  SystemIntegrationTransition,
} from '../ports/SystemIntegration.js';
import type {
  InstallationChange,
  InstallationExecutor,
  InstallationPlan,
} from '../ports/InstallationLifecycle.js';

export class ProtectionInstallationConflictError extends Error {
  constructor(readonly plan: ProtectionInstallationPlan) {
    super(
      `Protection installation ${plan.operation} has ${plan.conflicts.length} conflict(s): ${plan.conflicts
        .map((conflict) => `${conflict.path.value}: ${conflict.message}`)
        .join('; ')}`,
    );
    this.name = 'ProtectionInstallationConflictError';
  }
}

export class SystemIntegrationConcurrentChangeError extends Error {
  constructor(readonly transition: SystemIntegrationTransition) {
    super(`Refusing stale ${transition.kind} transition; external state changed after planning`);
    this.name = 'SystemIntegrationConcurrentChangeError';
  }
}

/**
 * Coordinates checksum-managed files with reversible OS/Git activation.
 *
 * Activation and repair commit files first, then point Git at them, then start
 * the resident. Deactivation reverses that order so no service or Git command
 * can observe a descriptor/hook that has already disappeared.
 */
export class TransactionalProtectionInstallationExecutor {
  constructor(
    private readonly files: InstallationExecutor,
    private readonly services: ServiceController,
    private readonly git: GitConfigurationController,
  ) {}

  async execute(
    plan: ProtectionInstallationPlan,
  ): Promise<ProtectionInstallationExecutionResult> {
    if (plan.conflicts.length > 0) throw new ProtectionInstallationConflictError(plan);
    await this.verifyExternalPreconditions(plan.externalChanges);

    return plan.operation === 'deactivate'
      ? this.deactivate(plan)
      : this.activateOrRepair(plan);
  }

  private async activateOrRepair(
    plan: ProtectionInstallationPlan,
  ): Promise<ProtectionInstallationExecutionResult> {
    let fileResult: Awaited<ReturnType<InstallationExecutor['execute']>> | null = null;
    const attempted: SystemIntegrationTransition[] = [];
    const degraded: string[] = [];
    let applied = 0;
    try {
      fileResult = await this.files.execute(plan.filePlan);
      for (const transition of plan.externalChanges) {
        await this.verifyExternalPrecondition(transition);
        // A host with no usable user-level service manager — a container, WSL
        // without systemd, a locked-down workstation — must still end up with
        // working interception. The watcher observes; it does not confine.
        if (transition.kind === 'service') {
          try {
            attempted.push(transition);
            await this.applyExternal(transition);
            applied += 1;
          } catch (error) {
            attempted.pop();
            await this.restoreQuietly(transition);
            degraded.push(
              `the resident watcher could not be activated: ${(error as Error).message}`,
            );
          }
          continue;
        }
        attempted.push(transition);
        await this.applyExternal(transition);
        applied += 1;
      }
      return { filesApplied: fileResult.applied, externalApplied: applied, degraded };
    } catch (error) {
      const rollbackErrors = await this.rollbackExternal(attempted);
      if (fileResult !== null && plan.filePlan.changes.length > 0) {
        try {
          await this.files.execute(invertPlan(plan.filePlan));
        } catch (rollbackError) {
          rollbackErrors.push(rollbackError);
        }
      }
      throwRollbackAware(error, rollbackErrors);
    }
  }

  private async deactivate(
    plan: ProtectionInstallationPlan,
  ): Promise<ProtectionInstallationExecutionResult> {
    const attempted: SystemIntegrationTransition[] = [];
    try {
      for (const transition of plan.externalChanges) {
        await this.verifyExternalPrecondition(transition);
        attempted.push(transition);
        await this.applyExternal(transition);
      }
      const fileResult = await this.files.execute(plan.filePlan);
      return {
        filesApplied: fileResult.applied,
        externalApplied: plan.externalChanges.length,
        degraded: [],
      };
    } catch (error) {
      const rollbackErrors = await this.rollbackExternal(attempted);
      throwRollbackAware(error, rollbackErrors);
    }
  }

  /** Best effort: the transition already failed, so its rollback may too. */
  private async restoreQuietly(transition: ServiceTransition): Promise<void> {
    try {
      await this.services.restore(transition.registration, transition.before);
    } catch {
      // Nothing was activated, so there is nothing further to undo.
    }
  }

  private async verifyExternalPreconditions(
    transitions: readonly SystemIntegrationTransition[],
  ): Promise<void> {
    // These are read-only and independent. No activation begins until every
    // snapshot still matches the plan.
    const matches = await Promise.all(
      transitions.map((transition) => this.externalPreconditionMatches(transition)),
    );
    const staleIndex = matches.findIndex((matchesPlan) => !matchesPlan);
    if (staleIndex !== -1) {
      throw new SystemIntegrationConcurrentChangeError(
        transitions[staleIndex] as SystemIntegrationTransition,
      );
    }
  }

  private async verifyExternalPrecondition(
    transition: SystemIntegrationTransition,
  ): Promise<void> {
    if (!(await this.externalPreconditionMatches(transition))) {
      throw new SystemIntegrationConcurrentChangeError(transition);
    }
  }

  private async externalPreconditionMatches(
    transition: SystemIntegrationTransition,
  ): Promise<boolean> {
    if (transition.kind === 'git-hooks-path') {
      return (await this.git.readGlobalHooksPath()) === transition.before;
    }
    return sameServiceStatus(
      await this.services.inspect(transition.registration),
      transition.before,
    );
  }

  private async applyExternal(transition: SystemIntegrationTransition): Promise<void> {
    if (transition.kind === 'git-hooks-path') {
      await this.git.writeGlobalHooksPath(transition.after, transition.before);
      return;
    }
    if (transition.restart === true) {
      await this.services.restart(transition.registration, transition.before);
      return;
    }
    await this.services.setDesired(
      transition.registration,
      transition.after,
      transition.before,
    );
  }

  private async rollbackExternal(
    attempted: readonly SystemIntegrationTransition[],
  ): Promise<unknown[]> {
    const errors: unknown[] = [];
    for (const transition of [...attempted].reverse()) {
      try {
        if (transition.kind === 'git-hooks-path') {
          await this.git.writeGlobalHooksPath(transition.before);
        } else {
          await this.services.restore(transition.registration, transition.before);
        }
      } catch (error) {
        errors.push(error);
      }
    }
    return errors;
  }
}

function invertPlan(plan: InstallationPlan): InstallationPlan {
  return {
    // Only activation/repair call this inverse; their rollback is deactivation.
    operation: 'deactivate',
    changes: [...plan.changes].reverse().map(invertChange),
    conflicts: [],
  };
}

function invertChange(change: InstallationChange): InstallationChange {
  return change.mode === undefined
    ? {
        path: change.path,
        before: change.after,
        after: change.before,
        summary: `Rollback: ${change.summary}`,
      }
    : {
        path: change.path,
        before: change.after,
        after: change.before,
        summary: `Rollback: ${change.summary}`,
        mode: change.mode,
      };
}

function sameServiceStatus(left: ServiceStatus, right: ServiceStatus): boolean {
  return (
    left.registered === right.registered &&
    left.active === right.active &&
    left.healthy === right.healthy
  );
}

function throwRollbackAware(error: unknown, rollbackErrors: readonly unknown[]): never {
  if (rollbackErrors.length === 0) throw error;
  throw new AggregateError(
    [error, ...rollbackErrors],
    'Protection installation failed and could not be rolled back completely',
  );
}

// Keep the discriminated transition types reachable in generated declarations.
export type { GitHooksPathTransition, ServiceTransition };
