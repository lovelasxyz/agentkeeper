import type {
  InstallationProcessExecutor,
  ServiceController,
  ServiceRegistration,
  ServiceStatus,
} from '../../application/ports/SystemIntegration.js';
import type { Platform } from '../../domain/value-objects/Platform.js';
import { requireSuccess } from './SystemIntegrationErrors.js';

/**
 * Shared skeleton of every platform's service controller: optimistic
 * concurrency, idempotent desired-state changes and restore semantics are
 * platform-neutral. What each strategy owns is everything the OS disagrees
 * about — how a service is inspected, how a transition is applied, and how
 * long the manager needs before the new state can be trusted.
 */
export abstract class ServiceControllerBase implements ServiceController {
  abstract readonly platform: Platform;

  constructor(protected readonly processes: InstallationProcessExecutor) {}

  async inspect(registration: ServiceRegistration): Promise<ServiceStatus> {
    this.assertOwnRegistration(registration);
    return this.doInspect(registration);
  }

  async setDesired(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
    expected?: ServiceStatus,
  ): Promise<void> {
    this.assertOwnRegistration(registration);
    const current = await this.doInspect(registration);
    if (expected !== undefined && !sameStatus(current, expected)) {
      throw new Error(`Service ${registration.id} changed immediately before mutation`);
    }
    if (desired === 'active' && current.registered && current.active && current.healthy) return;
    if (desired === 'absent' && !current.registered) return;
    await this.applyDesired(registration, desired, current);
  }

  async restart(registration: ServiceRegistration, expected?: ServiceStatus): Promise<void> {
    this.assertOwnRegistration(registration);
    const current = await this.doInspect(registration);
    if (expected !== undefined && !sameStatus(current, expected)) {
      throw new Error(`Service ${registration.id} changed immediately before mutation`);
    }
    if (current.registered && current.active) {
      await this.restartActive(registration);
      return;
    }
    // The service fell out of the expected state between planning and
    // execution; bringing it up is the closest honest fulfilment of a restart.
    await this.applyDesired(registration, 'active', current);
  }

  async restore(registration: ServiceRegistration, status: ServiceStatus): Promise<void> {
    if (!status.registered) {
      await this.setDesired(registration, 'absent');
      return;
    }
    if (status.active) {
      await this.setDesired(registration, 'active');
      return;
    }

    // A registered-but-stopped state only appears as a repair precondition.
    // Recreate registration, then stop without removing its login enablement.
    await this.setDesired(registration, 'active');
    await this.stopPreservingRegistration(registration);
  }

  protected assertOwnRegistration(registration: ServiceRegistration): void {
    if (registration.platform !== this.platform) {
      throw new Error(
        `${this.constructor.name} cannot manage a ${registration.platform} registration`,
      );
    }
  }

  protected abstract doInspect(registration: ServiceRegistration): Promise<ServiceStatus>;

  protected abstract applyDesired(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
    current: ServiceStatus,
  ): Promise<void>;

  /**
   * Restarts a verified-registered, verified-active service so it picks up
   * the descriptor currently on disk. Each manager re-reads its descriptor
   * differently; that difference is exactly what the strategies own.
   */
  protected abstract restartActive(registration: ServiceRegistration): Promise<void>;

  /** Stops the service while keeping its login registration (repair path only). */
  protected abstract stopPreservingRegistration(registration: ServiceRegistration): Promise<void>;

  protected async success(executable: string, args: readonly string[]): Promise<void> {
    const result = await this.processes.execute(executable, args);
    requireSuccess(executable, args, result);
  }
}

export function absentStatus(): ServiceStatus {
  return { registered: false, active: false, healthy: false };
}

export function sameStatus(left: ServiceStatus, right: ServiceStatus): boolean {
  return (
    left.registered === right.registered &&
    left.active === right.active &&
    left.healthy === right.healthy
  );
}
