import type {
  InstallationProcessExecutor,
  ServiceController,
  ServiceRegistration,
  ServiceStatus,
} from '../../application/ports/SystemIntegration.js';
import type { Platform } from '../../domain/value-objects/Platform.js';
import {
  LaunchdServiceController,
  type LaunchdServiceControllerOptions,
} from './LaunchdServiceController.js';
import {
  SystemdServiceController,
  type SystemdServiceControllerOptions,
} from './SystemdServiceController.js';
import {
  ScheduledTaskServiceController,
  type ScheduledTaskServiceControllerOptions,
} from './ScheduledTaskServiceController.js';

export interface PlatformServiceControllerOptions
  extends LaunchdServiceControllerOptions,
    SystemdServiceControllerOptions,
    ScheduledTaskServiceControllerOptions {}

/**
 * Routes a registration to the one strategy that owns its platform. The
 * strategies carry the platform differences; this class carries nothing but
 * the dispatch, so a change to one manager's semantics touches one file.
 */
export class PlatformServiceController implements ServiceController {
  private readonly controllers: Readonly<Record<Platform, ServiceController>>;

  constructor(
    processes: InstallationProcessExecutor,
    options: PlatformServiceControllerOptions = {},
  ) {
    this.controllers = {
      darwin: new LaunchdServiceController(processes, options),
      linux: new SystemdServiceController(processes, options),
      win32: new ScheduledTaskServiceController(processes, options),
    };
  }

  inspect(registration: ServiceRegistration): Promise<ServiceStatus> {
    return this.controllers[registration.platform].inspect(registration);
  }

  setDesired(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
    expected?: ServiceStatus,
  ): Promise<void> {
    return this.controllers[registration.platform].setDesired(registration, desired, expected);
  }

  restart(registration: ServiceRegistration, expected?: ServiceStatus): Promise<void> {
    return this.controllers[registration.platform].restart(registration, expected);
  }

  restore(registration: ServiceRegistration, status: ServiceStatus): Promise<void> {
    return this.controllers[registration.platform].restore(registration, status);
  }
}
