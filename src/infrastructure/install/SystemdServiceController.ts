import type {
  InstallationProcessExecutor,
  ServiceRegistration,
  ServiceStatus,
} from '../../application/ports/SystemIntegration.js';
import type { Platform } from '../../domain/value-objects/Platform.js';
import { ServiceControllerBase } from './ServiceControllerBase.js';

export interface SystemdServiceControllerOptions {
  readonly systemctl?: string;
}

/**
 * User-level systemd controller. `systemctl` is synchronous about state
 * transitions, so unlike launchd there is nothing to settle: the answer the
 * command returns is the answer the manager holds.
 */
export class SystemdServiceController extends ServiceControllerBase {
  readonly platform: Platform = 'linux';

  private readonly systemctl: string;

  constructor(
    processes: InstallationProcessExecutor,
    options: SystemdServiceControllerOptions = {},
  ) {
    super(processes);
    this.systemctl = options.systemctl ?? 'systemctl';
  }

  protected async doInspect(registration: ServiceRegistration): Promise<ServiceStatus> {
    const [enabled, active] = await Promise.all([
      this.processes.execute(this.systemctl, ['--user', 'is-enabled', registration.id]),
      this.processes.execute(this.systemctl, ['--user', 'is-active', registration.id]),
    ]);
    const enabledState = enabled.stdout.trim();
    const isActive = active.exitCode === 0 && active.stdout.trim() === 'active';
    const registered =
      enabled.exitCode === 0 ||
      isActive ||
      ['disabled', 'indirect', 'static', 'generated', 'linked', 'masked'].includes(enabledState);
    return { registered, active: isActive, healthy: registered && isActive };
  }

  protected async applyDesired(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
  ): Promise<void> {
    await this.success(this.systemctl, ['--user', 'daemon-reload']);
    await this.success(
      this.systemctl,
      desired === 'active'
        ? ['--user', 'enable', '--now', registration.id]
        : ['--user', 'disable', '--now', registration.id],
    );
  }

  protected async stopPreservingRegistration(registration: ServiceRegistration): Promise<void> {
    await this.success(this.systemctl, ['--user', 'stop', registration.id]);
  }

  /** The unit file may have changed on disk; reload before restarting. */
  protected async restartActive(registration: ServiceRegistration): Promise<void> {
    await this.success(this.systemctl, ['--user', 'daemon-reload']);
    await this.success(this.systemctl, ['--user', 'restart', registration.id]);
  }
}
