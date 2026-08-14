import type {
  InstallationProcessExecutor,
  ServiceRegistration,
  ServiceStatus,
} from '../../application/ports/SystemIntegration.js';
import type { Platform } from '../../domain/value-objects/Platform.js';
import { ServiceControllerBase, absentStatus } from './ServiceControllerBase.js';

export interface LaunchdServiceControllerOptions {
  /** Required, for example `gui/501`; supplied by composition. */
  readonly launchdDomain?: string;
  readonly launchctl?: string;
  /** How long to wait for launchd to release a booted-out identifier. */
  readonly serviceSettleTimeoutMs?: number;
  /** Injectable only to keep the settle tests fast. */
  readonly serviceSettlePollMs?: number;
}

/**
 * User-level launchd controller. Owns launchd's settle semantics: `bootout`
 * returns before the job has left the domain, so removal is only reported
 * once the identifier no longer prints.
 */
export class LaunchdServiceController extends ServiceControllerBase {
  readonly platform: Platform = 'darwin';

  private readonly launchctl: string;
  private readonly serviceSettleTimeoutMs: number;
  private readonly serviceSettlePollMs: number;

  constructor(
    processes: InstallationProcessExecutor,
    private readonly options: LaunchdServiceControllerOptions = {},
  ) {
    super(processes);
    this.launchctl = options.launchctl ?? '/bin/launchctl';
    this.serviceSettleTimeoutMs = options.serviceSettleTimeoutMs ?? 5_000;
    this.serviceSettlePollMs = options.serviceSettlePollMs ?? 100;
  }

  protected async doInspect(registration: ServiceRegistration): Promise<ServiceStatus> {
    const target = `${this.domain()}/${registration.id}`;
    const result = await this.processes.execute(this.launchctl, ['print', target]);
    if (result.exitCode !== 0) return absentStatus();
    const active = /\bstate\s*=\s*running\b/i.test(result.stdout);
    return { registered: true, active, healthy: active };
  }

  protected async applyDesired(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
    current: ServiceStatus,
  ): Promise<void> {
    const domain = this.domain();
    const target = `${domain}/${registration.id}`;
    if (desired === 'absent') {
      await this.success(this.launchctl, ['bootout', target]);
      await this.awaitRelease(registration);
      return;
    }
    if (!current.registered) {
      await this.success(this.launchctl, ['bootstrap', domain, registration.descriptorPath.value]);
      // RunAtLoad starts a newly bootstrapped job. Do not immediately kill and
      // restart it with `kickstart -k`; install should launch the watcher once.
      return;
    }
    await this.success(this.launchctl, ['kickstart', '-k', target]);
  }

  protected async stopPreservingRegistration(registration: ServiceRegistration): Promise<void> {
    await this.success(this.launchctl, [
      'kill',
      'SIGTERM',
      `${this.domain()}/${registration.id}`,
    ]);
  }

  /**
   * launchd keeps the plist it was bootstrapped with, so `kickstart -k` alone
   * would restart the *old* descriptor. A restart that must observe the file
   * on disk is a bootout — with its release wait — followed by a bootstrap.
   */
  protected async restartActive(registration: ServiceRegistration): Promise<void> {
    const domain = this.domain();
    const target = `${domain}/${registration.id}`;
    await this.success(this.launchctl, ['bootout', target]);
    await this.awaitRelease(registration);
    await this.success(this.launchctl, ['bootstrap', domain, registration.descriptorPath.value]);
  }

  /**
   * `bootout` returns before the job has actually left the domain.
   *
   * Reporting removal at that point made an `activate` following a
   * `deactivate` refuse with `service-id-collision` — and between the two the
   * machine has no watcher at all, so the failure lands at the worst moment.
   */
  private async awaitRelease(registration: ServiceRegistration): Promise<void> {
    const deadline = Date.now() + this.serviceSettleTimeoutMs;
    for (;;) {
      if (!(await this.doInspect(registration)).registered) return;
      if (Date.now() >= deadline) {
        throw new Error(
          `Service ${registration.id} is still registered ${this.serviceSettleTimeoutMs}ms after bootout`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, this.serviceSettlePollMs));
    }
  }

  private domain(): string {
    const processUid = typeof process.getuid === 'function' ? process.getuid() : null;
    const domain =
      this.options.launchdDomain ?? (processUid === null ? undefined : `gui/${processUid}`);
    if (domain === undefined || !/^gui\/[0-9]+$/.test(domain)) {
      throw new Error('A validated launchdDomain such as gui/501 is required on macOS');
    }
    return domain;
  }
}
