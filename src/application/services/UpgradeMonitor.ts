import { AGENTKEEPER_DEV_VERSION } from '../../version.js';

/**
 * Observes whether the running build predates the package installed on disk.
 *
 * The daemon's own version is a build-time constant, so it cannot notice an
 * upgrade by itself; the installed manifest is the only honest source. The
 * check is pure observation — one call, one answer — so it is driven by a
 * plain interval in the daemon and tested without timers here.
 */
export class UpgradeMonitor {
  constructor(
    private readonly runningVersion: string,
    private readonly readInstalledVersion: () => Promise<string | null>,
    private readonly onStale: (installedVersion: string) => void,
  ) {}

  /** True exactly when an upgrade was proven: a known, differing installed version. */
  async checkOnce(): Promise<boolean> {
    // A dev build reports 0.0.0-dev, which no registry version can equal;
    // without the guard every source checkout would look permanently stale.
    if (this.runningVersion === AGENTKEEPER_DEV_VERSION) return false;
    const installed = await this.readInstalledVersion();
    if (installed === null || installed === this.runningVersion) return false;
    this.onStale(installed);
    return true;
  }
}
