import { describe, expect, it } from 'vitest';

import { UpgradeMonitor } from '../../../src/application/services/UpgradeMonitor.js';

/**
 * The daemon's periodic self-observation: the package on disk is the truth
 * about what should be running, and a daemon that predates it must hand itself
 * back to the service manager for a restart onto the new code.
 */
describe('UpgradeMonitor', () => {
  it('reports stale exactly when the installed version is known and differs', async () => {
    const stale: string[] = [];
    const monitor = new UpgradeMonitor('1.0.4', async () => '1.0.5', (installed) =>
      stale.push(installed),
    );

    expect(await monitor.checkOnce()).toBe(true);
    expect(stale).toEqual(['1.0.5']);
  });

  it('stays quiet when installed matches running', async () => {
    const stale: string[] = [];
    const monitor = new UpgradeMonitor('1.0.5', async () => '1.0.5', (installed) =>
      stale.push(installed),
    );

    expect(await monitor.checkOnce()).toBe(false);
    expect(stale).toEqual([]);
  });

  it('stays quiet when the installed version cannot be proven', async () => {
    const stale: string[] = [];
    const monitor = new UpgradeMonitor('1.0.4', async () => null, (installed) =>
      stale.push(installed),
    );

    expect(await monitor.checkOnce()).toBe(false);
    expect(stale).toEqual([]);
  });

  it('stays quiet for a dev build, which can never prove its own version', async () => {
    const stale: string[] = [];
    const monitor = new UpgradeMonitor('0.0.0-dev', async () => '1.0.5', (installed) =>
      stale.push(installed),
    );

    expect(await monitor.checkOnce()).toBe(false);
    expect(stale).toEqual([]);
  });
});
