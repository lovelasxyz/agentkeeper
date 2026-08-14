import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../src/domain/value-objects/AbsolutePath.js';
import type { ServiceRegistration } from '../../../src/application/ports/SystemIntegration.js';
import { LaunchdServiceController } from '../../../src/infrastructure/install/LaunchdServiceController.js';
import { ScriptedProcessExecutor } from '../fakes.js';

const ok = (stdout = '') => ({ exitCode: 0, stdout, stderr: '' });
const missing = () => ({ exitCode: 1, stdout: '', stderr: '' });

const REGISTRATION: ServiceRegistration = {
  platform: 'darwin',
  id: 'dev.agentkeeper.watcher',
  descriptorPath: AbsolutePath.of('/Users/dev/Library/LaunchAgents/dev.agentkeeper.watcher.plist'),
};

const controller = (processes: ScriptedProcessExecutor, settle?: object) =>
  new LaunchdServiceController(processes, { launchdDomain: 'gui/501', ...settle });

/**
 * Contract test for the launchd strategy: bootstrap/kickstart/bootout
 * semantics plus the settle behaviour launchd alone needs — `bootout` returns
 * before the job leaves the domain.
 */
describe('LaunchdServiceController', () => {
  it('bootstraps a RunAtLoad agent once, idempotently', async () => {
    let registered = false;
    let running = false;
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args[0] === 'print') {
        return registered ? ok(`state = ${running ? 'running' : 'waiting'}\n`) : missing();
      }
      if (args[0] === 'bootstrap') {
        registered = true;
        running = true; // launchd honours RunAtLoad from the managed plist
        return ok();
      }
      if (args[0] === 'kickstart') {
        running = true;
        return ok();
      }
      return ok();
    });
    const absent = await controller(processes).inspect(REGISTRATION);

    await controller(processes).setDesired(REGISTRATION, 'active', absent);
    const callCount = processes.calls.length;
    await controller(processes).setDesired(
      REGISTRATION,
      'active',
      { registered: true, active: true, healthy: true },
    );

    expect(processes.calls.some((call) => call.args[0] === 'bootstrap')).toBe(true);
    expect(processes.calls.some((call) => call.args[0] === 'kickstart')).toBe(false);
    expect(processes.calls).toHaveLength(callCount + 1); // the idempotency inspection only
  });

  it('refuses to mutate when the manager changed since planning', async () => {
    const processes = new ScriptedProcessExecutor(() => ok('state = waiting'));
    await expect(
      controller(processes).setDesired(
        REGISTRATION,
        'active',
        { registered: true, active: true, healthy: true },
      ),
    ).rejects.toThrow('changed immediately before mutation');
  });

  it('waits for launchd to release the identifier before reporting removal', async () => {
    // `bootout` returns before the job has left the domain. Reporting success
    // immediately made an `activate` that follows a `deactivate` refuse with
    // `service-id-collision`, leaving the machine with no protection at all.
    let registered = true;
    let printsAfterBootout = 0;
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args[0] === 'print') {
        if (!registered) return missing();
        // launchd keeps reporting the job for two more polls.
        if (printsAfterBootout > 0 && ++printsAfterBootout > 3) registered = false;
        return ok('state = running');
      }
      if (args[0] === 'bootout') {
        printsAfterBootout = 1;
        return ok();
      }
      return ok();
    });

    await controller(processes, { serviceSettlePollMs: 1 }).setDesired(REGISTRATION, 'absent');

    const bootoutAt = processes.calls.findIndex((call) => call.args[0] === 'bootout');
    const pollsAfter = processes.calls
      .slice(bootoutAt + 1)
      .filter((call) => call.args[0] === 'print');
    expect(bootoutAt).toBeGreaterThanOrEqual(0);
    expect(pollsAfter.length).toBeGreaterThan(1);
    expect(registered).toBe(false);
  });

  it('reports a service that never leaves the domain instead of pretending it did', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) =>
      args[0] === 'print' ? ok('state = running') : ok(),
    );

    await expect(
      controller(processes, { serviceSettlePollMs: 1, serviceSettleTimeoutMs: 10 }).setDesired(
        REGISTRATION,
        'absent',
      ),
    ).rejects.toThrow(/still registered/i);
  });

  it('restores a registered-but-stopped job by starting it, then stopping without unregistering', async () => {
    let running = false;
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args[0] === 'print') return ok(`state = ${running ? 'running' : 'waiting'}`);
      if (args[0] === 'kickstart') running = true;
      if (args[0] === 'kill') running = false;
      return ok();
    });

    await controller(processes).restore(REGISTRATION, {
      registered: true,
      active: false,
      healthy: false,
    });

    const verbs = processes.calls.map((call) => call.args[0]);
    expect(verbs).toContain('kickstart');
    expect(verbs).toEqual(
      expect.arrayContaining(['kill']),
    );
    expect(verbs.indexOf('kickstart')).toBeLessThan(verbs.indexOf('kill'));
    expect(verbs).not.toContain('bootout');
  });

  it('refuses a registration that belongs to another platform', async () => {
    const processes = new ScriptedProcessExecutor(() => ok());
    const foreign: ServiceRegistration = {
      platform: 'linux',
      id: 'agentkeeper.service',
      descriptorPath: AbsolutePath.of('/home/dev/.config/systemd/user/agentkeeper.service'),
    };

    await expect(controller(processes).inspect(foreign)).rejects.toThrow('linux');
  });

  it('requires a validated gui/<uid> domain', async () => {
    const processes = new ScriptedProcessExecutor(() => ok());
    const broken = new LaunchdServiceController(processes, { launchdDomain: 'system' });

    await expect(broken.inspect(REGISTRATION)).rejects.toThrow('launchdDomain');
  });
});

describe('LaunchdServiceController restart', () => {
  it('re-reads a changed plist by booting out and bootstrapping again, waiting for release', async () => {
    let registered = true;
    let running = true;
    const order: string[] = [];
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args[0] === 'print') {
        order.push('print');
        return registered ? ok(`state = ${running ? 'running' : 'waiting'}`) : missing();
      }
      if (args[0] === 'bootout') {
        order.push('bootout');
        registered = false;
        running = false;
        return ok();
      }
      if (args[0] === 'bootstrap') {
        order.push('bootstrap');
        registered = true;
        running = true; // RunAtLoad
        return ok();
      }
      if (args[0] === 'kickstart') {
        order.push('kickstart');
        return ok();
      }
      return ok();
    });
    const registration = {
      platform: 'darwin' as const,
      id: 'dev.agentkeeper.watcher',
      descriptorPath: AbsolutePath.of('/Users/dev/Library/LaunchAgents/dev.agentkeeper.watcher.plist'),
    };

    // A restart must not `kickstart -k`: launchd would keep the plist it
    // already holds, and the whole point is that an upgrade replaced that file.
    await controller(processes, { serviceSettlePollMs: 1 }).restart(registration);

    expect(order).toContain('bootout');
    expect(order).toContain('bootstrap');
    expect(order.indexOf('bootout')).toBeLessThan(order.indexOf('bootstrap'));
    expect(order).not.toContain('kickstart');
    expect(registered && running).toBe(true);
  });
});
