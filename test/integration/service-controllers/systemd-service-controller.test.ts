import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../src/domain/value-objects/AbsolutePath.js';
import type { ServiceRegistration } from '../../../src/application/ports/SystemIntegration.js';
import { SystemdServiceController } from '../../../src/infrastructure/install/SystemdServiceController.js';
import { ScriptedProcessExecutor } from '../fakes.js';

const ok = (stdout = '') => ({ exitCode: 0, stdout, stderr: '' });

const REGISTRATION: ServiceRegistration = {
  platform: 'linux',
  id: 'agentkeeper.service',
  descriptorPath: AbsolutePath.of('/home/dev/.config/systemd/user/agentkeeper.service'),
};

/** Contract test for the systemd strategy: `systemctl` transitions are
 * synchronous, so there is no settle window — the answer returned is final. */
describe('SystemdServiceController', () => {
  it('uses systemctl --user enable --now for login persistence', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('is-enabled')) return { exitCode: 1, stdout: 'disabled\n', stderr: '' };
      if (args.includes('is-active')) return { exitCode: 3, stdout: 'inactive\n', stderr: '' };
      return ok();
    });
    const controller = new SystemdServiceController(processes);
    const before = await controller.inspect(REGISTRATION);

    await controller.setDesired(REGISTRATION, 'active', before);

    expect(processes.calls.some((call) => call.args.join(' ') === '--user daemon-reload')).toBe(
      true,
    );
    expect(
      processes.calls.some(
        (call) => call.args.join(' ') === '--user enable --now agentkeeper.service',
      ),
    ).toBe(true);
  });

  it('reads registration and activity independently and synchronously', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('is-enabled')) return ok('enabled\n');
      if (args.includes('is-active')) return ok('active\n');
      return ok();
    });

    expect(await new SystemdServiceController(processes).inspect(REGISTRATION)).toEqual({
      registered: true,
      active: true,
      healthy: true,
    });
  });

  it('treats an enabled-but-inactive unit as registered, so removal is planned', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('is-enabled')) return { exitCode: 1, stdout: 'disabled\n', stderr: '' };
      if (args.includes('is-active')) return { exitCode: 3, stdout: 'inactive\n', stderr: '' };
      return ok();
    });

    expect(await new SystemdServiceController(processes).inspect(REGISTRATION)).toEqual({
      registered: true,
      active: false,
      healthy: false,
    });
  });

  it('is idempotent when the unit is already enabled and active', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('is-enabled')) return ok('enabled\n');
      if (args.includes('is-active')) return ok('active\n');
      return ok();
    });
    const controller = new SystemdServiceController(processes);

    await controller.setDesired(REGISTRATION, 'active');

    expect(
      processes.calls.every(
        (call) => call.args.includes('is-enabled') || call.args.includes('is-active'),
      ),
    ).toBe(true);
  });

  it('restores a registered-but-stopped unit by enabling, then stopping without disabling', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('is-enabled')) return ok('enabled\n');
      if (args.includes('is-active')) return { exitCode: 3, stdout: 'inactive\n', stderr: '' };
      return ok();
    });
    await new SystemdServiceController(processes).restore(REGISTRATION, {
      registered: true,
      active: false,
      healthy: false,
    });

    const verbs = processes.calls.map((call) => call.args.join(' '));
    const enableAt = verbs.indexOf('--user enable --now agentkeeper.service');
    const stopAt = verbs.indexOf('--user stop agentkeeper.service');
    expect(enableAt).toBeGreaterThanOrEqual(0);
    expect(stopAt).toBeGreaterThan(enableAt);
    expect(verbs).not.toContain('--user disable --now agentkeeper.service');
  });

  it('refuses a registration that belongs to another platform', async () => {
    const foreign: ServiceRegistration = {
      platform: 'darwin',
      id: 'dev.agentkeeper.watcher',
      descriptorPath: AbsolutePath.of('/Users/dev/Library/LaunchAgents/x.plist'),
    };

    await expect(new SystemdServiceController(new ScriptedProcessExecutor(() => ok())).inspect(foreign)).rejects.toThrow('darwin');
  });
});

describe('SystemdServiceController restart', () => {
  it('reloads the unit from disk, then restarts it', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('is-enabled')) return ok('enabled\n');
      if (args.includes('is-active')) return ok('active\n');
      return ok();
    });

    await new SystemdServiceController(processes).restart(REGISTRATION);

    const verbs = processes.calls.map((call) => call.args.join(' '));
    expect(verbs).toContain('--user daemon-reload');
    expect(verbs).toContain('--user restart agentkeeper.service');
    expect(verbs.indexOf('--user daemon-reload')).toBeLessThan(
      verbs.indexOf('--user restart agentkeeper.service'),
    );
  });
});
