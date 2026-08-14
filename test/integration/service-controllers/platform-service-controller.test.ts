import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../src/domain/value-objects/AbsolutePath.js';
import type { ServiceRegistration } from '../../../src/application/ports/SystemIntegration.js';
import { PlatformServiceController } from '../../../src/infrastructure/install/PlatformServiceController.js';
import { ScriptedProcessExecutor } from '../fakes.js';

const ok = (stdout = '') => ({ exitCode: 0, stdout, stderr: '' });
const missing = () => ({ exitCode: 1, stdout: '', stderr: '' });

/** The composite routes each registration to the strategy owning its
 * platform, and nothing else: the platform switch lives here exactly once. */
describe('PlatformServiceController', () => {
  it('routes a macOS registration to launchctl', async () => {
    const processes = new ScriptedProcessExecutor(() => missing());
    const registration: ServiceRegistration = {
      platform: 'darwin',
      id: 'dev.agentkeeper.watcher',
      descriptorPath: AbsolutePath.of('/Users/dev/Library/LaunchAgents/dev.agentkeeper.watcher.plist'),
    };

    await new PlatformServiceController(processes, { launchdDomain: 'gui/501' }).inspect(
      registration,
    );

    expect(processes.calls).toHaveLength(1);
    expect(processes.calls[0]?.executable).toBe('/bin/launchctl');
  });

  it('routes a Linux registration to systemctl --user', async () => {
    const processes = new ScriptedProcessExecutor(() => ok());
    const registration: ServiceRegistration = {
      platform: 'linux',
      id: 'agentkeeper.service',
      descriptorPath: AbsolutePath.of('/home/dev/.config/systemd/user/agentkeeper.service'),
    };

    await new PlatformServiceController(processes).inspect(registration);

    expect(processes.calls.every((call) => call.executable === 'systemctl')).toBe(true);
  });

  it('routes a Windows registration to schtasks', async () => {
    const processes = new ScriptedProcessExecutor(() => missing());
    const registration: ServiceRegistration = {
      platform: 'win32',
      id: 'AgentkeeperWatcher',
      descriptorPath: AbsolutePath.of('C:\\Users\\dev\\.agentkeeper\\services\\watcher.xml'),
    };

    await new PlatformServiceController(processes).inspect(registration);

    expect(processes.calls).toHaveLength(1);
    expect(processes.calls[0]?.executable).toBe('schtasks.exe');
  });

  it('passes the settle options through to the launchd strategy', async () => {
    let registered = true;
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args[0] === 'print') return registered ? ok('state = running') : missing();
      if (args[0] === 'bootout') registered = false;
      return ok();
    });
    const registration: ServiceRegistration = {
      platform: 'darwin',
      id: 'dev.agentkeeper.watcher',
      descriptorPath: AbsolutePath.of('/Users/dev/Library/LaunchAgents/dev.agentkeeper.watcher.plist'),
    };

    await new PlatformServiceController(processes, {
      launchdDomain: 'gui/501',
      serviceSettlePollMs: 1,
    }).setDesired(registration, 'absent');

    expect(processes.calls.some((call) => call.args[0] === 'bootout')).toBe(true);
  });
});
