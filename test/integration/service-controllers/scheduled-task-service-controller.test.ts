import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../src/domain/value-objects/AbsolutePath.js';
import type { ServiceRegistration } from '../../../src/application/ports/SystemIntegration.js';
import { ScheduledTaskServiceController } from '../../../src/infrastructure/install/ScheduledTaskServiceController.js';
import { SystemIntegrationCommandError } from '../../../src/infrastructure/install/SystemIntegrationErrors.js';
import { ScriptedProcessExecutor } from '../fakes.js';

const ok = (stdout = '') => ({ exitCode: 0, stdout, stderr: '' });
const missing = () => ({ exitCode: 1, stdout: '', stderr: '' });

const REGISTRATION: ServiceRegistration = {
  platform: 'win32',
  id: 'AgentkeeperWatcher',
  descriptorPath: AbsolutePath.of('C:\\Users\\dev\\.agentkeeper\\services\\watcher.xml'),
};

/**
 * Contract test for the Task Scheduler strategy: a locale-neutral existence
 * check, an encoded machine-token state probe, and fail-closed parsing.
 */
describe('ScheduledTaskServiceController', () => {
  it('registers and immediately runs the least-privilege scheduled task', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) =>
      args[0] === '/Query' ? missing() : ok(),
    );

    await new ScheduledTaskServiceController(processes).setDesired(
      REGISTRATION,
      'active',
      { registered: false, active: false, healthy: false },
    );

    expect(processes.calls.some((call) => call.args[0] === '/Create')).toBe(true);
    expect(processes.calls.some((call) => call.args[0] === '/Run')).toBe(true);
    expect(processes.calls.every((call) => call.executable === 'schtasks.exe')).toBe(true);
  });

  it('uses an encoded locale-neutral PowerShell probe for task health', async () => {
    const hostileTaskName = "AgentkeeperWatcher'; Set-Content C:\\pwned.txt owned; #'";
    const processes = new ScriptedProcessExecutor((executable) =>
      executable === 'schtasks-safe.exe'
        ? ok('<?xml version="1.0"?><Task/>')
        : ok('agentkeeper-task-state:running'),
    );
    const controller = new ScheduledTaskServiceController(processes, {
      schtasks: 'schtasks-safe.exe',
      powershell: 'powershell-safe.exe',
    });
    const registration: ServiceRegistration = { ...REGISTRATION, id: hostileTaskName };

    expect(await controller.inspect(registration)).toEqual({
      registered: true,
      active: true,
      healthy: true,
    });

    const query = processes.calls[0];
    expect(query).toEqual({
      executable: 'schtasks-safe.exe',
      args: ['/Query', '/TN', hostileTaskName, '/XML'],
    });
    const probe = processes.calls[1];
    expect(probe?.executable).toBe('powershell-safe.exe');
    expect(probe?.args).toEqual([
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-EncodedCommand',
      expect.any(String),
    ]);
    expect(probe?.args.join(' ')).not.toContain(hostileTaskName);
    const encoded = probe?.args.at(-1) as string;
    const script = Buffer.from(encoded, 'base64').toString('utf16le');
    expect(script).toContain(
      "$taskName = 'AgentkeeperWatcher''; Set-Content C:\\pwned.txt owned; #'''",
    );
    expect(script).toContain('Get-ScheduledTask -TaskName $taskName -ErrorAction Stop');
    expect(script).toContain('[int]$task.State -eq 4');
  });

  it('distinguishes a registered-but-stopped task without localized text', async () => {
    const processes = new ScriptedProcessExecutor((executable) =>
      executable === 'schtasks.exe'
        ? ok('<?xml version="1.0"?><Task/>')
        : ok('agentkeeper-task-state:stopped'),
    );

    expect(await new ScheduledTaskServiceController(processes).inspect(REGISTRATION)).toEqual({
      registered: true,
      active: false,
      healthy: false,
    });
  });

  it('fails closed on a failed or non-machine-readable state probe', async () => {
    const localized = new ScheduledTaskServiceController(
      new ScriptedProcessExecutor((executable) =>
        executable === 'schtasks.exe' ? ok('<Task/>') : ok('Выполняется'),
      ),
    );
    await expect(localized.inspect(REGISTRATION)).rejects.toThrow('machine-readable task state');

    const failed = new ScheduledTaskServiceController(
      new ScriptedProcessExecutor((executable) =>
        executable === 'schtasks.exe'
          ? ok('<Task/>')
          : { exitCode: 7, stdout: '', stderr: 'probe failed' },
      ),
    );
    await expect(failed.inspect(REGISTRATION)).rejects.toBeInstanceOf(
      SystemIntegrationCommandError,
    );
  });

  it('does not invoke PowerShell when the task is absent', async () => {
    const processes = new ScriptedProcessExecutor(() => missing());

    expect(await new ScheduledTaskServiceController(processes).inspect(REGISTRATION)).toEqual({
      registered: false,
      active: false,
      healthy: false,
    });
    expect(processes.calls).toHaveLength(1);
    expect(processes.calls[0]?.executable).toBe('schtasks.exe');
  });

  it('ends a running task before deleting it, and treats deletion as authoritative', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) =>
      args[0] === '/Query' ? ok('<Task/>') : ok('agentkeeper-task-state:running'),
    );

    await new ScheduledTaskServiceController(processes).setDesired(REGISTRATION, 'absent');

    const verbs = processes.calls.map((call) => call.args[0]);
    expect(verbs.indexOf('/End')).toBeLessThan(verbs.indexOf('/Delete'));
  });

  it('refuses a registration that belongs to another platform', async () => {
    const foreign: ServiceRegistration = {
      platform: 'linux',
      id: 'agentkeeper.service',
      descriptorPath: AbsolutePath.of('/home/dev/.config/systemd/user/agentkeeper.service'),
    };

    await expect(
      new ScheduledTaskServiceController(new ScriptedProcessExecutor(() => ok())).inspect(foreign),
    ).rejects.toThrow('linux');
  });
});

describe('ScheduledTaskServiceController restart', () => {
  it('ends the running instance, re-creates from the current XML, then runs it', async () => {
    const processes = new ScriptedProcessExecutor((executable, args) => {
      if (executable === 'schtasks.exe' && args[0] === '/Query') return ok('<Task/>');
      if (executable === 'schtasks.exe') return ok();
      return ok('agentkeeper-task-state:running');
    });

    await new ScheduledTaskServiceController(processes).restart(REGISTRATION);

    const verbs = processes.calls.map((call) => call.args[0]);
    expect(verbs.indexOf('/End')).toBeLessThan(verbs.indexOf('/Create'));
    expect(verbs.indexOf('/Create')).toBeLessThan(verbs.indexOf('/Run'));
  });
});
