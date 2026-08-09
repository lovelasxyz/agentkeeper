import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import type {
  InstallationProcessExecutor,
  InstallationProcessResult,
  ServiceRegistration,
} from '../../src/application/ports/SystemIntegration.js';
import {
  PlatformServiceController,
  ProcessGitConfigurationController,
  SystemIntegrationCommandError,
} from '../../src/infrastructure/install/SystemIntegrationAdapters.js';

class ScriptedProcessExecutor implements InstallationProcessExecutor {
  readonly calls: Array<{ executable: string; args: readonly string[] }> = [];

  constructor(
    private readonly respond: (
      executable: string,
      args: readonly string[],
    ) => InstallationProcessResult,
  ) {}

  async execute(executable: string, args: readonly string[]): Promise<InstallationProcessResult> {
    this.calls.push({ executable, args });
    return this.respond(executable, args);
  }
}

const ok = (stdout = ''): InstallationProcessResult => ({ exitCode: 0, stdout, stderr: '' });
const missing = (): InstallationProcessResult => ({ exitCode: 1, stdout: '', stderr: '' });

describe('ProcessGitConfigurationController', () => {
  it('reads NUL-delimited path bytes and changes only global core.hooksPath', async () => {
    let current: string | null = '/work/.husky';
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('--get-all')) return current === null ? missing() : ok(`${current}\0`);
      if (args.includes('--replace-all')) {
        current = args.at(-1) as string;
        return ok();
      }
      if (args.includes('--unset-all')) {
        current = null;
        return ok();
      }
      return { exitCode: 2, stdout: '', stderr: 'unexpected invocation' };
    });
    const git = new ProcessGitConfigurationController(processes, '/usr/bin/git');

    expect(await git.readGlobalHooksPath()).toBe('/work/.husky');
    await git.writeGlobalHooksPath('/Users/dev/.agentkeeper/git-hooks', '/work/.husky');
    expect(current).toBe('/Users/dev/.agentkeeper/git-hooks');
    await git.writeGlobalHooksPath(null, '/Users/dev/.agentkeeper/git-hooks');
    expect(current).toBeNull();
    expect(
      processes.calls.every(
        (call) => call.executable === '/usr/bin/git' && call.args[0] === 'config',
      ),
    ).toBe(true);
    expect(processes.calls.some((call) => call.args.includes('credential.helper'))).toBe(false);
  });

  it('refuses to collapse duplicate existing values', async () => {
    const git = new ProcessGitConfigurationController(
      new ScriptedProcessExecutor(() => ok('/one\0/two\0')),
    );

    await expect(git.readGlobalHooksPath()).rejects.toThrow('multiple values');
  });
});

describe('PlatformServiceController', () => {
  it('bootstraps a RunAtLoad launchd agent once, idempotently', async () => {
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
    const controller = new PlatformServiceController(processes, {
      launchdDomain: 'gui/501',
    });
    const registration: ServiceRegistration = {
      platform: 'darwin',
      id: 'dev.agentkeeper.watcher',
      descriptorPath: AbsolutePath.of(
        '/Users/dev/Library/LaunchAgents/dev.agentkeeper.watcher.plist',
      ),
    };
    const absent = await controller.inspect(registration);

    await controller.setDesired(registration, 'active', absent);
    const callCount = processes.calls.length;
    await controller.setDesired(
      registration,
      'active',
      { registered: true, active: true, healthy: true },
    );

    expect(processes.calls.some((call) => call.args[0] === 'bootstrap')).toBe(true);
    expect(processes.calls.some((call) => call.args[0] === 'kickstart')).toBe(false);
    expect(processes.calls).toHaveLength(callCount + 1); // the idempotency inspection only
  });

  it('uses systemctl --user enable --now for login persistence', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('is-enabled')) return { exitCode: 1, stdout: 'disabled\n', stderr: '' };
      if (args.includes('is-active')) return { exitCode: 3, stdout: 'inactive\n', stderr: '' };
      return ok();
    });
    const controller = new PlatformServiceController(processes);
    const registration: ServiceRegistration = {
      platform: 'linux',
      id: 'agentkeeper.service',
      descriptorPath: AbsolutePath.of(
        '/Users/dev/.config/systemd/user/agentkeeper.service',
      ),
    };
    const before = await controller.inspect(registration);

    await controller.setDesired(registration, 'active', before);

    expect(processes.calls.some((call) => call.args.join(' ') === '--user daemon-reload')).toBe(
      true,
    );
    expect(
      processes.calls.some(
        (call) => call.args.join(' ') === '--user enable --now agentkeeper.service',
      ),
    ).toBe(true);
  });

  it('registers and immediately runs the least-privilege Windows scheduled task', async () => {
    const processes = new ScriptedProcessExecutor((_executable, args) =>
      args[0] === '/Query' ? missing() : ok(),
    );
    const controller = new PlatformServiceController(processes);
    const registration: ServiceRegistration = {
      platform: 'win32',
      id: 'AgentkeeperWatcher',
      descriptorPath: AbsolutePath.of('C:\\Users\\dev\\.agentkeeper\\services\\watcher.xml'),
    };

    await controller.setDesired(
      registration,
      'active',
      { registered: false, active: false, healthy: false },
    );

    expect(processes.calls.some((call) => call.args[0] === '/Create')).toBe(true);
    expect(processes.calls.some((call) => call.args[0] === '/Run')).toBe(true);
    expect(processes.calls.every((call) => call.executable === 'schtasks.exe')).toBe(true);
  });

  it('uses an encoded locale-neutral PowerShell probe for Windows task health', async () => {
    const hostileTaskName = "AgentkeeperWatcher'; Set-Content C:\\pwned.txt owned; #'";
    const processes = new ScriptedProcessExecutor((executable) =>
      executable === 'schtasks-safe.exe'
        ? ok('<?xml version="1.0"?><Task/>')
        : ok('agentkeeper-task-state:running'),
    );
    const controller = new PlatformServiceController(processes, {
      schtasks: 'schtasks-safe.exe',
      powershell: 'powershell-safe.exe',
    });
    const registration: ServiceRegistration = {
      platform: 'win32',
      id: hostileTaskName,
      descriptorPath: AbsolutePath.of('C:\\Users\\dev\\.agentkeeper\\services\\watcher.xml'),
    };

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

  it('distinguishes a registered-but-stopped Windows task without localized text', async () => {
    const processes = new ScriptedProcessExecutor((executable) =>
      executable === 'schtasks.exe'
        ? ok('<?xml version="1.0"?><Task/>')
        : ok('agentkeeper-task-state:stopped'),
    );
    const controller = new PlatformServiceController(processes);
    const registration: ServiceRegistration = {
      platform: 'win32',
      id: 'AgentkeeperWatcher',
      descriptorPath: AbsolutePath.of('C:\\Users\\dev\\.agentkeeper\\services\\watcher.xml'),
    };

    expect(await controller.inspect(registration)).toEqual({
      registered: true,
      active: false,
      healthy: false,
    });
  });

  it('fails closed on a failed or non-machine-readable Windows state probe', async () => {
    const registration: ServiceRegistration = {
      platform: 'win32',
      id: 'AgentkeeperWatcher',
      descriptorPath: AbsolutePath.of('C:\\Users\\dev\\.agentkeeper\\services\\watcher.xml'),
    };
    const localized = new PlatformServiceController(
      new ScriptedProcessExecutor((executable) =>
        executable === 'schtasks.exe' ? ok('<Task/>') : ok('Выполняется'),
      ),
    );
    await expect(localized.inspect(registration)).rejects.toThrow('machine-readable task state');

    const failed = new PlatformServiceController(
      new ScriptedProcessExecutor((executable) =>
        executable === 'schtasks.exe'
          ? ok('<Task/>')
          : { exitCode: 7, stdout: '', stderr: 'probe failed' },
      ),
    );
    await expect(failed.inspect(registration)).rejects.toBeInstanceOf(
      SystemIntegrationCommandError,
    );
  });

  it('does not invoke PowerShell when the Windows task is absent', async () => {
    const processes = new ScriptedProcessExecutor(() => missing());
    const controller = new PlatformServiceController(processes);
    const registration: ServiceRegistration = {
      platform: 'win32',
      id: 'AgentkeeperWatcher',
      descriptorPath: AbsolutePath.of('C:\\Users\\dev\\.agentkeeper\\services\\watcher.xml'),
    };

    expect(await controller.inspect(registration)).toEqual({
      registered: false,
      active: false,
      healthy: false,
    });
    expect(processes.calls).toHaveLength(1);
    expect(processes.calls[0]?.executable).toBe('schtasks.exe');
  });
});
