import { spawn } from 'node:child_process';
import { Buffer } from 'node:buffer';
import type {
  GitConfigurationController,
  InstallationProcessExecutor,
  InstallationProcessResult,
  ServiceController,
  ServiceRegistration,
  ServiceStatus,
} from '../../application/ports/SystemIntegration.js';

const MAX_CAPTURE_BYTES = 1024 * 1024;
const WINDOWS_TASK_RUNNING = 'agentkeeper-task-state:running';
const WINDOWS_TASK_STOPPED = 'agentkeeper-task-state:stopped';

export class SystemIntegrationCommandError extends Error {
  constructor(
    readonly executable: string,
    readonly args: readonly string[],
    readonly result: InstallationProcessResult,
  ) {
    super(
      `${executable} ${args.join(' ')} failed with exit ${result.exitCode}: ${result.stderr.trim()}`,
    );
    this.name = 'SystemIntegrationCommandError';
  }
}

/** Production no-shell adapter; output is bounded so a child cannot exhaust memory. */
export class NodeInstallationProcessExecutor implements InstallationProcessExecutor {
  constructor(private readonly timeoutMilliseconds = 15_000) {}

  execute(executable: string, args: readonly string[]): Promise<InstallationProcessResult> {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, [...args], {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      let stdout = '';
      let stderr = '';
      child.stdout.setEncoding('utf8');
      child.stderr.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => {
        stdout = appendBounded(stdout, chunk);
      });
      child.stderr.on('data', (chunk: string) => {
        stderr = appendBounded(stderr, chunk);
      });
      const timeout = setTimeout(() => {
        child.kill();
        reject(new Error(`${executable} timed out after ${this.timeoutMilliseconds} ms`));
      }, this.timeoutMilliseconds);
      timeout.unref();
      child.once('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
      child.once('close', (exitCode) => {
        clearTimeout(timeout);
        resolve({ exitCode: exitCode ?? 1, stdout, stderr });
      });
    });
  }
}

/** Exact global core.hooksPath reads/writes; never touches another Git key. */
export class ProcessGitConfigurationController implements GitConfigurationController {
  constructor(
    private readonly processes: InstallationProcessExecutor,
    private readonly gitExecutable = 'git',
  ) {}

  async readGlobalHooksPath(): Promise<string | null> {
    const result = await this.processes.execute(this.gitExecutable, [
      'config',
      '--global',
      '-z',
      '--get-all',
      'core.hooksPath',
    ]);
    if (result.exitCode === 1 && result.stdout.length === 0) return null;
    requireSuccess(this.gitExecutable, ['config', '--global', '-z', '--get-all', 'core.hooksPath'], result);
    const values = result.stdout.split('\0').filter((value) => value.length > 0);
    if (values.length > 1) {
      throw new Error(
        'Global core.hooksPath has multiple values; refusing to collapse them during installation',
      );
    }
    return values[0] ?? null;
  }

  async writeGlobalHooksPath(path: string | null, expected?: string | null): Promise<void> {
    const current = await this.readGlobalHooksPath();
    if (expected !== undefined && current !== expected) {
      throw new Error('Global core.hooksPath changed immediately before mutation');
    }
    if (current === path) return;
    const args =
      path === null
        ? ['config', '--global', '--unset-all', 'core.hooksPath']
        : ['config', '--global', '--replace-all', 'core.hooksPath', path];
    const result = await this.processes.execute(this.gitExecutable, args);
    // `--unset-all` returns 5 when the key was absent. The read above normally
    // makes that impossible, but treating it as idempotent closes the race.
    if (path === null && result.exitCode === 5) return;
    requireSuccess(this.gitExecutable, args, result);
  }
}

export interface PlatformServiceControllerOptions {
  /** Required on macOS, for example `gui/501`; supplied by composition. */
  readonly launchdDomain?: string;
  readonly launchctl?: string;
  readonly systemctl?: string;
  readonly schtasks?: string;
  readonly powershell?: string;
  /** How long to wait for launchd to release a booted-out identifier. */
  readonly serviceSettleTimeoutMs?: number;
  /** Injectable only to keep the settle tests fast. */
  readonly serviceSettlePollMs?: number;
}

/** User-level launchd/systemd/Task Scheduler controller with idempotent state changes. */
export class PlatformServiceController implements ServiceController {
  private readonly launchctl: string;
  private readonly systemctl: string;
  private readonly schtasks: string;
  private readonly powershell: string;
  private readonly serviceSettleTimeoutMs: number;
  private readonly serviceSettlePollMs: number;

  constructor(
    private readonly processes: InstallationProcessExecutor,
    private readonly options: PlatformServiceControllerOptions = {},
  ) {
    this.launchctl = options.launchctl ?? '/bin/launchctl';
    this.systemctl = options.systemctl ?? 'systemctl';
    this.schtasks = options.schtasks ?? 'schtasks.exe';
    this.powershell = options.powershell ?? 'powershell.exe';
    this.serviceSettleTimeoutMs = options.serviceSettleTimeoutMs ?? 5_000;
    this.serviceSettlePollMs = options.serviceSettlePollMs ?? 100;
  }

  async inspect(registration: ServiceRegistration): Promise<ServiceStatus> {
    switch (registration.platform) {
      case 'darwin':
        return this.inspectLaunchd(registration);
      case 'linux':
        return this.inspectSystemd(registration);
      case 'win32':
        return this.inspectScheduledTask(registration);
    }
  }

  async setDesired(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
    expected?: ServiceStatus,
  ): Promise<void> {
    const current = await this.inspect(registration);
    if (expected !== undefined && !sameStatus(current, expected)) {
      throw new Error(`Service ${registration.id} changed immediately before mutation`);
    }
    if (desired === 'active' && current.registered && current.active && current.healthy) return;
    if (desired === 'absent' && !current.registered) return;

    switch (registration.platform) {
      case 'darwin':
        await this.setLaunchd(registration, desired, current);
        return;
      case 'linux':
        await this.setSystemd(registration, desired);
        return;
      case 'win32':
        await this.setScheduledTask(registration, desired);
    }
  }

  async restore(registration: ServiceRegistration, status: ServiceStatus): Promise<void> {
    if (!status.registered) {
      await this.setDesired(registration, 'absent');
      return;
    }
    if (status.active) {
      await this.setDesired(registration, 'active');
      return;
    }

    // A registered-but-stopped state only appears as a repair precondition.
    // Recreate registration, then stop without removing its login enablement.
    await this.setDesired(registration, 'active');
    await this.stopPreservingRegistration(registration);
  }

  /**
   * `bootout` returns before the job has actually left the domain.
   *
   * Reporting removal at that point made an `activate` following a
   * `deactivate` refuse with `service-id-collision` — and between the two the
   * machine has no watcher at all, so the failure lands at the worst moment.
   */
  private async awaitLaunchdRelease(registration: ServiceRegistration): Promise<void> {
    const deadline = Date.now() + this.serviceSettleTimeoutMs;
    for (;;) {
      if (!(await this.inspectLaunchd(registration)).registered) return;
      if (Date.now() >= deadline) {
        throw new Error(
          `Service ${registration.id} is still registered ${this.serviceSettleTimeoutMs}ms after bootout`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, this.serviceSettlePollMs));
    }
  }

  private async inspectLaunchd(registration: ServiceRegistration): Promise<ServiceStatus> {
    const target = `${this.launchdDomain()}/${registration.id}`;
    const result = await this.processes.execute(this.launchctl, ['print', target]);
    if (result.exitCode !== 0) return absentStatus();
    const active = /\bstate\s*=\s*running\b/i.test(result.stdout);
    return { registered: true, active, healthy: active };
  }

  private async inspectSystemd(registration: ServiceRegistration): Promise<ServiceStatus> {
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

  private async inspectScheduledTask(
    registration: ServiceRegistration,
  ): Promise<ServiceStatus> {
    // `/XML` is used only as a locale-neutral existence check. Task status in
    // `/FO CSV` is translated by Windows and cannot be parsed safely.
    const query = await this.processes.execute(this.schtasks, [
      '/Query',
      '/TN',
      registration.id,
      '/XML',
    ]);
    if (query.exitCode !== 0) return absentStatus();

    // PowerShell's ScheduledTasks state is an enum: Running is numeric value
    // 4 on supported Windows releases. `-EncodedCommand` keeps the task name
    // out of command-line parsing, and the no-shell process port keeps every
    // argument separate. The script emits one invariant machine token only.
    const probeArgs = encodedPowerShellArguments(renderTaskStateProbe(registration.id));
    const probe = await this.processes.execute(this.powershell, probeArgs);
    requireSuccess(this.powershell, probeArgs, probe);
    const state = probe.stdout.trim();
    if (state !== WINDOWS_TASK_RUNNING && state !== WINDOWS_TASK_STOPPED) {
      throw new Error(
        `PowerShell returned an invalid machine-readable task state for ${registration.id}`,
      );
    }
    const active = state === WINDOWS_TASK_RUNNING;
    return { registered: true, active, healthy: active };
  }

  private async setLaunchd(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
    current: ServiceStatus,
  ): Promise<void> {
    const domain = this.launchdDomain();
    const target = `${domain}/${registration.id}`;
    if (desired === 'absent') {
      await this.success(this.launchctl, ['bootout', target]);
      await this.awaitLaunchdRelease(registration);
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

  private async setSystemd(
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

  private async setScheduledTask(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
  ): Promise<void> {
    if (desired === 'absent') {
      // `/End` can fail when the task is already stopped; deletion is the
      // authoritative transition and is checked separately.
      await this.processes.execute(this.schtasks, ['/End', '/TN', registration.id]);
      await this.success(this.schtasks, ['/Delete', '/TN', registration.id, '/F']);
      return;
    }
    await this.success(this.schtasks, [
      '/Create',
      '/TN',
      registration.id,
      '/XML',
      registration.descriptorPath.value,
      '/F',
    ]);
    await this.success(this.schtasks, ['/Run', '/TN', registration.id]);
  }

  private async stopPreservingRegistration(registration: ServiceRegistration): Promise<void> {
    switch (registration.platform) {
      case 'darwin':
        await this.success(this.launchctl, [
          'kill',
          'SIGTERM',
          `${this.launchdDomain()}/${registration.id}`,
        ]);
        return;
      case 'linux':
        await this.success(this.systemctl, ['--user', 'stop', registration.id]);
        return;
      case 'win32':
        await this.success(this.schtasks, ['/End', '/TN', registration.id]);
    }
  }

  private launchdDomain(): string {
    const processUid = typeof process.getuid === 'function' ? process.getuid() : null;
    const domain = this.options.launchdDomain ?? (processUid === null ? undefined : `gui/${processUid}`);
    if (domain === undefined || !/^gui\/[0-9]+$/.test(domain)) {
      throw new Error('A validated launchdDomain such as gui/501 is required on macOS');
    }
    return domain;
  }

  private async success(executable: string, args: readonly string[]): Promise<void> {
    const result = await this.processes.execute(executable, args);
    requireSuccess(executable, args, result);
  }
}

function requireSuccess(
  executable: string,
  args: readonly string[],
  result: InstallationProcessResult,
): void {
  if (result.exitCode !== 0) throw new SystemIntegrationCommandError(executable, args, result);
}

function absentStatus(): ServiceStatus {
  return { registered: false, active: false, healthy: false };
}

function sameStatus(left: ServiceStatus, right: ServiceStatus): boolean {
  return (
    left.registered === right.registered &&
    left.active === right.active &&
    left.healthy === right.healthy
  );
}

function appendBounded(current: string, chunk: string): string {
  if (current.length >= MAX_CAPTURE_BYTES) return current;
  return `${current}${chunk}`.slice(0, MAX_CAPTURE_BYTES);
}

function renderTaskStateProbe(taskName: string): string {
  return [
    "$ErrorActionPreference = 'Stop'",
    `$taskName = ${powerShellLiteral(taskName)}`,
    '$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop',
    'if ([int]$task.State -eq 4) {',
    `  [Console]::Out.Write('${WINDOWS_TASK_RUNNING}')`,
    '} else {',
    `  [Console]::Out.Write('${WINDOWS_TASK_STOPPED}')`,
    '}',
    '',
  ].join('\r\n');
}

function encodedPowerShellArguments(script: string): readonly string[] {
  return [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-EncodedCommand',
    Buffer.from(script, 'utf16le').toString('base64'),
  ];
}

function powerShellLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}
