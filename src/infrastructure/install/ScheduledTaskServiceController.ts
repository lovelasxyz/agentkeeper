import { Buffer } from 'node:buffer';
import type {
  InstallationProcessExecutor,
  ServiceRegistration,
  ServiceStatus,
} from '../../application/ports/SystemIntegration.js';
import type { Platform } from '../../domain/value-objects/Platform.js';
import { ServiceControllerBase, absentStatus } from './ServiceControllerBase.js';
import { requireSuccess } from './SystemIntegrationErrors.js';

const WINDOWS_TASK_RUNNING = 'agentkeeper-task-state:running';
const WINDOWS_TASK_STOPPED = 'agentkeeper-task-state:stopped';

export interface ScheduledTaskServiceControllerOptions {
  readonly schtasks?: string;
  readonly powershell?: string;
}

/**
 * Task Scheduler controller. State is read through a locale-neutral
 * PowerShell probe emitting one machine token, because `schtasks /FO CSV`
 * translates task status into the display language and cannot be parsed.
 */
export class ScheduledTaskServiceController extends ServiceControllerBase {
  readonly platform: Platform = 'win32';

  private readonly schtasks: string;
  private readonly powershell: string;

  constructor(
    processes: InstallationProcessExecutor,
    options: ScheduledTaskServiceControllerOptions = {},
  ) {
    super(processes);
    this.schtasks = options.schtasks ?? 'schtasks.exe';
    this.powershell = options.powershell ?? 'powershell.exe';
  }

  protected async doInspect(registration: ServiceRegistration): Promise<ServiceStatus> {
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

  protected async applyDesired(
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

  protected async stopPreservingRegistration(registration: ServiceRegistration): Promise<void> {
    await this.success(this.schtasks, ['/End', '/TN', registration.id]);
  }

  /** A running task keeps its old definition; re-create from the current XML. */
  protected async restartActive(registration: ServiceRegistration): Promise<void> {
    await this.success(this.schtasks, ['/End', '/TN', registration.id]);
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
