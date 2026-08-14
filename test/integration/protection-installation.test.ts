import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import type {
  GitConfigurationController,
  ServiceController,
  ServiceRegistration,
  ServiceStatus,
} from '../../src/application/ports/SystemIntegration.js';
import { TransactionalInstallationExecutor } from '../../src/application/use-cases/ExecuteInstallationPlan.js';
import {
  ProtectionInstallationConflictError,
  SystemIntegrationConcurrentChangeError,
  TransactionalProtectionInstallationExecutor,
} from '../../src/application/use-cases/ExecuteProtectionInstallation.js';
import type {
  InstallationExecutor,
  InstallationPlan,
} from '../../src/application/ports/InstallationLifecycle.js';
import type { ManagedInstallationOptions } from '../../src/infrastructure/install/ManagedInstallation.js';
import { ProtectionInstallationPlanner } from '../../src/infrastructure/install/ProtectionInstallation.js';
import type { Platform } from '../../src/domain/value-objects/Platform.js';
import type { DaemonRuntimeStore } from '../../src/application/ports/index.js';
import { InMemoryFileSystem } from './fakes.js';

const HOME = AbsolutePath.of('/Users/dev');
const STATE = HOME.join('.agentkeeper');
const PROFILE = HOME.join('.zshrc');
const SETTINGS = HOME.join('.claude/settings.json');
const RUNTIME = AbsolutePath.of('/opt/node runtime/100%/node');
const ENTRYPOINT = AbsolutePath.of('/opt/agentkeeper app/dist/cli.js');
const MANAGED_HOOKS = STATE.join('git-hooks');

function baseOptions(): ManagedInstallationOptions {
  return {
    home: HOME,
    stateDir: STATE,
    shell: 'posix',
    runtimeExecutable: RUNTIME,
    agentkeeperEntrypoint: ENTRYPOINT,
    agentExecutables: { claude: AbsolutePath.of('/opt/agents/claude') },
    profiles: [PROFILE],
    claudeSettings: SETTINGS,
  };
}

class FakeServiceController implements ServiceController {
  status: ServiceStatus = { registered: false, active: false, healthy: false };
  readonly calls: string[] = [];
  failNextDesired: 'active' | 'absent' | null = null;

  async inspect(registration: ServiceRegistration): Promise<ServiceStatus> {
    this.calls.push(`inspect:${registration.platform}:${registration.id}`);
    return { ...this.status };
  }

  async setDesired(
    registration: ServiceRegistration,
    desired: 'active' | 'absent',
  ): Promise<void> {
    this.calls.push(`set:${registration.id}:${desired}`);
    if (this.failNextDesired === desired) {
      this.failNextDesired = null;
      throw new Error('simulated service activation failure');
    }
    this.status =
      desired === 'active'
        ? { registered: true, active: true, healthy: true }
        : { registered: false, active: false, healthy: false };
  }

  async restart(registration: ServiceRegistration): Promise<void> {
    this.calls.push(`restart:${registration.id}`);
    this.status = { registered: true, active: true, healthy: true };
  }

  async restore(registration: ServiceRegistration, status: ServiceStatus): Promise<void> {
    this.calls.push(`restore:${registration.id}`);
    this.status = { ...status };
  }
}

class FakeGitConfiguration implements GitConfigurationController {
  readonly writes: Array<string | null> = [];
  failNextWrite = false;
  failForPath: string | null | undefined = undefined;
  readCalls = 0;
  mutateOnRead: { readonly call: number; readonly value: string | null } | null = null;

  constructor(public hooksPath: string | null) {}

  async readGlobalHooksPath(): Promise<string | null> {
    this.readCalls += 1;
    if (this.mutateOnRead?.call === this.readCalls) this.hooksPath = this.mutateOnRead.value;
    return this.hooksPath;
  }

  async writeGlobalHooksPath(path: string | null): Promise<void> {
    if (this.failNextWrite) {
      this.failNextWrite = false;
      throw new Error('simulated git config failure');
    }
    if (this.failForPath !== undefined && path === this.failForPath) {
      throw new Error('simulated git rollback failure');
    }
    this.writes.push(path);
    this.hooksPath = path;
  }
}

async function fixture(
  platform: Platform = 'darwin',
  originalHooksPath: string | null = '/work/.husky',
  watcher?: { readonly installedVersion: string; readRunningVersion(): Promise<string | null> },
): Promise<{
  files: InMemoryFileSystem;
  service: FakeServiceController;
  git: FakeGitConfiguration;
  planner: ProtectionInstallationPlanner;
  executor: TransactionalProtectionInstallationExecutor;
}> {
  const files = new InMemoryFileSystem();
  await files.write(PROFILE, '# personal\n');
  await files.write(SETTINGS, '{"hooks":{"Stop":[1]}}');
  const service = new FakeServiceController();
  const git = new FakeGitConfiguration(originalHooksPath);
  const planner = new ProtectionInstallationPlanner(
    files,
    baseOptions(),
    platform,
    service,
    git,
    watcher,
  );
  const executor = new TransactionalProtectionInstallationExecutor(
    new TransactionalInstallationExecutor(files),
    service,
    git,
  );
  return { files, service, git, planner, executor };
}

describe('ProtectionInstallationPlanner', () => {
  it('installs a launchd login resident and chain-safe global git hooks once', async () => {
    const { files, service, git, planner, executor } = await fixture();
    const plan = await planner.plan('activate');

    expect(plan.conflicts).toEqual([]);
    expect(plan.externalChanges.map((change) => change.kind)).toEqual([
      'git-hooks-path',
      'service',
    ]);
    const paths = plan.filePlan.changes.map((change) => change.path.value);
    expect(paths).toContain(
      '/Users/dev/Library/LaunchAgents/dev.agentkeeper.watcher.plist',
    );
    expect(paths).toEqual(
      expect.arrayContaining([
        `${MANAGED_HOOKS.value}/pre-commit`,
        `${MANAGED_HOOKS.value}/post-checkout`,
        `${MANAGED_HOOKS.value}/post-merge`,
      ]),
    );
    const preCommit = plan.filePlan.changes.find(
      (change) => change.path.value === `${MANAGED_HOOKS.value}/pre-commit`,
    )?.after;
    expect(preCommit).toContain("_agentkeeper_previous_hooks='/work/.husky'");
    expect(preCommit).toContain('"$_agentkeeper_existing_hook" "$@"');
    expect(preCommit).toContain(
      "'/opt/node runtime/100%/node' '/opt/agentkeeper app/dist/cli.js' scan --quiet --source 'git-pre-commit'",
    );
    expect(preCommit).not.toContain('scan --quiet --source \'git-pre-commit\' || true');

    await executor.execute(plan);
    expect(git.hooksPath).toBe(MANAGED_HOOKS.value);
    expect(service.status).toEqual({ registered: true, active: true, healthy: true });
    const launchd = await files.read(
      HOME.join('Library/LaunchAgents/dev.agentkeeper.watcher.plist'),
    );
    expect(launchd).toContain('<key>RunAtLoad</key><true/>');
    expect(launchd).toContain(
      '<array><string>/opt/node runtime/100%/node</string><string>/opt/agentkeeper app/dist/cli.js</string><string>daemon</string></array>',
    );

    const second = await planner.plan('activate');
    expect(second.filePlan.changes).toEqual([]);
    expect(second.externalChanges).toEqual([]);
    expect(second.healthy).toBe(true);
    expect((await planner.health()).healthy).toBe(true);
  });

  it('deactivates the resident, restores core.hooksPath, and restores user files exactly', async () => {
    const { files, service, git, planner, executor } = await fixture();
    const profileBefore = await files.read(PROFILE);
    const settingsBefore = await files.read(SETTINGS);
    await executor.execute(await planner.plan('activate'));

    const deactivate = await planner.plan('deactivate');
    expect(deactivate.conflicts).toEqual([]);
    expect(deactivate.externalChanges.map((change) => change.kind)).toEqual([
      'service',
      'git-hooks-path',
    ]);
    await executor.execute(deactivate);

    expect(service.status.registered).toBe(false);
    expect(git.hooksPath).toBe('/work/.husky');
    expect(await files.read(MANAGED_HOOKS.join('pre-commit'))).toBeNull();
    expect(await files.read(PROFILE)).toBe(profileBefore);
    expect(await files.read(SETTINGS)).toBe(settingsBefore);
    expect((await planner.plan('deactivate')).externalChanges).toEqual([]);
  });

  it('repairs a managed hook and restarts an unhealthy resident without touching foreign hooks', async () => {
    const { files, service, git, planner, executor } = await fixture();
    await executor.execute(await planner.plan('activate'));
    const hook = MANAGED_HOOKS.join('post-merge');
    await files.write(hook, '# damaged\n');
    service.status = { registered: true, active: false, healthy: false };
    git.hooksPath = '/work/.husky';

    const repair = await planner.plan('repair');
    expect(repair.conflicts).toEqual([]);
    expect(repair.filePlan.changes.map((change) => change.path.value)).toEqual([hook.value]);
    expect(repair.externalChanges.map((change) => change.kind)).toEqual([
      'git-hooks-path',
      'service',
    ]);
    await executor.execute(repair);

    expect(await files.read(hook)).toContain("scan --quiet --source 'git-post-merge' || true");
    expect(service.status.healthy).toBe(true);
    expect(git.hooksPath).toBe(MANAGED_HOOKS.value);
    expect((await planner.health()).healthy).toBe(true);
  });

  it('repairs one damaged Git state copy from its checksum-managed replica', async () => {
    const { files, planner, executor } = await fixture();
    await executor.execute(await planner.plan('activate'));
    const primary = STATE.join('installation/git-state.json');
    const replica = STATE.join('installation/git-state.replica.json');
    const expected = await files.read(replica);
    await files.write(primary, '{ damaged');

    const repair = await planner.plan('repair');

    expect(repair.conflicts).toEqual([]);
    expect(repair.filePlan.changes.map((change) => change.path.value)).toEqual([primary.value]);
    await executor.execute(repair);
    expect(await files.read(primary)).toBe(expected);
    expect((await planner.health()).healthy).toBe(true);
  });

  it('refuses to overwrite a hooksPath changed by somebody else after activation', async () => {
    const { git, planner, executor } = await fixture();
    await executor.execute(await planner.plan('activate'));
    git.hooksPath = '/tmp/foreign-hooks';

    const repair = await planner.plan('repair');

    expect(repair.conflicts[0]?.code).toBe('external-state-drift');
    expect(repair.filePlan.changes).toEqual([]);
    await expect(executor.execute(repair)).rejects.toBeInstanceOf(
      ProtectionInstallationConflictError,
    );
    expect(git.hooksPath).toBe('/tmp/foreign-hooks');
  });

  it('installs degraded rather than not at all when the watcher cannot be activated', async () => {
    // Spec §24: a host with no usable user-level service manager still gets
    // the interception. The watcher observes; it is never the boundary, so
    // refusing to install because it will not start removes real protection
    // in exchange for none.
    const { files, service, git, planner, executor } = await fixture();
    service.failNextDesired = 'active';

    const result = await executor.execute(await planner.plan('activate'));

    expect(result.degraded).toHaveLength(1);
    expect(result.degraded[0]).toMatch(/watcher could not be activated/i);
    expect(service.status.registered).toBe(false);
    // Everything that does confine the agent is still in place.
    expect(await files.read(STATE.join('installation/manifest.json'))).not.toBeNull();
    expect(await files.read(MANAGED_HOOKS.join('post-checkout'))).not.toBeNull();
    expect(git.hooksPath).toBe(MANAGED_HOOKS.value);
  });

  it('refuses when external state changes between planning and execution', async () => {
    const { files, git, planner, executor } = await fixture();
    const plan = await planner.plan('activate');
    git.hooksPath = '/changed-after-plan';

    await expect(executor.execute(plan)).rejects.toBeInstanceOf(
      SystemIntegrationConcurrentChangeError,
    );
    expect(await files.read(STATE.join('installation/manifest.json'))).toBeNull();
    expect(git.hooksPath).toBe('/changed-after-plan');
  });

  it('rechecks external state immediately before each mutation and rolls installed files back', async () => {
    const { files, service, git, planner, executor } = await fixture();
    const plan = await planner.plan('activate');
    git.readCalls = 0;
    git.mutateOnRead = { call: 2, value: '/changed-during-file-activation' };

    await expect(executor.execute(plan)).rejects.toBeInstanceOf(
      SystemIntegrationConcurrentChangeError,
    );
    expect(git.hooksPath).toBe('/changed-during-file-activation');
    expect(service.status.registered).toBe(false);
    expect(await files.read(STATE.join('installation/manifest.json'))).toBeNull();
  });

  it('restores service and Git activation if filesystem deactivation fails', async () => {
    const { files, service, git, planner, executor } = await fixture();
    await executor.execute(await planner.plan('activate'));
    const plan = await planner.plan('deactivate');
    const failingFiles: InstallationExecutor = {
      async execute(_plan: InstallationPlan) {
        throw new Error('simulated filesystem deactivation failure');
      },
    };
    const failingExecutor = new TransactionalProtectionInstallationExecutor(
      failingFiles,
      service,
      git,
    );

    await expect(failingExecutor.execute(plan)).rejects.toThrow(
      'simulated filesystem deactivation failure',
    );
    expect(service.status).toEqual({ registered: true, active: true, healthy: true });
    expect(git.hooksPath).toBe(MANAGED_HOOKS.value);
    expect(await files.read(STATE.join('installation/manifest.json'))).not.toBeNull();
  });

  it('reports an incomplete rollback while still restoring managed files', async () => {
    const { files, git, planner, executor } = await fixture();
    const plan = await planner.plan('activate');
    // Git hook routing is part of the boundary, so its failure still aborts
    // the whole activation — unlike the watcher, which only degrades it.
    git.failNextWrite = true;
    git.failForPath = '/work/.husky';

    await expect(executor.execute(plan)).rejects.toThrow(
      'could not be rolled back completely',
    );
    expect(await files.read(STATE.join('installation/manifest.json'))).toBeNull();
  });

  it('reports a filesystem rollback failure together with the triggering failure', async () => {
    const { service, git, planner } = await fixture();
    const plan = await planner.plan('activate');
    let fileExecutions = 0;
    const rollbackFailingFiles: InstallationExecutor = {
      async execute(filePlan: InstallationPlan) {
        fileExecutions += 1;
        if (fileExecutions === 2) throw new Error('simulated filesystem rollback failure');
        return { applied: filePlan.changes.length, dryRun: false };
      },
    };
    git.failNextWrite = true;
    const executor = new TransactionalProtectionInstallationExecutor(
      rollbackFailingFiles,
      service,
      git,
    );

    await expect(executor.execute(plan)).rejects.toMatchObject({
      name: 'AggregateError',
      message: 'Protection installation failed and could not be rolled back completely',
      errors: [
        expect.objectContaining({ message: 'simulated git config failure' }),
        expect.objectContaining({ message: 'simulated filesystem rollback failure' }),
      ],
    });
    expect(fileExecutions).toBe(2);
    expect(git.hooksPath).toBe('/work/.husky');
  });

  it('refuses a pre-existing service registration when no manifest proves ownership', async () => {
    const { service, planner } = await fixture();
    service.status = { registered: true, active: false, healthy: false };

    const plan = await planner.plan('activate');

    expect(plan.conflicts[0]?.code).toBe('service-id-collision');
    expect(plan.filePlan.changes).toEqual([]);
  });

  it.each([
    '~/.agentkeeper/git-hooks',
    '/Users/dev/.agentkeeper/git-hooks/',
  ])('refuses a semantically recursive existing hooksPath: %s', async (existingPath) => {
    const { planner } = await fixture('darwin', existingPath);

    const plan = await planner.plan('activate');

    expect(plan.conflicts[0]?.code).toBe('external-state-drift');
    expect(plan.filePlan.changes).toEqual([]);
  });

  it.each([
    [
      'linux' as const,
      '/Users/dev/.config/systemd/user/agentkeeper.service',
      [
        'WantedBy=default.target',
        'ExecStart="/opt/node runtime/100%%/node" "/opt/agentkeeper app/dist/cli.js" daemon',
        'Restart=on-failure',
      ],
    ],
    [
      'win32' as const,
      '/Users/dev/.agentkeeper/services/agentkeeper-watcher.xml',
      [
        '<LogonTrigger>',
        '<RunLevel>LeastPrivilege</RunLevel>',
        '<Command>/opt/node runtime/100%/node</Command>',
        '<Arguments>&quot;/opt/agentkeeper app/dist/cli.js&quot; daemon</Arguments>',
      ],
    ],
  ])('generates a reboot/login-persistent %s descriptor', async (platform, path, fragments) => {
    const { planner } = await fixture(platform);

    const plan = await planner.plan('activate');
    const descriptor = plan.filePlan.changes.find((change) => change.path.value === path)?.after;

    expect(plan.conflicts).toEqual([]);
    for (const fragment of fragments) expect(descriptor).toContain(fragment);
  });

  it('chains repository-local default hooks when core.hooksPath was not configured', async () => {
    const { planner } = await fixture('linux', null);

    const plan = await planner.plan('activate');
    const hook = plan.filePlan.changes.find(
      (change) => change.path.value === `${MANAGED_HOOKS.value}/post-checkout`,
    )?.after;

    expect(hook).toContain('git rev-parse --git-dir');
    expect(hook).toContain('/hooks/post-checkout');
  });
});

describe('stale watcher restart (an upgrade must be sufficient on its own)', () => {
  class FakeDaemonRuntime implements DaemonRuntimeStore {
    record: { pid: number; version: string; startedAt: string } | null = null;
    async read() {
      return this.record;
    }
    async announce(record: { pid: number; version: string; startedAt: string }) {
      this.record = record;
    }
  }

  const watcherAt = (runtime: FakeDaemonRuntime, installedVersion: string) => ({
    installedVersion,
    readRunningVersion: async () => (await runtime.read())?.version ?? null,
  });

  it('plans a service restart when the running watcher predates the installed version', async () => {
    const runtime = new FakeDaemonRuntime();
    const { planner, executor } = await fixture('darwin', '/work/.husky', watcherAt(runtime, '1.0.5'));
    await executor.execute(await planner.plan('activate'));
    // The watcher is already running — but the code it runs belongs to 1.0.4.
    runtime.record = { pid: 4242, version: '1.0.4', startedAt: new Date().toISOString() };

    const plan = await planner.plan('activate');

    const serviceChange = plan.externalChanges.find((change) => change.kind === 'service');
    expect(serviceChange).toMatchObject({ after: 'active', restart: true });
    expect(plan.healthy).toBe(false);
  });

  it('restarts through the service controller when executing the plan', async () => {
    const runtime = new FakeDaemonRuntime();
    const { service, git, planner, executor } = await fixture(
      'darwin',
      '/work/.husky',
      watcherAt(runtime, '1.0.5'),
    );
    await executor.execute(await planner.plan('activate'));
    expect(service.calls).not.toContain('restart:dev.agentkeeper.watcher');

    runtime.record = { pid: 4242, version: '1.0.4', startedAt: new Date().toISOString() };
    const plan = await planner.plan('activate');
    expect(plan.healthy).toBe(false);
    await executor.execute(plan);

    expect(service.calls).toContain('restart:dev.agentkeeper.watcher');
    expect(git.writes.length).toBe(1); // activation write only; upgrade rewrites nothing
  });

  it('keeps a healthy installation untouched when the watcher runs the installed version', async () => {
    const runtime = new FakeDaemonRuntime();
    const { service, planner, executor } = await fixture(
      'darwin',
      '/work/.husky',
      watcherAt(runtime, '1.0.5'),
    );
    await executor.execute(await planner.plan('activate'));
    runtime.record = { pid: 4242, version: '1.0.5', startedAt: new Date().toISOString() };

    const plan = await planner.plan('activate');

    expect(plan.healthy).toBe(true);
    expect(plan.externalChanges).toEqual([]);
  });

  it('does not invent a restart when no watcher has ever announced itself', async () => {
    const runtime = new FakeDaemonRuntime();
    const { planner, executor } = await fixture(
      'darwin',
      '/work/.husky',
      watcherAt(runtime, '1.0.5'),
    );
    await executor.execute(await planner.plan('activate'));

    const plan = await planner.plan('activate');

    expect(plan.healthy).toBe(true);
    expect(plan.externalChanges).toEqual([]);
  });

  it('restarts on repair as well, so either command is sufficient', async () => {
    const runtime = new FakeDaemonRuntime();
    const { planner, executor } = await fixture(
      'darwin',
      '/work/.husky',
      watcherAt(runtime, '1.0.5'),
    );
    await executor.execute(await planner.plan('activate'));
    runtime.record = { pid: 4242, version: '1.0.4', startedAt: new Date().toISOString() };

    const plan = await planner.plan('repair');

    expect(plan.externalChanges.some((change) => change.kind === 'service' && change.restart === true)).toBe(true);
  });
});

/**
 * The pre-commit hook is a blocking gate on purpose: a scan that reports a
 * finding must stop the commit. But a scan that could not run at all reports
 * nothing, and turning that into a failed commit takes the developer's git
 * down with a broken install — which is how people end up deleting the guard.
 */
// The hook body is POSIX sh; Windows has no interpreter for it, and the
// managed hooks there are a different shape entirely.
const describeOnPosix = process.platform === 'win32' ? describe.skip : describe;

describeOnPosix('the pre-commit hook survives a broken install', () => {
  const roots: string[] = [];

  afterAll(() => {
    for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
  });

  /** The real generated body, for an entrypoint that may or may not exist. */
  async function preCommitBody(entrypoint: string): Promise<string> {
    const planner = new ProtectionInstallationPlanner(
      new InMemoryFileSystem(),
      {
        ...baseOptions(),
        // A real interpreter: this exercises the hook's own behaviour, not the
        // fixture's placeholder path.
        runtimeExecutable: AbsolutePath.of(process.execPath),
        agentkeeperEntrypoint: AbsolutePath.of(entrypoint),
      },
      'darwin',
      new FakeServiceController(),
      new FakeGitConfiguration(null),
    );
    const plan = await planner.plan('activate');
    const body = plan.filePlan.changes.find(
      (change) => change.path.value === `${MANAGED_HOOKS.value}/pre-commit`,
    )?.after;
    if (body === null || body === undefined) throw new Error('no pre-commit hook was planned');
    return body;
  }

  it('skips the scan and lets the commit through when the CLI is gone', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentkeeper-hook-'));
    roots.push(root);
    const hook = join(root, 'pre-commit');
    writeFileSync(hook, await preCommitBody(join(root, 'absent', 'cli.js')));
    chmodSync(hook, 0o755);

    const result = runHook(hook);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toMatch(/agentkeeper/i);
  });

  it('still blocks the commit when the scan itself refuses', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentkeeper-hook-'));
    roots.push(root);
    const refusing = join(root, 'refusing-cli.js');
    writeFileSync(refusing, 'process.exit(2);\n');
    const hook = join(root, 'pre-commit');
    writeFileSync(hook, await preCommitBody(refusing));
    chmodSync(hook, 0o755);

    expect(runHook(hook).status).toBe(2);
  });
});

function runHook(hook: string): { status: number; stderr: string } {
  const run = spawnSync('/bin/sh', [hook], { encoding: 'utf8' });
  return { status: run.status ?? 1, stderr: run.stderr ?? '' };
}
