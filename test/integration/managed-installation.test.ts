import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import {
  DryRunInstallationExecutor,
  InstallationConcurrentChangeError,
  InstallationPlanConflictError,
  TransactionalInstallationExecutor,
} from '../../src/application/use-cases/ExecuteInstallationPlan.js';
import {
  ManagedInstallationPlanner,
  type ManagedInstallationOptions,
} from '../../src/infrastructure/install/ManagedInstallation.js';
import { InMemoryFileSystem } from './fakes.js';

const HOME = AbsolutePath.of('/Users/dev');
const STATE = HOME.join('.agentkeeper');
const MANIFEST = STATE.join('installation/manifest.json');
const CLAUDE_SETTINGS = HOME.join('.claude/settings.json');
const POSIX_PROFILE = HOME.join('.zshrc');
const POWERSHELL_PROFILE = HOME.join('Documents/PowerShell/Microsoft.PowerShell_profile.ps1');
const RUNTIME = AbsolutePath.of('/opt/node runtime/bin/node');
const ENTRYPOINT = AbsolutePath.of('/opt/agentkeeper/dist/cli.js');
const AGENTS = ['claude', 'codex', 'gemini', 'opencode'] as const;

const TARGETS = {
  claude: AbsolutePath.of('/opt/agents/claude'),
  codex: AbsolutePath.of('/opt/agents/codex'),
  gemini: AbsolutePath.of('/opt/agents/gemini'),
  opencode: AbsolutePath.of('/opt/agents/opencode'),
} as const;

function options(
  shell: 'posix' | 'powershell' = 'posix',
): ManagedInstallationOptions {
  return {
    home: HOME,
    stateDir: STATE,
    shell,
    runtimeExecutable: RUNTIME,
    agentkeeperEntrypoint: ENTRYPOINT,
    agentExecutables: TARGETS,
    profiles: [shell === 'posix' ? POSIX_PROFILE : POWERSHELL_PROFILE],
    claudeSettings: CLAUDE_SETTINGS,
  };
}

function planner(
  files: InMemoryFileSystem,
  shell: 'posix' | 'powershell' = 'posix',
): ManagedInstallationPlanner {
  return new ManagedInstallationPlanner(files, options(shell));
}

describe('ManagedInstallationPlanner', () => {
  it('activates transparent shims and merges one Claude hook without replacing existing hooks', async () => {
    const files = new InMemoryFileSystem();
    const profileBefore = '# personal profile\nexport EDITOR=vim\n';
    const settingsBefore =
      '{\n  "model": "opus",\n  "hooks": {\n    "PreToolUse": [{"matcher":"Bash","hooks":[{"type":"command","command":"mine"}]}],\n    "Stop": [1]\n  }\n}\n';
    await files.write(POSIX_PROFILE, profileBefore);
    await files.write(CLAUDE_SETTINGS, settingsBefore);

    const plan = await planner(files).plan('activate');
    expect(plan.conflicts).toEqual([]);
    await new TransactionalInstallationExecutor(files).execute(plan);

    for (const agent of AGENTS) {
      const shim = await files.read(STATE.join(`shims/posix/${agent}`));
      expect(shim).toContain(
        `exec '/opt/node runtime/bin/node' '/opt/agentkeeper/dist/cli.js' run -- '/opt/agents/${agent}' "$@"`,
      );
      expect(shim).not.toContain('AGENTKEEPER_BYPASS');
    }

    const profileAfter = await files.read(POSIX_PROFILE);
    expect(profileAfter).toContain(profileBefore);
    expect(profileAfter?.match(/>>> agentkeeper managed >>>/g)).toHaveLength(1);
    expect(profileAfter).toContain(". '/Users/dev/.agentkeeper/shell/agentkeeper.sh'");

    const installedSettingsBytes = (await files.read(CLAUDE_SETTINGS)) as string;
    expect(installedSettingsBytes).toContain(
      '{"matcher":"Bash","hooks":[{"type":"command","command":"mine"}]}',
    );
    const settingsAfter = JSON.parse(installedSettingsBytes) as {
      model: string;
      hooks: { PreToolUse: unknown[]; Stop: unknown[] };
    };
    expect(settingsAfter.model).toBe('opus');
    expect(settingsAfter.hooks.Stop).toEqual([1]);
    expect(settingsAfter.hooks.PreToolUse[0]).toEqual({
      matcher: 'Bash',
      hooks: [{ type: 'command', command: 'mine' }],
    });
    expect(settingsAfter.hooks.PreToolUse).toHaveLength(2);
    expect(JSON.stringify(settingsAfter.hooks.PreToolUse[1])).toContain(
      "'/opt/node runtime/bin/node' '/opt/agentkeeper/dist/cli.js' hook pretooluse",
    );

    const manifest = JSON.parse((await files.read(MANIFEST)) as string) as {
      checksum: string;
      payload: {
        version: number;
        runtimeExecutable: string;
        agentkeeperEntrypoint: string;
        entries: Array<{ installedChecksum: string; originalChecksum: string | null }>;
      };
    };
    expect(manifest.checksum).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(manifest.payload).toMatchObject({
      version: 2,
      runtimeExecutable: '/opt/node runtime/bin/node',
      agentkeeperEntrypoint: '/opt/agentkeeper/dist/cli.js',
    });
    expect(manifest.payload.entries.length).toBeGreaterThan(AGENTS.length);
    expect(manifest.payload.entries.every((entry) => entry.installedChecksum.startsWith('sha256:'))).toBe(true);
    expect(manifest.payload.entries.some((entry) => entry.originalChecksum !== null)).toBe(true);
  });

  it('is idempotent and restores shared files byte-exact on clean deactivation', async () => {
    const files = new InMemoryFileSystem();
    const profileBefore = '# no final newline';
    const settingsBefore = '{ "hooks" : { "Stop" : [ {"custom":true} ] }, "theme":"dark" }';
    await files.write(POSIX_PROFILE, profileBefore);
    await files.write(CLAUDE_SETTINGS, settingsBefore);
    const managed = planner(files);
    const executor = new TransactionalInstallationExecutor(files);

    await executor.execute(await managed.plan('activate'));
    expect((await managed.plan('activate')).changes).toEqual([]);

    const deactivate = await managed.plan('deactivate');
    expect(deactivate.conflicts).toEqual([]);
    await executor.execute(deactivate);

    expect(await files.read(POSIX_PROFILE)).toBe(profileBefore);
    expect(await files.read(CLAUDE_SETTINGS)).toBe(settingsBefore);
    expect(await files.read(STATE.join('shims/posix/claude'))).toBeNull();
    expect(await files.read(MANIFEST)).toBeNull();
    expect((await managed.plan('deactivate')).changes).toEqual([]);
  });

  it('repairs owned shim drift but refuses to overwrite drifted user settings', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POSIX_PROFILE, '# user\n');
    await files.write(CLAUDE_SETTINGS, '{"hooks":{"Stop":[1]}}');
    const managed = planner(files);
    const executor = new TransactionalInstallationExecutor(files);
    await executor.execute(await managed.plan('activate'));

    const shimPath = STATE.join('shims/posix/claude');
    await files.write(shimPath, '# hijacked\n');
    const repairShim = await managed.plan('repair');
    expect(repairShim.conflicts).toEqual([]);
    expect(repairShim.changes.map((change) => change.path.value)).toContain(shimPath.value);
    await executor.execute(repairShim);
    expect(await files.read(shimPath)).toContain("dist/cli.js' run --");
    expect((await managed.plan('repair')).changes).toEqual([]);

    const userEdit = '{"hooks":{"Stop":[1]},"addedWhileInstalled":true}';
    await files.write(CLAUDE_SETTINGS, userEdit);
    const repairSettings = await managed.plan('repair');
    expect(repairSettings.changes).toEqual([]);
    expect(repairSettings.conflicts[0]?.code).toBe('shared-file-drift');
    await expect(executor.execute(repairSettings)).rejects.toBeInstanceOf(
      InstallationPlanConflictError,
    );
    expect(await files.read(CLAUDE_SETTINGS)).toBe(userEdit);

    const deactivate = await managed.plan('deactivate');
    expect(deactivate.conflicts[0]?.code).toBe('shared-file-drift');
    expect(deactivate.changes).toEqual([]);
  });

  it('never claims pre-existing managed paths or malformed/foreign Claude configuration', async () => {
    const files = new InMemoryFileSystem();
    const foreignShim = '# foreign wrapper\n';
    await files.write(STATE.join('shims/posix/claude'), foreignShim);
    await files.write(POSIX_PROFILE, '# >>> agentkeeper managed >>>\nforeign\n');
    await files.write(CLAUDE_SETTINGS, '{ broken');

    const plan = await planner(files).plan('activate');
    expect(plan.changes).toEqual([]);
    expect(plan.conflicts.map((conflict) => conflict.code)).toEqual(
      expect.arrayContaining(['owned-path-exists', 'managed-marker-collision', 'invalid-shared-config']),
    );
    expect(await files.read(STATE.join('shims/posix/claude'))).toBe(foreignShim);
    expect(await files.read(CLAUDE_SETTINGS)).toBe('{ broken');
  });

  it('rejects a tampered manifest instead of trusting paths or checksums from it', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POSIX_PROFILE, '# user\n');
    await files.write(CLAUDE_SETTINGS, '{}');
    const managed = planner(files);
    await new TransactionalInstallationExecutor(files).execute(await managed.plan('activate'));

    const envelope = JSON.parse((await files.read(MANIFEST)) as string) as {
      checksum: string;
      payload: { entries: Array<{ path: string }> };
    };
    envelope.payload.entries[0]!.path = '/Users/dev/.ssh/config';
    await files.write(MANIFEST, `${JSON.stringify(envelope)}\n`);

    for (const operation of ['activate', 'repair', 'deactivate'] as const) {
      const plan = await managed.plan(operation);
      expect(plan.changes).toEqual([]);
      expect(plan.conflicts[0]?.code).toBe('invalid-manifest');
    }
    expect(await files.read(AbsolutePath.of('/Users/dev/.ssh/config'))).toBeNull();
  });

  it('generates PowerShell shims and a one-time profile snippet for every supported agent', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POWERSHELL_PROFILE, '# my PowerShell profile\r\n');
    await files.write(CLAUDE_SETTINGS, '{}');

    const plan = await planner(files, 'powershell').plan('activate');
    expect(plan.conflicts).toEqual([]);
    await new TransactionalInstallationExecutor(files).execute(plan);

    for (const agent of AGENTS) {
      const shim = await files.read(STATE.join(`shims/powershell/${agent}.ps1`));
      expect(shim).toContain(`run -- '/opt/agents/${agent}' @args`);
      expect(shim).toContain(
        "& '/opt/node runtime/bin/node' '/opt/agentkeeper/dist/cli.js' run --",
      );
      expect(shim).toContain('exit $LASTEXITCODE');
      expect(shim).not.toContain('AGENTKEEPER_BYPASS');

      const commandShim = await files.read(STATE.join(`shims/powershell/${agent}.cmd`));
      expect(commandShim).toContain(`"/opt/agents/${agent}" %*`);
      expect(commandShim).toContain(
        '"/opt/node runtime/bin/node" "/opt/agentkeeper/dist/cli.js" run --',
      );
      expect(commandShim).toContain('setlocal DisableDelayedExpansion');
      expect(commandShim).not.toContain('AGENTKEEPER_BYPASS');
    }
    const init = await files.read(STATE.join('shell/agentkeeper.ps1'));
    expect(init).toContain("$env:PATH");
    const profile = await files.read(POWERSHELL_PROFILE);
    expect(profile).toContain(". '/Users/dev/.agentkeeper/shell/agentkeeper.ps1'");
    expect(profile?.match(/>>> agentkeeper managed >>>/g)).toHaveLength(1);
  });

  it('activates only the agent CLIs that are actually installed', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POSIX_PROFILE, '# user\n');
    await files.write(CLAUDE_SETTINGS, '{}');
    const partial: ManagedInstallationOptions = {
      ...options(),
      agentExecutables: { codex: TARGETS.codex },
    };

    const plan = await new ManagedInstallationPlanner(files, partial).plan('activate');
    expect(plan.conflicts).toEqual([]);
    await new TransactionalInstallationExecutor(files).execute(plan);

    expect(await files.read(STATE.join('shims/posix/codex'))).toContain(
      "dist/cli.js' run -- '/opt/agents/codex'",
    );
    expect(await files.read(STATE.join('shims/posix/claude'))).toBeNull();
    expect(await files.read(STATE.join('shims/posix/gemini'))).toBeNull();
    expect(await files.read(STATE.join('shims/posix/opencode'))).toBeNull();
  });

  it('can deactivate safely after the intercepted agent executable was removed', async () => {
    const files = new InMemoryFileSystem();
    const profileBefore = '# user\n';
    const settingsBefore = '{}';
    await files.write(POSIX_PROFILE, profileBefore);
    await files.write(CLAUDE_SETTINGS, settingsBefore);
    await new TransactionalInstallationExecutor(files).execute(
      await planner(files).plan('activate'),
    );

    const withoutAgents = new ManagedInstallationPlanner(files, {
      ...options(),
      agentExecutables: {},
    });
    const deactivate = await withoutAgents.plan('deactivate');
    expect(deactivate.conflicts).toEqual([]);
    await new TransactionalInstallationExecutor(files).execute(deactivate);

    expect(await files.read(POSIX_PROFILE)).toBe(profileBefore);
    expect(await files.read(CLAUDE_SETTINGS)).toBe(settingsBefore);
    expect(await files.read(MANIFEST)).toBeNull();
  });

  it('renders the PowerShell lifecycle with real Windows drive paths and spaces', async () => {
    const files = new InMemoryFileSystem();
    const windowsHome = AbsolutePath.of('C:\\Users\\Dev');
    const windowsState = windowsHome.join('.agentkeeper');
    const windowsProfile = windowsHome.join(
      'Documents/PowerShell/Microsoft.PowerShell_profile.ps1',
    );
    const windowsSettings = windowsHome.join('.claude/settings.json');
    files.files.set(windowsProfile.value, '# user\r\n');
    files.files.set(windowsSettings.value, '{}');
    const windowsTargets = Object.fromEntries(
      AGENTS.map((agent) => [
        agent,
        AbsolutePath.of(`C:\\Program Files\\Agents\\${agent}.exe`),
      ]),
    ) as Readonly<Record<(typeof AGENTS)[number], AbsolutePath>>;

    const plan = await new ManagedInstallationPlanner(files, {
      home: windowsHome,
      stateDir: windowsState,
      shell: 'powershell',
      runtimeExecutable: AbsolutePath.of(
        'C:\\Program Files\\Node 100%\\node.exe',
      ),
      agentkeeperEntrypoint: AbsolutePath.of(
        'C:\\Program Files\\Agentkeeper!\\dist\\cli.js',
      ),
      agentExecutables: windowsTargets,
      profiles: [windowsProfile],
      claudeSettings: windowsSettings,
    }).plan('activate');

    expect(plan.conflicts).toEqual([]);
    const powerShellShim = plan.changes.find(
      (change) => change.path.value === windowsState.join('shims/powershell/claude.ps1').value,
    )?.after;
    expect(powerShellShim).toContain("run -- 'C:/program files/agents/claude.exe' @args");
    expect(powerShellShim).toContain(
      "& 'C:/program files/node 100%/node.exe' 'C:/program files/agentkeeper!/dist/cli.js' run --",
    );
    const commandShim = plan.changes.find(
      (change) => change.path.value === windowsState.join('shims/powershell/claude.cmd').value,
    )?.after;
    expect(commandShim).toContain('setlocal DisableDelayedExpansion');
    expect(commandShim).toContain(
      '"C:/program files/node 100%%/node.exe" "C:/program files/agentkeeper!/dist/cli.js" run --',
    );
    expect(commandShim).toContain('"C:/program files/agents/claude.exe" %*');
    const profile = plan.changes.find((change) => change.path.equals(windowsProfile))?.after;
    expect(profile).toContain(
      ". 'C:/users/dev/.agentkeeper/shell/agentkeeper.ps1'",
    );
    const settings = plan.changes.find((change) => change.path.equals(windowsSettings))?.after;
    expect(settings).toContain(
      "& 'C:/program files/node 100%/node.exe' 'C:/program files/agentkeeper!/dist/cli.js' hook pretooluse",
    );
  });

  it('binds the trusted runtime and CLI entrypoint into the manifest configuration contract', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POSIX_PROFILE, '# user\n');
    await files.write(CLAUDE_SETTINGS, '{}');
    const executor = new TransactionalInstallationExecutor(files);
    await executor.execute(await planner(files).plan('activate'));

    for (const changed of [
      { runtimeExecutable: AbsolutePath.of('/different/node') },
      { agentkeeperEntrypoint: AbsolutePath.of('/different/cli.js') },
    ]) {
      const repair = await new ManagedInstallationPlanner(files, {
        ...options(),
        ...changed,
      }).plan('repair');
      expect(repair.changes).toEqual([]);
      expect(repair.conflicts[0]?.code).toBe('configuration-mismatch');
    }
  });

  it('rejects executable resolution that would recurse through its own shim directory', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POSIX_PROFILE, '# user\n');
    await files.write(CLAUDE_SETTINGS, '{}');
    const recursiveOptions: ManagedInstallationOptions = {
      ...options(),
      agentExecutables: {
        ...TARGETS,
        claude: STATE.join('shims/posix/claude'),
      },
    };

    const plan = await new ManagedInstallationPlanner(files, recursiveOptions).plan('activate');

    expect(plan.changes).toEqual([]);
    expect(plan.conflicts[0]?.code).toBe('configuration-mismatch');
  });

  it('never lets inherited sandbox environment select a direct-exec bypass path', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POSIX_PROFILE, '# user\n');
    await files.write(CLAUDE_SETTINGS, '{}');

    const plan = await planner(files).plan('activate');
    const shims = plan.changes.filter((change) => change.path.value.includes('/shims/'));

    expect(shims).toHaveLength(AGENTS.length);
    for (const shim of shims) {
      expect(shim.after).not.toContain('AGENTKEEPER_BYPASS');
      expect(shim.after).toMatch(/exec '.*node' '.*cli\.js' run --/);
      expect(shim.after?.match(/^exec /gm)).toHaveLength(1);
    }
  });
});

describe('installation execution adapters', () => {
  it('rolls every earlier write back when a transaction fails', async () => {
    class FailOnceFileSystem extends InMemoryFileSystem {
      failPath: string | null = null;

      override async write(path: AbsolutePath, content: string, mode?: number): Promise<void> {
        if (path.value === this.failPath) {
          this.failPath = null;
          throw new Error('simulated disk failure');
        }
        await super.write(path, content);
      }
    }

    const files = new FailOnceFileSystem();
    const profileBefore = '# user\n';
    const settingsBefore = '{"model":"opus"}';
    await files.write(POSIX_PROFILE, profileBefore);
    await files.write(CLAUDE_SETTINGS, settingsBefore);
    const plan = await new ManagedInstallationPlanner(files, options()).plan('activate');
    files.failPath = STATE.join('shims/posix/gemini').value;

    await expect(new TransactionalInstallationExecutor(files).execute(plan)).rejects.toThrow(
      'simulated disk failure',
    );
    expect(await files.read(POSIX_PROFILE)).toBe(profileBefore);
    expect(await files.read(CLAUDE_SETTINGS)).toBe(settingsBefore);
    expect(await files.read(STATE.join('shims/posix/claude'))).toBeNull();
    expect(await files.read(MANIFEST)).toBeNull();
  });

  it('provides an explicit no-op adapter for dry runs and tests', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POSIX_PROFILE, '# user\n');
    await files.write(CLAUDE_SETTINGS, '{}');
    const plan = await planner(files).plan('activate');
    const dryRun = new DryRunInstallationExecutor();

    const result = await dryRun.execute(plan);

    expect(result).toEqual({ applied: 0, dryRun: true });
    expect(dryRun.executedPlans).toEqual([plan]);
    expect(await files.read(MANIFEST)).toBeNull();
    expect(await files.read(POSIX_PROFILE)).toBe('# user\n');
  });

  it('refuses a stale plan before its first write', async () => {
    const files = new InMemoryFileSystem();
    await files.write(POSIX_PROFILE, '# user\n');
    await files.write(CLAUDE_SETTINGS, '{}');
    const plan = await planner(files).plan('activate');
    await files.write(POSIX_PROFILE, '# changed after planning\n');

    await expect(new TransactionalInstallationExecutor(files).execute(plan)).rejects.toBeInstanceOf(
      InstallationConcurrentChangeError,
    );
    expect(await files.read(POSIX_PROFILE)).toBe('# changed after planning\n');
    expect(await files.read(STATE.join('shims/posix/claude'))).toBeNull();
    expect(await files.read(MANIFEST)).toBeNull();
  });

  it('rechecks every precondition immediately before mutation and rolls earlier writes back', async () => {
    const first = HOME.join('transaction/first');
    const raced = HOME.join('transaction/raced');
    class RaceAfterPreflightFileSystem extends InMemoryFileSystem {
      private racedReads = 0;

      override async read(path: AbsolutePath): Promise<string | null> {
        if (path.equals(raced) && ++this.racedReads === 2) return 'changed concurrently';
        return super.read(path);
      }
    }
    const files = new RaceAfterPreflightFileSystem();
    const plan = {
      operation: 'activate' as const,
      conflicts: [],
      changes: [
        { path: first, before: null, after: 'managed', summary: 'create first' },
        { path: raced, before: null, after: 'managed', summary: 'create raced' },
      ],
    };

    await expect(new TransactionalInstallationExecutor(files).execute(plan)).rejects.toBeInstanceOf(
      InstallationConcurrentChangeError,
    );
    expect(await files.read(first)).toBeNull();
    expect(await files.read(raced)).toBeNull();
  });

  it('restores overwritten content byte-exact when a later mutation fails', async () => {
    const shared = HOME.join('transaction/shared');
    const failing = HOME.join('transaction/failing');
    class FailOneWriteFileSystem extends InMemoryFileSystem {
      failPath: string | null = null;

      override async write(path: AbsolutePath, content: string): Promise<void> {
        if (path.value === this.failPath) {
          this.failPath = null;
          throw new Error('simulated later failure');
        }
        await super.write(path, content);
      }
    }
    const files = new FailOneWriteFileSystem();
    await files.write(shared, 'original bytes');
    files.failPath = failing.value;
    const plan = {
      operation: 'repair' as const,
      conflicts: [],
      changes: [
        { path: shared, before: 'original bytes', after: 'managed bytes', summary: 'replace shared' },
        { path: failing, before: null, after: 'never committed', summary: 'fail here' },
      ],
    };

    await expect(new TransactionalInstallationExecutor(files).execute(plan)).rejects.toThrow(
      'simulated later failure',
    );
    expect(await files.read(shared)).toBe('original bytes');
    expect(await files.read(failing)).toBeNull();
  });

  it('surfaces both the original failure and an incomplete rollback', async () => {
    const shared = HOME.join('transaction/shared');
    const failing = HOME.join('transaction/failing');
    class RollbackFailureFileSystem extends InMemoryFileSystem {
      rollbackArmed = false;

      override async write(path: AbsolutePath, content: string): Promise<void> {
        if (this.rollbackArmed && path.equals(failing)) {
          throw new Error('simulated apply failure');
        }
        if (this.rollbackArmed && path.equals(shared) && content === 'original bytes') {
          throw new Error('simulated rollback failure');
        }
        await super.write(path, content);
      }
    }
    const files = new RollbackFailureFileSystem();
    await files.write(shared, 'original bytes');
    files.rollbackArmed = true;
    const plan = {
      operation: 'activate' as const,
      conflicts: [],
      changes: [
        { path: shared, before: 'original bytes', after: 'managed bytes', summary: 'replace shared' },
        { path: failing, before: null, after: 'never committed', summary: 'fail here' },
      ],
    };

    const execution = new TransactionalInstallationExecutor(files).execute(plan);
    await expect(execution).rejects.toMatchObject({
      name: 'AggregateError',
      message: 'Installation transaction failed and could not be rolled back completely',
      errors: [
        expect.objectContaining({ message: 'simulated apply failure' }),
        expect.objectContaining({ message: 'simulated rollback failure' }),
      ],
    });
    expect(await files.read(shared)).toBe('managed bytes');
  });
});
