import { describe, expect, it } from 'vitest';
import { InMemoryFileSystem, FixedClock, RecordingAudit } from './fakes.js';
import {
  ClaudeHookIntegration,
  DaemonIntegration,
  GitHookIntegration,
  ShellFunctionsIntegration,
} from '../../src/infrastructure/install/integrations.js';
import { ApplyChanges } from '../../src/application/use-cases/ApplyChanges.js';
import { Configuration } from '../../src/infrastructure/config/Configuration.js';
import { BaselineCollector } from '../../src/presentation/daemon/BaselineCollector.js';
import { SensitivePathRegistry } from '../../src/domain/paths/SensitivePathRegistry.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import type { PathContext } from '../../src/domain/paths/PathContext.js';
import type { Integration } from '../../src/application/ports/Integration.js';

const HOME = AbsolutePath.of('/Users/dev');
const STATE = HOME.join('.agentkeeper');
const BIN = '/usr/local/bin/agentkeeper';

async function roundTrip(
  files: InMemoryFileSystem,
  integration: Integration,
): Promise<void> {
  const apply = new ApplyChanges(files, STATE.join('backups'), new RecordingAudit(), new FixedClock());
  const applied = await apply.execute(await integration.plan());
  expect(await integration.isInstalled()).toBe(true);
  await apply.execute(await integration.uninstallPlan());
  expect(await integration.isInstalled()).toBe(false);
  expect(applied.length).toBeGreaterThan(0);
}

describe('ShellFunctionsIntegration', () => {
  const build = async () => {
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.zshrc'), '# mine\nexport EDITOR=vim\n');
    return { files, integration: new ShellFunctionsIntegration(files, HOME, STATE) };
  };

  it('writes the functions to their own file and one line to the rc file', async () => {
    const { files, integration } = await build();
    const changes = await integration.plan();

    expect(changes.map((change) => change.path.basename)).toEqual(['shell-init.sh', '.zshrc']);
    const rc = changes[1]?.after as string;
    expect(rc).toContain('# mine');
    expect(rc.split('\n').filter((line) => line.includes('shell-init.sh'))).toHaveLength(1);
  });

  it('does not create a shell rc file the user does not have', async () => {
    const files = new InMemoryFileSystem();
    const integration = new ShellFunctionsIntegration(files, HOME, STATE);
    const changes = await integration.plan();
    expect(changes.map((change) => change.path.basename)).toEqual(['shell-init.sh']);
  });

  it('is idempotent: a second plan does not add the line twice', async () => {
    const { files, integration } = await build();
    const apply = new ApplyChanges(files, STATE.join('backups'), new RecordingAudit(), new FixedClock());
    await apply.execute(await integration.plan());

    const second = await integration.plan();
    expect(second.some((change) => change.path.basename === '.zshrc')).toBe(false);
  });

  it('restores the rc file exactly on uninstall', async () => {
    const { files, integration } = await build();
    const original = (await files.read(HOME.join('.zshrc'))) as string;
    const apply = new ApplyChanges(files, STATE.join('backups'), new RecordingAudit(), new FixedClock());

    await apply.execute(await integration.plan());
    await apply.execute(await integration.uninstallPlan());

    expect(await files.read(HOME.join('.zshrc'))).toBe(original);
  });

  it('round-trips', async () => {
    const { files, integration } = await build();
    await roundTrip(files, integration);
  });
});

describe('ClaudeHookIntegration', () => {
  it('keeps the settings the user already had', async () => {
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.claude/settings.json'), '{"model":"opus","hooks":{"Stop":[1]}}');

    const integration = new ClaudeHookIntegration(files, HOME, BIN);
    const after = JSON.parse((await integration.plan())[0]?.after as string) as {
      model: string;
      hooks: Record<string, unknown>;
    };

    expect(after.model).toBe('opus');
    expect(after.hooks['Stop']).toEqual([1]);
    expect(JSON.stringify(after.hooks['PreToolUse'])).toContain('hook pretooluse');
  });

  it('leaves the other hooks in place when removed', async () => {
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.claude/settings.json'), '{"hooks":{"Stop":[1]}}');
    const integration = new ClaudeHookIntegration(files, HOME, BIN);
    const apply = new ApplyChanges(files, STATE.join('backups'), new RecordingAudit(), new FixedClock());

    await apply.execute(await integration.plan());
    await apply.execute(await integration.uninstallPlan());

    const settings = JSON.parse((await files.read(HOME.join('.claude/settings.json'))) as string) as {
      hooks: Record<string, unknown>;
    };
    expect(settings.hooks['Stop']).toEqual([1]);
    expect(settings.hooks['PreToolUse']).toBeUndefined();
  });

  it('removes the hooks key entirely when it was the only one', async () => {
    const files = new InMemoryFileSystem();
    const integration = new ClaudeHookIntegration(files, HOME, BIN);
    const apply = new ApplyChanges(files, STATE.join('backups'), new RecordingAudit(), new FixedClock());

    await apply.execute(await integration.plan());
    await apply.execute(await integration.uninstallPlan());

    expect(await files.read(HOME.join('.claude/settings.json'))).not.toContain('hooks');
  });

  it('survives a settings file that is not valid JSON', async () => {
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.claude/settings.json'), '{ broken');
    const changes = await new ClaudeHookIntegration(files, HOME, BIN).plan();
    expect(JSON.parse(changes[0]?.after as string)).toHaveProperty('hooks');
  });

  it('round-trips', async () => {
    const files = new InMemoryFileSystem();
    await roundTrip(files, new ClaudeHookIntegration(files, HOME, BIN));
  });
});

describe('GitHookIntegration', () => {
  it('writes both hooks', async () => {
    const files = new InMemoryFileSystem();
    const changes = await new GitHookIntegration(files, STATE, BIN, null).plan();
    expect(changes.map((change) => change.path.basename)).toEqual(['post-checkout', 'post-merge']);
    expect(changes[0]?.after).toContain('scan --quiet');
  });

  it('chains to hooks that were already configured, so husky keeps working', async () => {
    const files = new InMemoryFileSystem();
    const changes = await new GitHookIntegration(files, STATE, BIN, '/work/.husky').plan();
    expect(changes[0]?.after).toContain('/work/.husky/post-checkout');
  });

  it('never lets its own failure break a checkout', async () => {
    const files = new InMemoryFileSystem();
    const changes = await new GitHookIntegration(files, STATE, BIN, null).plan();
    expect(changes[0]?.after).toContain('|| true');
  });

  it('round-trips', async () => {
    const files = new InMemoryFileSystem();
    await roundTrip(files, new GitHookIntegration(files, STATE, BIN, null));
  });
});

describe('DaemonIntegration', () => {
  it('writes a user-level launch agent on macOS, never a system one', async () => {
    const files = new InMemoryFileSystem();
    const changes = await new DaemonIntegration(files, HOME, 'darwin', BIN).plan();
    expect(changes[0]?.path.value).toBe('/Users/dev/Library/LaunchAgents/dev.agentkeeper.watcher.plist');
    expect(changes[0]?.after).toContain('<key>RunAtLoad</key>');
  });

  it('writes a systemd user unit on Linux', async () => {
    const files = new InMemoryFileSystem();
    const changes = await new DaemonIntegration(files, HOME, 'linux', BIN).plan();
    expect(changes[0]?.path.value).toBe('/Users/dev/.config/systemd/user/agentkeeper.service');
    expect(changes[0]?.after).toContain('WantedBy=default.target');
  });

  it('installs nothing on a platform it does not support yet', async () => {
    const files = new InMemoryFileSystem();
    expect(await new DaemonIntegration(files, HOME, 'win32', BIN).plan()).toEqual([]);
  });

  it('round-trips', async () => {
    const files = new InMemoryFileSystem();
    await roundTrip(files, new DaemonIntegration(files, HOME, 'darwin', BIN));
  });
});

describe('Configuration', () => {
  it('is strict by default', async () => {
    const config = Configuration.defaults();
    expect(config.onUnavailable).toBe('fail');
    expect(config.sandboxEnabled).toBe(true);
    expect(config.strictMode).toBe(false);
  });

  it('has family A off by default, as the spec requires', () => {
    expect(Configuration.defaults().isEnabled('categoryA')).toBe(false);
    expect(Configuration.defaults().isEnabled('AG-A001')).toBe(false);
  });

  it('keeps every other family on', () => {
    expect(Configuration.defaults().isEnabled('AG-H001')).toBe(true);
  });

  it('lets a single rule be turned off', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      STATE.join('config.json'),
      JSON.stringify({ version: 1, rules: { 'AG-E003': { enabled: false } } }),
    );
    const config = await Configuration.load(files, STATE);
    expect(config.isEnabled('AG-E003')).toBe(false);
    expect(config.isEnabled('AG-E002')).toBe(true);
  });

  it('merges a partial file over the defaults', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      STATE.join('config.json'),
      JSON.stringify({ version: 1, sandbox: { starterProfile: 'python' } }),
    );
    const config = await Configuration.load(files, STATE);
    expect(config.starterProfile).toBe('python');
    expect(config.onUnavailable).toBe('fail'); // still the strict default
  });

  it('falls back to the strict defaults when the file is unreadable', async () => {
    const files = new InMemoryFileSystem();
    await files.write(STATE.join('config.json'), '{ broken');
    const config = await Configuration.load(files, STATE);
    expect(config.onUnavailable).toBe('fail');
  });

  it('does not let malformed security fields turn fail-closed into an unconfined run', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      STATE.join('config.json'),
      JSON.stringify({
        version: 1,
        sandbox: { enabled: 'yes', onUnavailable: 'continue-anyway' },
        strictMode: 'no',
        rules: { categoryA: { enabled: 'sometimes' } },
      }),
    );

    const config = await Configuration.load(files, STATE);
    expect(config.sandboxEnabled).toBe(true);
    expect(config.onUnavailable).toBe('fail');
    expect(config.strictMode).toBe(false);
    expect(config.isEnabled('AG-A001')).toBe(false);
  });

  it('refuses configuration schemas from another version', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      STATE.join('config.json'),
      JSON.stringify({ version: 99, sandbox: { enabled: false, onUnavailable: 'warn' } }),
    );

    const config = await Configuration.load(files, STATE);
    expect(config.sandboxEnabled).toBe(true);
    expect(config.onUnavailable).toBe('fail');
  });

  it('validates collections and bounded numeric settings instead of trusting JSON shapes', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      STATE.join('config.json'),
      JSON.stringify({
        version: 1,
        watchRoots: ['~/projects', 7, null],
        notifications: 'webhook',
        logRetentionDays: -10,
      }),
    );

    const config = await Configuration.load(files, STATE);
    expect(config.watchRoots(HOME).map(String)).toEqual(['/Users/dev/projects']);
    expect(config.document.notifications).toBe('native');
    expect(config.document.logRetentionDays).toBe(90);
  });

  it('resolves watch roots against the home directory', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      STATE.join('config.json'),
      JSON.stringify({ version: 1, watchRoots: ['~/projects'] }),
    );
    const config = await Configuration.load(files, STATE);
    expect(config.watchRoots(HOME).map(String)).toEqual(['/Users/dev/projects']);
  });
});

describe('BaselineCollector', () => {
  const context: PathContext = {
    home: HOME,
    workspace: HOME.join('projects/app'),
    platform: 'darwin',
  };

  it('targets the persistence surfaces of this platform', () => {
    const collector = new BaselineCollector(
      new InMemoryFileSystem(),
      SensitivePathRegistry.default(),
      new FixedClock(),
    );
    const targets = collector.targets(context).map(String);
    expect(targets).toContain('/Users/dev/.zshenv');
    expect(targets).toContain('/Users/dev/.npmrc');
    expect(targets).toContain('/Users/dev/Library/LaunchAgents');
    expect(targets).not.toContain('/Users/dev/.config/systemd/user'); // Linux only
  });

  it('does not include credential paths: the snapshot is about persistence', () => {
    const collector = new BaselineCollector(
      new InMemoryFileSystem(),
      SensitivePathRegistry.default(),
      new FixedClock(),
    );
    expect(collector.targets(context).map(String)).not.toContain('/Users/dev/.aws');
  });

  it('hashes what exists and skips what does not', async () => {
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.zshenv'), 'export A=1\n');
    const collector = new BaselineCollector(files, SensitivePathRegistry.default(), new FixedClock());

    const snapshot = await collector.collect(context);
    expect(snapshot.map((entry) => entry.path.value)).toEqual(['/Users/dev/.zshenv']);
  });

  it('keeps collecting when a persistence surface is unreadable without root', async () => {
    // `/private/var/at/tabs` is root-only on macOS. Aborting the snapshot there
    // made `activate` fail outright on a stock machine.
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.zshenv'), 'export A=1\n');
    const denied = Object.assign(new Error('list failed for /private/var/at/tabs (EACCES)'), {
      code: 'EACCES',
    });
    const guarded = Object.create(files) as InMemoryFileSystem;
    guarded.list = async (root, options) => {
      if (root.value === '/private/var/at/tabs') throw denied;
      return files.list(root, options);
    };
    await files.write(AbsolutePath.of('/private/var/at/tabs/root'), '* * * * * echo hi\n');

    const collector = new BaselineCollector(
      guarded,
      SensitivePathRegistry.default(),
      new FixedClock(),
    );

    const snapshot = await collector.collect(context);
    expect(snapshot.map((entry) => entry.path.value)).toEqual(['/Users/dev/.zshenv']);
  });

  it('still reports an unexpected filesystem failure instead of a thin baseline', async () => {
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.zshenv'), 'export A=1\n');
    await files.write(HOME.join('Library/LaunchAgents/some.plist'), '<plist/>\n');
    const guarded = Object.create(files) as InMemoryFileSystem;
    guarded.list = async () => {
      throw Object.assign(new Error('list failed (EIO)'), { code: 'EIO' });
    };
    const collector = new BaselineCollector(
      guarded,
      SensitivePathRegistry.default(),
      new FixedClock(),
    );

    await expect(collector.collect(context)).rejects.toThrow(/EIO/);
  });

  it('baselines only the files a sensitive pattern names, not the directory holding them', async () => {
    // `~/.claude/settings*.json` anchors on `~/.claude`, and collecting the
    // whole directory both blew the listing limit — activation failed outright
    // on a machine with an ordinary Claude Code history — and would have
    // baselined session files that change every few minutes.
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.claude/settings.json'), '{"hooks":{}}');
    for (let index = 0; index < 2_100; index += 1) {
      await files.write(HOME.join(`.claude/projects/session-${index}.jsonl`), 'noise\n');
    }
    const collector = new BaselineCollector(files, SensitivePathRegistry.default(), new FixedClock());

    const snapshot = await collector.collect(context);

    expect(snapshot.map((entry) => entry.path.value)).toEqual([
      '/Users/dev/.claude/settings.json',
    ]);
  });

  it('records digests, never content', async () => {
    const files = new InMemoryFileSystem();
    await files.write(HOME.join('.zshenv'), 'export SECRET=hunter2\n');
    const collector = new BaselineCollector(files, SensitivePathRegistry.default(), new FixedClock());

    expect(JSON.stringify(await collector.collect(context))).not.toContain('hunter2');
  });

  it('suppresses its mutable control-plane writes but not protected configuration events', () => {
    const collector = new BaselineCollector(
      new InMemoryFileSystem(),
      SensitivePathRegistry.default(),
      new FixedClock(),
    );

    expect(collector.isRelevantWatchEvent(STATE.join('audit.log'), context)).toBe(false);
    expect(
      collector.isRelevantWatchEvent(STATE.join('audit/audit-1.open.jsonl'), context),
    ).toBe(false);
    expect(collector.isRelevantWatchEvent(STATE.join('baseline.json.a1b2.tmp'), context)).toBe(false);
    expect(collector.isRelevantWatchEvent(STATE.join('config.json.a1b2c3d4e5f6.tmp'), context)).toBe(false);
    expect(collector.isRelevantWatchEvent(STATE.join('shims/kept.tmp'), context)).toBe(true);
    expect(collector.isRelevantWatchEvent(STATE.join('persistence-pending.json'), context)).toBe(false);
    expect(collector.isRelevantWatchEvent(STATE.join('pause.json'), context)).toBe(false);
    expect(collector.isRelevantWatchEvent(STATE.join('decisions.json'), context)).toBe(true);
    expect(collector.isRelevantWatchEvent(STATE.join('config.json'), context)).toBe(true);
    expect(collector.isRelevantWatchEvent(HOME.join('.zshenv'), context)).toBe(true);
    expect(collector.isRelevantWatchEvent(null, context)).toBe(true);
  });
});
