import { EventEmitter } from 'node:events';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  NodeWatchService,
  type DirectoryWatcher,
  type WatchDirectory,
} from '../../../src/infrastructure/watch/NodeWatchService.js';
import { AbsolutePath } from '../../../src/domain/value-objects/AbsolutePath.js';

const temporaryRoots: string[] = [];

afterEach(async () => {
  for (const root of temporaryRoots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function temporaryRoot(): Promise<AbsolutePath> {
  const root = await mkdtemp(join(tmpdir(), 'agentkeeper-watch-'));
  temporaryRoots.push(root);
  return AbsolutePath.of(root);
}

function nextEvent(): {
  readonly promise: Promise<string | null>;
  readonly accept: (path: string | null) => void;
} {
  let accept!: (path: string | null) => void;
  const promise = new Promise<string | null>((resolve) => {
    accept = resolve;
  });
  return { promise, accept };
}

describe('NodeWatchService', () => {
  it('watches existing directory trees recursively without native-recursive assumptions', async () => {
    const root = await temporaryRoot();
    await mkdir(root.join('nested/deeper').value, { recursive: true });
    const driver = new FakeWatchDriver();
    const event = nextEvent();
    const started = await new NodeWatchService({ watchDirectory: driver.watch }).start(
      [root],
      (change) => event.accept(change.path?.value ?? null),
      () => {},
    );

    expect(started.coverage.status).toBe('protected');
    expect(started.coverage.watchedDirectories).toBe(3);
    driver.change(root.join('nested/deeper'), 'change', 'change.txt');
    await expect(event.promise).resolves.toBe(root.join('nested/deeper/change.txt').value);
    started.session.close();
  });

  it('reports an explicit degraded state when a missing target is covered by an ancestor', async () => {
    const root = await temporaryRoot();
    const driver = new FakeWatchDriver();
    const event = nextEvent();
    const target = root.join('not-created/config.json');
    const started = await new NodeWatchService({ watchDirectory: driver.watch }).start(
      [target],
      (change) => event.accept(change.path?.value ?? null),
      () => {},
    );

    expect(started.coverage.status).toBe('degraded');
    expect(started.coverage.reasons.join('\n')).toContain('does not exist');
    await mkdir(root.join('not-created').value);
    driver.change(root, 'rename', 'not-created');
    await expect(event.promise).resolves.toBe(root.join('not-created').value);
    started.session.close();
  });

  it('bounds recursive registrations and reports the resulting coverage gap', async () => {
    const root = await temporaryRoot();
    await mkdir(root.join('one/two/three').value, { recursive: true });
    const driver = new FakeWatchDriver();
    const faults: string[] = [];
    const started = await new NodeWatchService({
      maxDirectories: 2,
      watchDirectory: driver.watch,
    }).start([root], () => {}, (fault) => faults.push(fault.reason));

    expect(started.coverage.status).toBe('degraded');
    expect(started.coverage.watchedDirectories).toBe(2);
    expect(started.coverage.reasons.join('\n')).toContain('directory limit 2');
    expect(faults.join('\n')).toContain('directory limit 2');
    started.session.close();
  });

  it('turns an asynchronous backend startup error into failed coverage', async () => {
    const root = await temporaryRoot();
    const faults: string[] = [];
    const watchDirectory: WatchDirectory = () => {
      const watcher = new FakeWatcher();
      queueMicrotask(() => watcher.emit('error', new Error('backend denied')));
      return watcher;
    };

    const started = await new NodeWatchService({ watchDirectory }).start(
      [root],
      () => {},
      (fault) => faults.push(fault.reason),
    );

    expect(started.coverage.status).toBe('failed');
    expect(started.coverage.watchedDirectories).toBe(0);
    expect(started.coverage.reasons.join('\n')).toContain('backend denied');
    expect(faults.join('\n')).toContain('backend denied');
    started.session.close();
  });
});

class FakeWatcher extends EventEmitter implements DirectoryWatcher {
  closed = false;

  close(): void {
    this.closed = true;
  }

  override on(event: 'error', listener: (error: Error) => void): this {
    return super.on(event, listener);
  }
}

class FakeWatchDriver {
  private readonly listeners = new Map<
    string,
    (eventType: string, filename: string | Buffer | null) => void
  >();

  readonly watch: WatchDirectory = (path, _options, listener) => {
    this.listeners.set(path, listener);
    return new FakeWatcher();
  };

  change(path: AbsolutePath, type: 'change' | 'rename', filename: string | null): void {
    const listener = this.listeners.get(path.value);
    if (listener === undefined) throw new Error(`No watcher registered for ${path.value}`);
    listener(type, filename);
  }
}
