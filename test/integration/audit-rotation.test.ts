import { describe, expect, it } from 'vitest';
import { JsonlAuditLog } from '../../src/infrastructure/store/stores.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { InMemoryFileSystem } from './fakes.js';

const STATE = AbsolutePath.of('/Users/dev/.agentkeeper');

class MutableNow {
  constructor(private value = new Date('2026-01-01T00:00:00Z')) {}

  now = (): Date => this.value;

  advance(milliseconds: number): void {
    this.value = new Date(this.value.getTime() + milliseconds);
  }
}

const options = (
  now: () => Date,
  overrides: Partial<{
    maxSegmentBytes: number;
    maxTotalBytes: number;
    maxSegments: number;
    maxEntryBytes: number;
    retentionDays: number;
  }> = {},
) => ({
  maxSegmentBytes: 256,
  maxTotalBytes: 1_024,
  maxSegments: 4,
  maxEntryBytes: 192,
  retentionDays: 90,
  now,
  processId: 1234,
  instanceId: '001122334455',
  processAlive: () => false,
  ...overrides,
});

describe('JsonlAuditLog rotation and retention', () => {
  it('serialises concurrent appends in invocation order', async () => {
    const files = new DelayedFirstAppendFileSystem();
    const clock = new MutableNow();
    const log = new JsonlAuditLog(
      files,
      STATE,
      options(clock.now, { maxSegments: 16, maxTotalBytes: 4_096 }),
    );

    const first = log.append(entry(clock.now(), 'first'));
    await new Promise<void>((resolve) => setImmediate(resolve));
    const second = log.append(entry(clock.now(), 'second'));
    await new Promise<void>((resolve) => setImmediate(resolve));
    files.releaseFirst();
    await Promise.all([first, second]);

    expect((await log.since(new Date(0))).map((value) => value.event)).toEqual([
      'first',
      'second',
    ]);
  });

  it('rotates into immutable segments without losing or reordering entries', async () => {
    const files = new InMemoryFileSystem();
    const clock = new MutableNow();
    const log = new JsonlAuditLog(
      files,
      STATE,
      options(clock.now, { maxSegments: 16, maxTotalBytes: 4_096 }),
    );

    for (let index = 0; index < 9; index += 1) {
      await log.append(entry(clock.now(), `event-${index}`, { payload: 'x'.repeat(45) }));
      clock.advance(1);
    }

    const segments = auditSegments(files);
    expect(segments.some((path) => path.endsWith('.closed.jsonl'))).toBe(true);
    expect(segments.some((path) => path.endsWith('.open.jsonl'))).toBe(true);
    expect((await log.since(new Date(0))).map((value) => value.event)).toEqual(
      Array.from({ length: 9 }, (_, index) => `event-${index}`),
    );
  });

  it('enforces count and byte budgets by evicting only the oldest closed segments', async () => {
    const files = new InMemoryFileSystem();
    const clock = new MutableNow();
    const log = new JsonlAuditLog(
      files,
      STATE,
      options(clock.now, { maxSegments: 3, maxTotalBytes: 700 }),
    );

    for (let index = 0; index < 20; index += 1) {
      await log.append(entry(clock.now(), `bounded-${index}`, { payload: 'y'.repeat(50) }));
      clock.advance(1);
    }

    const segments = auditSegments(files);
    const bytes = segments.reduce((total, path) => total + (files.files.get(path)?.length ?? 0), 0);
    expect(segments.length).toBeLessThanOrEqual(3);
    expect(bytes).toBeLessThanOrEqual(700);
    const retained = await log.since(new Date(0));
    expect(retained.at(-1)?.event).toBe('bounded-19');
    expect(retained.length).toBeLessThan(20);
  });

  it('expires closed evidence after the configured retention window', async () => {
    const files = new InMemoryFileSystem();
    const clock = new MutableNow();
    const log = new JsonlAuditLog(files, STATE, options(clock.now, { retentionDays: 1 }));
    await log.append(entry(clock.now(), 'expired'));
    clock.advance(2 * 24 * 60 * 60_000);
    await log.append(entry(clock.now(), 'current'));

    expect((await log.since(new Date(0))).map((value) => value.event)).toEqual(['current']);
  });

  it('atomically migrates the legacy audit.log and keeps its evidence', async () => {
    const files = new InMemoryFileSystem();
    const clock = new MutableNow();
    await files.write(
      STATE.join('audit.log'),
      `${JSON.stringify({ at: clock.now().toISOString(), event: 'legacy' })}\n`,
    );
    const log = new JsonlAuditLog(files, STATE, options(clock.now));

    await log.append(entry(clock.now(), 'segmented'));

    expect(await files.exists(STATE.join('audit.log'))).toBe(false);
    expect((await log.since(new Date(0))).map((value) => value.event)).toEqual([
      'legacy',
      'segmented',
    ]);
  });

  it('does not let untrusted details override reserved audit fields', async () => {
    const files = new InMemoryFileSystem();
    const clock = new MutableNow();
    const log = new JsonlAuditLog(files, STATE, options(clock.now));

    await log.append({
      at: clock.now(),
      event: 'trusted-event',
      details: { at: 'not-a-date', event: 'forged-event' },
    });

    expect(await log.since(new Date(0))).toMatchObject([
      { at: clock.now(), event: 'trusted-event' },
    ]);
  });

  it('refuses an oversized entry before growing the audit store', async () => {
    const files = new InMemoryFileSystem();
    const clock = new MutableNow();
    const log = new JsonlAuditLog(files, STATE, options(clock.now, { maxEntryBytes: 96 }));

    await expect(
      log.append(entry(clock.now(), 'oversized', { payload: 'z'.repeat(200) })),
    ).rejects.toThrow(/entry.*limit/i);
    expect(auditSegments(files)).toEqual([]);
  });
});

function entry(
  at: Date,
  event: string,
  details: Readonly<Record<string, unknown>> = {},
) {
  return { at, event, details };
}

function auditSegments(files: InMemoryFileSystem): string[] {
  return [...files.files.keys()]
    .filter((path) => path.startsWith(`${STATE.value}/audit/`) && path.endsWith('.jsonl'))
    .sort();
}

class DelayedFirstAppendFileSystem extends InMemoryFileSystem {
  private first = true;
  private release!: () => void;
  private readonly gate = new Promise<void>((resolve) => {
    this.release = resolve;
  });

  override async append(path: AbsolutePath, content: string): Promise<void> {
    if (this.first) {
      this.first = false;
      await this.gate;
    }
    await super.append(path, content);
  }

  releaseFirst(): void {
    this.release();
  }
}
