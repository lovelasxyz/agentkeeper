import { describe, expect, it } from 'vitest';
import { SerialAuditLog } from '../../../src/application/services/SerialAuditLog.js';
import type { AuditEntry, AuditLog } from '../../../src/application/ports/index.js';

describe('SerialAuditLog', () => {
  it('preserves call order when the underlying appends complete out of order', async () => {
    const stored: string[] = [];
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    const inner: AuditLog = {
      async append(entry) {
        if (entry.event === 'first') await firstGate;
        stored.push(entry.event);
      },
      async since() {
        return [];
      },
    };
    const audit = new SerialAuditLog(inner);
    const first = audit.append(entry('first'));
    const second = audit.append(entry('second'));
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(stored).toEqual([]);

    releaseFirst();
    await Promise.all([first, second]);
    expect(stored).toEqual(['first', 'second']);
  });

  it('does not let one failed append poison later evidence', async () => {
    const stored: string[] = [];
    const inner: AuditLog = {
      async append(value) {
        if (value.event === 'broken') throw new Error('disk temporarily unavailable');
        stored.push(value.event);
      },
      async since() {
        return [];
      },
    };
    const audit = new SerialAuditLog(inner);

    await expect(audit.append(entry('broken'))).rejects.toThrow('disk temporarily unavailable');
    await audit.append(entry('recovered'));
    expect(stored).toEqual(['recovered']);
  });

  it('waits for queued evidence before reading the log', async () => {
    const stored: AuditEntry[] = [];
    const inner: AuditLog = {
      async append(value) {
        stored.push(value);
      },
      async since(moment) {
        return stored.filter((value) => value.at >= moment);
      },
    };
    const audit = new SerialAuditLog(inner);
    void audit.append(entry('queued'));

    await expect(audit.since(new Date('2026-08-08T09:00:00Z'))).resolves.toMatchObject([
      { event: 'queued' },
    ]);
  });
});

function entry(event: string): AuditEntry {
  return { at: new Date('2026-08-08T10:00:00Z'), event, details: {} };
}
