import type { AuditEntry, AuditLog } from '../ports/index.js';

/** Preserves append order even when independent runtime callbacks fire together. */
export class SerialAuditLog implements AuditLog {
  private tail: Promise<void> = Promise.resolve();

  constructor(private readonly inner: AuditLog) {}

  append(entry: AuditEntry): Promise<void> {
    const operation = this.tail.then(async () => this.inner.append(entry));
    // A failed append is returned to its caller but does not poison every later
    // attempt; a full disk can be repaired while the daemon remains alive.
    this.tail = operation.catch(() => {});
    return operation;
  }

  async since(moment: Date): Promise<readonly AuditEntry[]> {
    await this.tail;
    return this.inner.since(moment);
  }
}
