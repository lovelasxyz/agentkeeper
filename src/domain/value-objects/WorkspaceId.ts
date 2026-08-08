import { createHash } from 'node:crypto';
import type { AbsolutePath } from './AbsolutePath.js';

const FORMAT = /^[0-9a-f]{16}$/;

/**
 * Short, stable identifier of a working directory. Short on purpose: it ends up
 * in a config file a human is expected to read and edit by hand (spec §4.5).
 */
export class WorkspaceId {
  private constructor(private readonly value: string) {
    Object.freeze(this);
  }

  static fromPath(path: AbsolutePath): WorkspaceId {
    return new WorkspaceId(createHash('sha256').update(path.value).digest('hex').slice(0, 16));
  }

  static parse(raw: string): WorkspaceId {
    if (!FORMAT.test(raw)) throw new Error(`Malformed workspace id: ${JSON.stringify(raw)}`);
    return new WorkspaceId(raw);
  }

  equals(other: WorkspaceId): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }

  toJSON(): string {
    return this.value;
  }
}
