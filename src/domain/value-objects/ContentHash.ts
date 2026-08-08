import { createHash } from 'node:crypto';

const SERIALISED = /^sha256:([0-9a-f]{64})$/;

/**
 * SHA-256 of an artifact's *content*.
 *
 * TOFU decisions (spec §7) are keyed by this rather than by path, which is what
 * closes the rug-pull vector: an approved `.claude/settings.json` that changes
 * under a `git pull` is simply a different artifact and gets asked about again.
 */
export class ContentHash {
  private constructor(private readonly hex: string) {
    Object.freeze(this);
  }

  static fromContent(content: string | Uint8Array): ContentHash {
    const digest = createHash('sha256').update(content).digest('hex');
    return new ContentHash(digest);
  }

  static parse(serialised: string): ContentHash {
    const match = SERIALISED.exec(serialised);
    if (!match) throw new Error(`Malformed content hash: ${JSON.stringify(serialised)}`);
    return new ContentHash(match[1] as string);
  }

  /** Enough to recognise an entry in a log line; never used for decisions. */
  get short(): string {
    return this.hex.slice(0, 8);
  }

  equals(other: ContentHash): boolean {
    return this.hex === other.hex;
  }

  toString(): string {
    return `sha256:${this.hex}`;
  }

  toJSON(): string {
    return this.toString();
  }
}
