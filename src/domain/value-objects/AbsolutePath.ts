import { posix } from 'node:path';

/**
 * A normalised absolute filesystem path.
 *
 * Pure value object: it never touches the filesystem, so it can be reasoned
 * about — and tested — without any I/O. Every path that crosses a policy or
 * rule boundary is expressed with this type, which removes a whole class of
 * "was this string absolute, normalised, tilde-expanded?" defects.
 */
export class AbsolutePath {
  private constructor(readonly value: string) {
    Object.freeze(this);
  }

  static of(raw: string): AbsolutePath {
    if (raw.includes('\0')) {
      throw new Error(`Path contains a NUL byte: ${JSON.stringify(raw)}`);
    }
    if (!raw.startsWith('/')) {
      throw new Error(`Path must be absolute: ${JSON.stringify(raw)}`);
    }
    return new AbsolutePath(posix.normalize(raw).replace(/\/+$/, '') || '/');
  }

  /**
   * Accepts what a human would type: `/etc/hosts`, `~`, `~/.ssh/id_rsa`.
   * A bare `~user` form is deliberately not supported — resolving another
   * account's home requires I/O and is outside this object's contract.
   */
  static fromUserPath(raw: string, home: AbsolutePath): AbsolutePath {
    if (raw === '~') return home;
    if (raw.startsWith('~/')) return AbsolutePath.of(`${home.value}/${raw.slice(2)}`);
    return AbsolutePath.of(raw);
  }

  get segments(): readonly string[] {
    return this.value === '/' ? [] : this.value.slice(1).split('/');
  }

  get basename(): string {
    return posix.basename(this.value);
  }

  get parent(): AbsolutePath {
    return AbsolutePath.of(posix.dirname(this.value));
  }

  join(...parts: readonly string[]): AbsolutePath {
    return AbsolutePath.of(posix.join(this.value, ...parts));
  }

  /** True when `other` is this path or lives underneath it. */
  contains(other: AbsolutePath): boolean {
    if (this.value === '/') return true;
    return other.value === this.value || other.value.startsWith(`${this.value}/`);
  }

  equals(other: AbsolutePath): boolean {
    return this.value === other.value;
  }

  /** Renders the path back with `~` when it sits inside the given home. */
  toDisplay(home: AbsolutePath): string {
    if (this.equals(home)) return '~';
    return home.contains(this) ? `~${this.value.slice(home.value.length)}` : this.value;
  }

  toString(): string {
    return this.value;
  }

  toJSON(): string {
    return this.value;
  }
}
