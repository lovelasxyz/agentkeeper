import { AbsolutePath } from './AbsolutePath.js';

export type ResourceScope = 'subtree' | 'file';

const PREFIX: Readonly<Record<string, ResourceScope>> = { dir: 'subtree', file: 'file' };

/**
 * A concrete filesystem resource a policy talks about.
 *
 * Deliberately narrower than `PathPattern`: a sandbox rule has to name a real
 * location, so wildcards stop at the domain boundary and never reach a policy.
 */
export class ResourceRef {
  private constructor(
    readonly scope: ResourceScope,
    readonly path: AbsolutePath,
  ) {
    Object.freeze(this);
  }

  static subtree(path: AbsolutePath): ResourceRef {
    return new ResourceRef('subtree', path);
  }

  static file(path: AbsolutePath): ResourceRef {
    return new ResourceRef('file', path);
  }

  /** Parses the `dir:~/projects` / `file:~/.gitconfig` form used in stored grants. */
  static parse(raw: string, home: AbsolutePath): ResourceRef {
    const separator = raw.indexOf(':');
    const kind = separator === -1 ? '' : raw.slice(0, separator);
    const scope = PREFIX[kind];
    if (!scope) throw new Error(`Unknown resource reference: ${JSON.stringify(raw)}`);
    const path = AbsolutePath.fromUserPath(raw.slice(separator + 1), home);
    return new ResourceRef(scope, path);
  }

  covers(candidate: AbsolutePath): boolean {
    return this.scope === 'subtree' ? this.path.contains(candidate) : this.path.equals(candidate);
  }

  /** True when granting this ref makes the other ref redundant. */
  subsumes(other: ResourceRef): boolean {
    if (this.scope === 'file') return other.scope === 'file' && this.path.equals(other.path);
    return this.path.contains(other.path);
  }

  equals(other: ResourceRef): boolean {
    return this.scope === other.scope && this.path.equals(other.path);
  }

  toResourceString(home: AbsolutePath): string {
    const kind = this.scope === 'subtree' ? 'dir' : 'file';
    return `${kind}:${this.path.toDisplay(home)}`;
  }

  toString(): string {
    return `${this.scope}:${this.path.toString()}`;
  }
}
