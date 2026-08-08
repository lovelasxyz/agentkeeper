import type { PathPattern } from '../value-objects/PathPattern.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { Access } from '../paths/SensitivePath.js';

/**
 * A refusal that outranks every allow rule below it.
 *
 * The sandbox profile is not a pure allowlist: it is allows, then these, then
 * the hand-written overrides. That ordering is what lets a user grant a whole
 * project directory without silently handing over the `.env` files of the
 * sibling projects inside it.
 */
export class DenyRule {
  constructor(
    readonly sourceId: string,
    readonly pattern: PathPattern,
    readonly access: Access,
    readonly reason: string,
    /**
     * Subtree the refusal does *not* apply to. Carries the `outsideWorkspaceOnly`
     * flag of a registry entry across the translation boundary — without it,
     * "every `.env` except this project's own" degrades into "every `.env`",
     * and the agent cannot read the file it was hired to work on.
     */
    readonly exceptWithin: AbsolutePath | null = null,
  ) {
    Object.freeze(this);
  }

  matches(path: AbsolutePath, home: AbsolutePath): boolean {
    if (this.exceptWithin?.contains(path) === true) return false;
    return this.pattern.matches(path, home);
  }

  toString(): string {
    const except = this.exceptWithin ? ` except ${this.exceptWithin.value}` : '';
    return `deny ${this.access} ${this.pattern.raw}${except} (${this.sourceId})`;
  }
}
