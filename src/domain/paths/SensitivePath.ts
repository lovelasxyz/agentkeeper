import { AccessTier, type AccessTierLevel } from '../value-objects/AccessTier.js';
import { Disposition, type DispositionName } from '../value-objects/Disposition.js';
import { PathPattern } from '../value-objects/PathPattern.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { Platform } from '../value-objects/Platform.js';
import type { PathContext } from './PathContext.js';

export type SensitiveCategory = 'credential' | 'persistence' | 'history' | 'config';
export type Access = 'read' | 'write';

/** Plain data shape of a registry row (spec §6.4). */
export interface SensitivePathSpec {
  readonly id: string;
  readonly pattern: string;
  readonly category: SensitiveCategory;
  /**
   * Access tier per operation, because the two genuinely differ. Reading
   * `~/.gitconfig` is what makes `git` work at all and costs little; writing it
   * installs `core.hooksPath` and is vector V9. One tier per row could only be
   * wrong in one of the two directions.
   */
  readonly readTier: AccessTierLevel;
  readonly writeTier: AccessTierLevel;
  readonly onRead: DispositionName;
  readonly onWrite: DispositionName;
  readonly platforms: readonly Platform[];
  readonly rationale: string;
  /**
   * Only sensitive outside the current workspace. `.env` is the motivating
   * case: the project's own `.env` is the agent's job, the neighbour's is theft.
   */
  readonly outsideWorkspaceOnly?: boolean;
}

export class SensitivePath {
  private constructor(
    readonly id: string,
    readonly pattern: PathPattern,
    readonly category: SensitiveCategory,
    readonly readTier: AccessTier,
    readonly writeTier: AccessTier,
    readonly onRead: Disposition,
    readonly onWrite: Disposition,
    readonly platforms: readonly Platform[],
    readonly rationale: string,
    readonly outsideWorkspaceOnly: boolean,
  ) {
    Object.freeze(this);
  }

  static fromSpec(spec: SensitivePathSpec): SensitivePath {
    return new SensitivePath(
      spec.id,
      PathPattern.of(spec.pattern),
      spec.category,
      AccessTier.ofLevel(spec.readTier),
      AccessTier.ofLevel(spec.writeTier),
      Disposition.of(spec.onRead),
      Disposition.of(spec.onWrite),
      Object.freeze([...spec.platforms]),
      spec.rationale,
      spec.outsideWorkspaceOnly ?? false,
    );
  }

  tierFor(access: Access): AccessTier {
    return access === 'read' ? this.readTier : this.writeTier;
  }

  dispositionFor(access: Access): Disposition {
    return access === 'read' ? this.onRead : this.onWrite;
  }

  appliesOn(platform: Platform): boolean {
    return this.platforms.includes(platform);
  }

  matches(path: AbsolutePath, context: PathContext): boolean {
    if (!this.appliesOn(context.platform)) return false;
    if (this.outsideWorkspaceOnly && context.workspace.contains(path)) return false;
    return this.pattern.matches(path, context.home);
  }

  /** Fixed anchor of the pattern, when it has one. Used to seed deny rules. */
  literalPrefix(home: AbsolutePath): AbsolutePath | null {
    return this.pattern.literalPrefix(home);
  }

  /** Whether a watcher must recurse below the anchor to cover this entry. */
  descendsBelowPrefix(): boolean {
    return this.pattern.descendsBelowPrefix();
  }

  toString(): string {
    return `${this.id} (${this.pattern.raw})`;
  }
}
