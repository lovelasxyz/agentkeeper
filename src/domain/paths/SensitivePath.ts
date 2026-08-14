import { AccessTier, type AccessTierLevel } from '../value-objects/AccessTier.js';
import { Disposition, type DispositionName } from '../value-objects/Disposition.js';
import { PathPattern } from '../value-objects/PathPattern.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { Platform } from '../value-objects/Platform.js';
import type { PathContext } from './PathContext.js';

export type SensitiveCategory = 'credential' | 'persistence' | 'history' | 'config';
export type Access = 'read' | 'write';

/**
 * What identifies a registry row regardless of category (spec §6.4). Tier and
 * disposition are deliberately absent here: for credential and history rows
 * they are implied, and implying them is what makes a weak row unwritable.
 */
export interface SensitivePathIdentity {
  readonly id: string;
  readonly pattern: string;
  readonly platforms: readonly Platform[];
  readonly rationale: string;
  /**
   * Only sensitive outside the current workspace. `.env` is the motivating
   * case: the project's own `.env` is the agent's job, the neighbour's is theft.
   */
  readonly outsideWorkspaceOnly?: boolean;
}

/**
 * Persistence rows are never writable at runtime; their read side differs.
 * The union makes the invariant structural: tier 2 pairs with `block`,
 * tier 1 never does, and no caller can write the two apart.
 */
export type PersistenceReadSide =
  | { readonly readTier: 2; readonly onRead: 'block' }
  | { readonly readTier: 1; readonly onRead: 'ask' | 'observe' };

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

  /** Credentials are never readable and never writable at runtime. There is no parameter to mistype. */
  static credential(identity: SensitivePathIdentity): SensitivePath {
    return SensitivePath.build('credential', identity, 2, 2, 'block', 'block');
  }

  /** Shell and REPL history: the same construction contract as credentials. */
  static history(identity: SensitivePathIdentity): SensitivePath {
    return SensitivePath.build('history', identity, 2, 2, 'block', 'block');
  }

  /** Persistence is never writable at runtime; only the read side is chosen per entry. */
  static persistence(identity: SensitivePathIdentity & PersistenceReadSide): SensitivePath {
    return SensitivePath.build('persistence', identity, identity.readTier, 2, identity.onRead, 'block');
  }

  /** Ordinary developer configuration states every guarantee explicitly. */
  static configuration(
    identity: SensitivePathIdentity & {
      readonly readTier: AccessTierLevel;
      readonly writeTier: AccessTierLevel;
      readonly onRead: DispositionName;
      readonly onWrite: DispositionName;
    },
  ): SensitivePath {
    return SensitivePath.build(
      'config',
      identity,
      identity.readTier,
      identity.writeTier,
      identity.onRead,
      identity.onWrite,
    );
  }

  private static build(
    category: SensitiveCategory,
    identity: SensitivePathIdentity,
    readTier: AccessTierLevel,
    writeTier: AccessTierLevel,
    onRead: DispositionName,
    onWrite: DispositionName,
  ): SensitivePath {
    // The constructors make this unreachable for typed callers; the guard is
    // for the untyped boundary, where a hand-edited row must still fail loudly.
    if ((readTier === 2) !== (onRead === 'block') || (writeTier === 2) !== (onWrite === 'block')) {
      throw new Error(`${identity.id}: tier 2 requires block, and block requires tier 2`);
    }
    return new SensitivePath(
      identity.id,
      PathPattern.of(identity.pattern),
      category,
      AccessTier.ofLevel(readTier),
      AccessTier.ofLevel(writeTier),
      Disposition.of(onRead),
      Disposition.of(onWrite),
      Object.freeze([...identity.platforms]),
      identity.rationale,
      identity.outsideWorkspaceOnly ?? false,
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
