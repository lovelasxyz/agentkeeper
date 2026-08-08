import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { ContentHash } from '../value-objects/ContentHash.js';
import type { PathContext } from '../paths/PathContext.js';

export type ChangeKind = 'created' | 'modified' | 'deleted';

export interface BaselineChangeProps {
  readonly path: AbsolutePath;
  readonly kind: ChangeKind;
  readonly previousHash: ContentHash | null;
  readonly currentHash: ContentHash | null;
  /** Current contents, when the file is small enough and still readable. */
  readonly content: string | null;
  readonly context: PathContext;
  /**
   * Whether isolation was active when this happened. A persistence change that
   * lands while the sandbox is up means something got around it, which is a
   * different and much worse event (spec §6.6).
   */
  readonly sandboxActive: boolean;
}

/** One difference between the trusted snapshot and the system as it is now. */
export class BaselineChange {
  readonly path: AbsolutePath;
  readonly kind: ChangeKind;
  readonly previousHash: ContentHash | null;
  readonly currentHash: ContentHash | null;
  readonly content: string | null;
  readonly context: PathContext;
  readonly sandboxActive: boolean;

  constructor(props: BaselineChangeProps) {
    this.path = props.path;
    this.kind = props.kind;
    this.previousHash = props.previousHash;
    this.currentHash = props.currentHash;
    this.content = props.content;
    this.context = props.context;
    this.sandboxActive = props.sandboxActive;
    Object.freeze(this);
  }

  get display(): string {
    return this.path.toDisplay(this.context.home);
  }

  contains(needle: string | RegExp): boolean {
    if (this.content === null) return false;
    return typeof needle === 'string' ? this.content.includes(needle) : needle.test(this.content);
  }
}
