import { AbsolutePath } from './AbsolutePath.js';

const RECURSIVE = '**';

/**
 * A glob over absolute paths, with exactly three constructs and no regex
 * escape hatch:
 *
 *   - `*`  matches any characters inside one segment, never crossing `/`
 *   - `**` matches zero or more whole segments
 *   - everything else is literal
 *
 * `**` matching *zero* segments is deliberate: `~/.ssh/**` has to protect
 * `~/.ssh` itself, otherwise listing the directory slips past a rule that
 * looks like it covers the whole subtree.
 *
 * Patterns must be anchored — absolute (`/etc/shadow`), home-relative
 * (`~/.ssh/**`) or recursive from the root (`**\/.env`). An unanchored
 * pattern is a bug, not a convenience.
 */
export class PathPattern {
  private constructor(
    readonly raw: string,
    private readonly segments: readonly string[],
    private readonly homeAnchored: boolean,
  ) {
    Object.freeze(this);
  }

  static of(raw: string): PathPattern {
    if (raw.includes('\0')) {
      throw new Error(`Pattern contains a NUL byte: ${JSON.stringify(raw)}`);
    }
    const homeAnchored = raw === '~' || raw.startsWith('~/');
    const body = homeAnchored ? raw.slice(1).replace(/^\//, '') : raw.replace(/^\//, '');
    if (!homeAnchored && !raw.startsWith('/') && !raw.startsWith(RECURSIVE)) {
      throw new Error(
        `Pattern must be anchored to "/", "~/" or "**": ${JSON.stringify(raw)}`,
      );
    }
    const segments = body.split('/').filter((segment) => segment.length > 0);
    return new PathPattern(raw, segments, homeAnchored);
  }

  matches(path: AbsolutePath, home: AbsolutePath): boolean {
    const target = this.homeAnchored ? relativeTo(home, path) : [...path.segments];
    if (target === null) return false;
    return matchSegments(this.segments, 0, target, 0);
  }

  /**
   * The wildcard-free head of the pattern, resolved against `home`. Used to
   * turn a protective pattern into a concrete sandbox rule; `null` when the
   * pattern begins with a wildcard and therefore has no fixed anchor.
   */
  literalPrefix(home: AbsolutePath): AbsolutePath | null {
    const literal: string[] = [];
    for (const segment of this.segments) {
      if (segment.includes('*')) break;
      literal.push(segment);
    }
    if (literal.length === 0) return this.homeAnchored ? home : null;
    const base = this.homeAnchored ? home : AbsolutePath.of('/');
    return base.join(...literal);
  }

  toString(): string {
    return this.raw;
  }
}

function relativeTo(home: AbsolutePath, path: AbsolutePath): string[] | null {
  if (!home.contains(path)) return null;
  return path.value === home.value ? [] : path.value.slice(home.value.length + 1).split('/');
}

/** Straightforward backtracking matcher; patterns are short and fixed at build time. */
function matchSegments(
  pattern: readonly string[],
  pi: number,
  target: readonly string[],
  ti: number,
): boolean {
  if (pi === pattern.length) return ti === target.length;

  const head = pattern[pi];
  if (head === RECURSIVE) {
    for (let skip = ti; skip <= target.length; skip += 1) {
      if (matchSegments(pattern, pi + 1, target, skip)) return true;
    }
    return false;
  }

  const segment = target[ti];
  if (segment === undefined || head === undefined) return false;
  if (!matchSegment(head, segment)) return false;
  return matchSegments(pattern, pi + 1, target, ti + 1);
}

function matchSegment(pattern: string, segment: string): boolean {
  if (!pattern.includes('*')) return pattern === segment;

  const parts = pattern.split('*');
  const first = parts[0] ?? '';
  const last = parts[parts.length - 1] ?? '';
  if (!segment.startsWith(first)) return false;
  if (segment.length < first.length + last.length) return false;
  if (!segment.endsWith(last)) return false;

  let cursor = first.length;
  for (let i = 1; i < parts.length - 1; i += 1) {
    const middle = parts[i] ?? '';
    if (middle.length === 0) continue;
    const found = segment.indexOf(middle, cursor);
    if (found === -1 || found + middle.length > segment.length - last.length) return false;
    cursor = found + middle.length;
  }
  return true;
}
