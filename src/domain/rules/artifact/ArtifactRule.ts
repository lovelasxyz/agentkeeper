import { Rule } from '../Rule.js';
import type { Artifact } from '../../entities/Artifact.js';

/**
 * Base for rules that read a file in the repository.
 *
 * Adds nothing but path matching, deliberately: every judgement stays in the
 * subclass, and the shared code is the part that would otherwise be copied
 * nineteen times and get subtly different each time.
 */
export abstract class ArtifactRule extends Rule<Artifact> {
  /** Workspace-relative globs this rule reads, e.g. `.claude/settings*.json`. */
  protected abstract readonly paths: readonly string[];

  override appliesTo(artifact: Artifact): boolean {
    return this.paths.some((pattern) => matchRelative(pattern, artifact.relativePath));
  }

  /** Reads a nested value out of parsed JSON without trusting any of its shape. */
  protected static at(value: unknown, ...keys: readonly string[]): unknown {
    let current = value;
    for (const key of keys) {
      if (typeof current !== 'object' || current === null) return undefined;
      current = (current as Record<string, unknown>)[key];
    }
    return current;
  }

  protected static isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }
}

/**
 * Same three constructs as `PathPattern`, applied to a workspace-relative path.
 *
 * Case-insensitive, and that is a security decision rather than convenience.
 * Windows paths reach the domain already lower-cased, so an exact match made
 * every `CLAUDE.md`/`AGENTS.md` rule unreachable on that platform — vector V3
 * undetected across a whole OS. Matching more broadly can only add findings a
 * human then reviews; matching less can only hide an attack.
 */
export function matchRelative(pattern: string, relativePath: string): boolean {
  const patternSegments = pattern.toLowerCase().split('/');
  const pathSegments = relativePath.toLowerCase().split('/');
  return match(patternSegments, 0, pathSegments, 0);
}

function match(
  pattern: readonly string[],
  pi: number,
  target: readonly string[],
  ti: number,
): boolean {
  if (pi === pattern.length) return ti === target.length;
  const head = pattern[pi];

  if (head === '**') {
    for (let skip = ti; skip <= target.length; skip += 1) {
      if (match(pattern, pi + 1, target, skip)) return true;
    }
    return false;
  }

  const segment = target[ti];
  if (segment === undefined || head === undefined) return false;
  if (!matchSegment(head, segment)) return false;
  return match(pattern, pi + 1, target, ti + 1);
}

function matchSegment(pattern: string, segment: string): boolean {
  if (!pattern.includes('*')) return pattern === segment;
  const [first = '', ...rest] = pattern.split('*');
  const last = rest[rest.length - 1] ?? '';
  return (
    segment.startsWith(first) &&
    segment.endsWith(last) &&
    segment.length >= first.length + last.length
  );
}
