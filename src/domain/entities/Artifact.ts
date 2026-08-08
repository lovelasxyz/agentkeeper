import { ContentHash } from '../value-objects/ContentHash.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';

export interface ArtifactProps {
  readonly path: AbsolutePath;
  readonly workspace: AbsolutePath;
  readonly content: string;
  /**
   * Hash recorded the last time this file was scanned, when there is one.
   * Supplied by the caller rather than looked up, so drift detection costs the
   * rules no I/O and stays a pure comparison.
   */
  readonly previousHash?: ContentHash | null;
}

/**
 * A file, already read, handed to the rules.
 *
 * Spec §8.3: a `Rule` never touches the filesystem. It receives path, content
 * and hash, which is why every rule in this project is tested with a string in
 * and an array out — no fixtures on disk, no mocks, no I/O in the hot path of
 * a hook that has a 50 ms budget.
 */
export class Artifact {
  readonly path: AbsolutePath;
  readonly workspace: AbsolutePath;
  readonly content: string;
  readonly hash: ContentHash;
  readonly previousHash: ContentHash | null;

  private parsed: { ok: true; value: unknown } | { ok: false } | null = null;

  constructor(props: ArtifactProps) {
    this.path = props.path;
    this.workspace = props.workspace;
    this.content = props.content;
    this.hash = ContentHash.fromContent(props.content);
    this.previousHash = props.previousHash ?? null;
  }

  /** Workspace-relative path, which is what a user recognises in a message. */
  get relativePath(): string {
    if (!this.workspace.contains(this.path)) return this.path.value;
    if (this.workspace.equals(this.path)) return '.';
    return this.path.value.slice(this.workspace.value.length + 1);
  }

  get basename(): string {
    return this.path.basename;
  }

  /** Path segments relative to the workspace, for structural matching. */
  get relativeSegments(): readonly string[] {
    return this.relativePath.split('/');
  }

  lines(): readonly string[] {
    return this.content.split(/\r?\n/);
  }

  /** Parsed JSON, or `null` when the file is not valid JSON. Parsed at most once. */
  json(): unknown {
    if (this.parsed === null) {
      try {
        this.parsed = { ok: true, value: JSON.parse(stripJsonComments(this.content)) as unknown };
      } catch {
        this.parsed = { ok: false };
      }
    }
    return this.parsed.ok ? this.parsed.value : null;
  }

  toString(): string {
    return this.relativePath;
  }
}

/**
 * VS Code and several agents accept JSONC. Comments are stripped rather than
 * treated as a parse failure, because "it did not look like JSON" is not a
 * reason to stop inspecting a file that will be executed.
 */
function stripJsonComments(text: string): string {
  let result = '';
  let inString = false;
  let escaped = false;
  let index = 0;

  while (index < text.length) {
    const char = text[index] as string;

    if (inString) {
      result += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') inString = false;
      index += 1;
      continue;
    }

    if (char === '"') {
      inString = true;
      result += char;
      index += 1;
      continue;
    }

    if (char === '/' && text[index + 1] === '/') {
      while (index < text.length && text[index] !== '\n') index += 1;
      continue;
    }

    if (char === '/' && text[index + 1] === '*') {
      index += 2;
      while (index < text.length && !(text[index] === '*' && text[index + 1] === '/')) index += 1;
      index += 2;
      continue;
    }

    result += char;
    index += 1;
  }
  return result;
}
