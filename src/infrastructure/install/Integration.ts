import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { FileSystem } from '../../application/ports/index.js';

export type { Integration, PlannedChange } from '../../application/ports/Integration.js';

export const MARKER_START = '# >>> agentkeeper >>>';
export const MARKER_END = '# <<< agentkeeper <<<';

/**
 * Wraps a shell snippet in removable markers.
 *
 * The irony is acknowledged in the README and in the prompt the user sees:
 * writing to `~/.zshrc` is exactly vector V9. That is why it is one line
 * pointing at a separate file, wrapped in markers, shown as a diff, and
 * removable exactly.
 */
export function withMarkers(body: string): string {
  return `${MARKER_START}\n${body}\n${MARKER_END}\n`;
}

export function stripMarkers(content: string): string {
  const start = content.indexOf(MARKER_START);
  if (start === -1) return content;
  const end = content.indexOf(MARKER_END, start);
  if (end === -1) return content;
  const after = content.slice(end + MARKER_END.length).replace(/^\n/, '');
  return `${content.slice(0, start)}${after}`;
}

export function hasMarkers(content: string | null): boolean {
  return content !== null && content.includes(MARKER_START);
}

export async function readOrNull(
  files: FileSystem,
  path: AbsolutePath,
): Promise<string | null> {
  return files.read(path);
}
