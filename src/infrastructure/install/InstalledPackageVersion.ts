import type { FileSystem } from '../../application/ports/index.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

/** How far above the entrypoint to look for the manifest: `<pkg>/dist/cli.js`
 * needs two, a source checkout entrypoint four. Never further. */
const MAX_MANIFEST_ASCENT = 5;

/**
 * The version of the package as installed on disk, read from the manifest
 * beside the running entrypoint.
 *
 * The daemon uses this to observe — not assume — that an upgrade replaced the
 * code underneath it: its own version is a build-time constant, and the only
 * honest source for "what should be running now" is the installed manifest.
 * `null` means no answer could be proven, which callers must treat as
 * "nothing to act on", never as "up to date".
 */
export async function installedPackageVersion(
  files: FileSystem,
  entrypoint: AbsolutePath,
): Promise<string | null> {
  for (
    let directory = entrypoint.parent, ascent = 0;
    ascent < MAX_MANIFEST_ASCENT && directory.value !== directory.parent.value;
    directory = directory.parent, ascent += 1
  ) {
    const raw = await files.read(directory.join('package.json'));
    if (raw === null) continue;
    const version = parseOwnManifestVersion(raw);
    if (version !== null) return version;
  }
  return null;
}

/** Only a manifest that is verifiably this package's own counts as an answer. */
function parseOwnManifestVersion(raw: string): string | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    const manifest = parsed as Record<string, unknown>;
    if (manifest['name'] !== 'agentkeeper') return null;
    const version = manifest['version'];
    return typeof version === 'string' && version.length > 0 ? version : null;
  } catch {
    return null;
  }
}

