import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { StarterProfile, type StarterProfileSpec } from '../../domain/policy/StarterProfile.js';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { FileSystem } from '../../application/ports/index.js';

/**
 * Loads the starter profiles shipped with the package (spec §4.4).
 *
 * They are data files under `profiles/`, extended by pull request, never
 * generated and never fetched — there is no network in this runtime at all.
 */
export class ProfileLoader {
  constructor(
    private readonly files: FileSystem,
    private readonly directory: AbsolutePath = defaultProfileDirectory(),
  ) {}

  async load(id: string): Promise<StarterProfile> {
    const raw = await this.files.read(this.directory.join(`${id}.json`));
    if (raw === null) {
      throw new Error(
        `Unknown starter profile "${id}". Available: ${(await this.available()).join(', ')}`,
      );
    }
    return StarterProfile.fromSpec(JSON.parse(raw) as StarterProfileSpec);
  }

  async available(): Promise<readonly string[]> {
    const entries = await this.files.list(this.directory, { maxEntries: 50 });
    return entries
      .filter((path) => path.basename.endsWith('.json'))
      .map((path) => path.basename.replace(/\.json$/, ''))
      .sort();
  }
}

function defaultProfileDirectory(): AbsolutePath {
  // dist/infrastructure/config/ProfileLoader.js → package root → profiles/
  const here = dirname(fileURLToPath(import.meta.url));
  return AbsolutePath.of(join(here, '..', '..', '..', 'profiles'));
}
