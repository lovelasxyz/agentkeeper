import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { FileSystem } from '../../application/ports/index.js';

export interface VersionedDocument {
  readonly version: number;
}

/**
 * Shared plumbing for the versioned JSON files in `~/.agentkeeper` (spec §10.4).
 *
 * A store that cannot be read is treated as empty rather than fatal, with one
 * exception made explicit at each call site: the allowlist. A corrupt allowlist
 * that silently reads as "no grants" would degrade safely; a corrupt one that
 * silently reads as "all grants" would not — so parsing is strict and the
 * caller decides.
 */
export class JsonDocument<T extends VersionedDocument> {
  constructor(
    private readonly files: FileSystem,
    private readonly path: AbsolutePath,
    private readonly currentVersion: number,
    private readonly empty: () => T,
  ) {}

  async load(): Promise<T> {
    const raw = await this.files.read(this.path);
    if (raw === null) return this.empty();

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new CorruptStoreError(this.path, (error as Error).message);
    }

    if (typeof parsed !== 'object' || parsed === null) {
      throw new CorruptStoreError(this.path, 'expected a JSON object');
    }

    const version = (parsed as VersionedDocument).version;
    if (version !== this.currentVersion) {
      throw new CorruptStoreError(
        this.path,
        `unsupported schema version ${String(version)}, expected ${this.currentVersion}`,
      );
    }
    return parsed as T;
  }

  async save(document: T): Promise<void> {
    await this.files.write(this.path, `${JSON.stringify(document, null, 2)}\n`);
  }

  get location(): AbsolutePath {
    return this.path;
  }
}

export class CorruptStoreError extends Error {
  constructor(
    readonly path: AbsolutePath,
    reason: string,
  ) {
    super(
      `${path.value} could not be read (${reason}). agentkeeper will not guess what it meant; ` +
        'fix the file or delete it to start from the default policy.',
    );
    this.name = 'CorruptStoreError';
  }
}
