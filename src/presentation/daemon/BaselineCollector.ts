import { ContentHash } from '../../domain/value-objects/ContentHash.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { SensitivePathRegistry } from '../../domain/paths/SensitivePathRegistry.js';
import type { BaselineEntry, Clock, FileSystem } from '../../application/ports/index.js';

/**
 * Snapshots zone B — the persistence surfaces outside any repository (spec §5).
 *
 * Only files whose *anchor* is known are collected: the point is a short, quiet
 * list that changes roughly monthly, not a full home-directory index. Content
 * is hashed and discarded; the snapshot holds paths and digests only.
 */
export class BaselineCollector {
  constructor(
    private readonly files: FileSystem,
    private readonly registry: SensitivePathRegistry,
    private readonly clock: Clock,
  ) {}

  /** The concrete files zone B watches on this platform. */
  targets(context: PathContext): readonly AbsolutePath[] {
    const found = new Map<string, AbsolutePath>();

    for (const entry of this.registry.forPlatform(context.platform)) {
      if (entry.category !== 'persistence') continue;
      const anchor = entry.literalPrefix(context.home);
      if (anchor === null) continue;
      found.set(anchor.value, anchor);
    }
    return [...found.values()];
  }

  async collect(context: PathContext): Promise<readonly BaselineEntry[]> {
    const entries: BaselineEntry[] = [];

    for (const target of this.targets(context)) {
      const info = await this.files.stat(target);
      if (info === null) continue;

      if (info.isDirectory) {
        for (const child of await this.files.list(target, { maxEntries: 200 })) {
          const entry = await this.entryFor(child);
          if (entry !== null) entries.push(entry);
        }
        continue;
      }
      const entry = await this.entryFor(target);
      if (entry !== null) entries.push(entry);
    }
    return entries;
  }

  private async entryFor(path: AbsolutePath): Promise<BaselineEntry | null> {
    const content = await this.files.read(path);
    if (content === null) return null;
    return { path, hash: ContentHash.fromContent(content), recordedAt: this.clock.now() };
  }
}
