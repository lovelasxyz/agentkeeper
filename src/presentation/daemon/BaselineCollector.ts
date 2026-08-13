import { ContentHash } from '../../domain/value-objects/ContentHash.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { SensitivePathRegistry } from '../../domain/paths/SensitivePathRegistry.js';
import type { WatchTarget } from '../../infrastructure/watch/NodeWatchService.js';
import type { BaselineEntry, Clock, FileSystem } from '../../application/ports/index.js';
import { mapWithConcurrency } from '../../application/services/BoundedConcurrency.js';

const BASELINE_IO_CONCURRENCY = 8;
// `.npmrc` is primarily a credential surface but its registry setting is also
// executable supply-chain state (AG-P007). Categorising it once must not make
// that persistence rule unreachable.
const PERSISTENCE_COMPANION_IDS = new Set(['npmrc']);
const SELF_MUTATING_STATE_FILES = new Set([
  'audit',
  'audit.log',
  'baseline.json',
  'persistence-pending.json',
  'pause.json',
]);

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
    return this.targetScopes(context).map((scope) => scope.anchor);
  }

  /**
   * Each watched anchor with the test that decides what belongs to it.
   *
   * The anchor of `~/.claude/settings*.json` is the whole `~/.claude`
   * directory, which holds thousands of session files. Collecting all of them
   * exceeded the listing limit and failed activation outright, and would have
   * baselined files that change every few minutes — a tamper signal that
   * screams constantly is the same as no signal.
   */
  private targetScopes(context: PathContext): readonly TargetScope[] {
    const found = new Map<string, TargetScope>();

    for (const entry of this.registry.forPlatform(context.platform)) {
      if (entry.category !== 'persistence' && !PERSISTENCE_COMPANION_IDS.has(entry.id)) continue;
      const anchor = entry.literalPrefix(context.home);
      if (anchor === null) continue;
      if (entry.id === 'agentkeeper-state') {
        // decisions/audit/baseline are intentionally mutable control-plane
        // files. Hashing them would make the daemon react to its own writes.
        // The paths below are configuration or checksum-managed code and must
        // remain stable outside explicit activate/repair operations.
        for (const relative of [
          'config.json',
          'allowlist.json',
          'installation/manifest.json',
          'installation/backups',
          'shell',
          'shims',
        ]) {
          const target = context.home.join('.agentkeeper', relative);
          // Checksum-managed code and configuration: every file under these
          // belongs to the baseline.
          found.set(target.value, { anchor: target, covers: () => true, recursive: true });
        }
        continue;
      }
      // Two entries can share an anchor (`~/.ssh/config` and `~/.ssh/**`).
      // Replacing the scope would silently drop the first one's files, so the
      // scopes are unioned: covered by either, recursive if either needs it.
      const existing = found.get(anchor.value);
      found.set(anchor.value, {
        anchor,
        covers:
          existing === undefined
            ? (path) => entry.matches(path, context)
            : (path) => existing.covers(path) || entry.matches(path, context),
        recursive: (existing?.recursive ?? false) || entry.descendsBelowPrefix(),
      });
    }
    return [...found.values()];
  }

  /**
   * Watch parent state changes, while collection excludes self-mutating files.
   *
   * Each target carries whether the watcher must recurse into it. `~/.claude`
   * is the anchor of `~/.claude/settings*.json` and holds thousands of session
   * directories; recursing into it exhausts the watcher's handle budget and
   * leaves every target registered after it — the other agents' configuration
   * — with no watch at all.
   */
  watchTargets(context: PathContext): readonly WatchTarget[] {
    const stateDir = context.home.join('.agentkeeper');
    const targets = this.targetScopes(context)
      .filter((scope) => !stateDir.contains(scope.anchor))
      .map((scope) => ({ path: scope.anchor, recursive: scope.recursive }));
    return [...targets, { path: stateDir, recursive: true }];
  }

  /**
   * Filters events produced by the daemon's own append/atomic-write cycle.
   * A null path is never guessed away: some watcher backends cannot provide a
   * filename and must conservatively trigger a comparison.
   */
  isRelevantWatchEvent(path: AbsolutePath | null, context: PathContext): boolean {
    if (path === null) return true;
    const stateDir = context.home.join('.agentkeeper');
    if (!stateDir.contains(path) || path.equals(stateDir)) return true;
    // NodeFileSystem's atomic staging file is not authoritative; the following
    // rename event for the real path is. Ignoring only its collision-resistant
    // suffix keeps a legitimate permanent `*.tmp` shim in scope.
    if (/\.[0-9a-f]{12}\.tmp$/i.test(path.basename)) return false;
    const relative = path.value.slice(stateDir.value.length + 1);
    const topLevel = relative.split('/')[0] ?? '';
    for (const mutable of SELF_MUTATING_STATE_FILES) {
      if (topLevel === mutable) return false;
      if (topLevel.startsWith(`${mutable}.`) && topLevel.endsWith('.tmp')) return false;
    }
    return true;
  }

  async collect(context: PathContext): Promise<readonly BaselineEntry[]> {
    const inspected = await mapWithConcurrency(
      this.targetScopes(context),
      BASELINE_IO_CONCURRENCY,
      async (scope) => ({ scope, info: await this.files.stat(scope.anchor) }),
    );
    const expanded = await mapWithConcurrency(
      inspected,
      BASELINE_IO_CONCURRENCY,
      async ({ scope, info }): Promise<readonly AbsolutePath[]> => {
        if (info === null) return [];
        if (!info.isDirectory) return [scope.anchor];
        try {
          return await this.files.list(scope.anchor, {
            maxEntries: 2_000,
            maxDepth: 8,
            failOnLimit: true,
            failOnError: true,
            // Only what the sensitive pattern actually names. Without this the
            // anchor of a file glob drags its whole directory into the baseline.
            includeFile: (path) => scope.covers(path),
          });
        } catch (error) {
          // A surface this process may never read — `/private/var/at/tabs`
          // needs root on macOS — contributes nothing at baseline time and
          // nothing at comparison time, so skipping it loses no tamper signal.
          // Aborting instead made `activate` fail on a stock machine. Any
          // other failure still stops the snapshot: a silently thin baseline
          // would read as "nothing changed" forever after.
          if (!isPermissionDenied(error)) throw error;
          return [];
        }
      },
    );
    const entries = await mapWithConcurrency(
      expanded.flat(),
      BASELINE_IO_CONCURRENCY,
      (path) => this.entryFor(path),
    );
    return entries.filter((entry): entry is BaselineEntry => entry !== null);
  }

  private async entryFor(path: AbsolutePath): Promise<BaselineEntry | null> {
    const content = await this.files.read(path);
    if (content === null) return null;
    return { path, hash: ContentHash.fromContent(content), recordedAt: this.clock.now() };
  }
}

/** Duck-typed on purpose: the port must not leak a concrete adapter's error class. */
function isPermissionDenied(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return code === 'EACCES' || code === 'EPERM';
}

/** A watched anchor and the test for what inside it belongs to the baseline. */
interface TargetScope {
  readonly anchor: AbsolutePath;
  readonly covers: (path: AbsolutePath) => boolean;
  /** Whether the watcher must recurse below the anchor to see what matters. */
  readonly recursive: boolean;
}
