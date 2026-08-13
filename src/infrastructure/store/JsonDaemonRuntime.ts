import type { FileSystem } from '../../application/ports/index.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

const MAX_RUNTIME_BYTES = 1_024;

/** What the resident watcher is actually running, as opposed to what is installed. */
export interface DaemonRuntimeRecord {
  readonly pid: number;
  readonly version: string;
  readonly startedAt: string;
}

/**
 * The resident watcher's self-report.
 *
 * Upgrading the package replaces the entrypoint on disk, but the running
 * daemon keeps executing the code it loaded at boot. Without this record the
 * CLI cannot tell the two apart, so a security fix that shipped hours ago can
 * sit inert while `doctor` reports a healthy installation — the false green
 * this product exists to refuse.
 */
export class JsonDaemonRuntime {
  private readonly path: AbsolutePath;

  constructor(
    private readonly files: FileSystem,
    stateDir: AbsolutePath,
  ) {
    this.path = stateDir.join('daemon.json');
  }

  async announce(record: DaemonRuntimeRecord): Promise<void> {
    await this.files.write(this.path, `${JSON.stringify(record, null, 2)}\n`);
  }

  /** `null` when no watcher has announced itself, or the record is unusable. */
  async read(): Promise<DaemonRuntimeRecord | null> {
    const info = await this.files.stat(this.path);
    if (info !== null && (info.isDirectory || info.size > MAX_RUNTIME_BYTES)) return null;
    const raw = await this.files.read(this.path);
    if (raw === null) return null;

    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed !== 'object' || parsed === null) return null;
      const record = parsed as Record<string, unknown>;
      const { pid, version, startedAt } = record;
      if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0) return null;
      if (typeof version !== 'string' || version.length === 0) return null;
      if (typeof startedAt !== 'string') return null;
      return { pid, version, startedAt };
    } catch {
      // A corrupt record must not be reported as a running watcher.
      return null;
    }
  }
}

/**
 * Whether a watcher is announced, alive, and running the installed code.
 *
 * A recorded pid that no longer exists means the watcher died; the record
 * outliving it is exactly the case that must not read as healthy.
 */
export function daemonRuntimeState(
  record: DaemonRuntimeRecord | null,
  installedVersion: string,
  isAlive: (pid: number) => boolean,
): 'absent' | 'stopped' | 'stale' | 'current' {
  if (record === null) return 'absent';
  if (!isAlive(record.pid)) return 'stopped';
  return record.version === installedVersion ? 'current' : 'stale';
}
