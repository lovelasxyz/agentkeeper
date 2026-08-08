import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { PlannedChange } from '../ports/Integration.js';
import type { AuditLog, Clock, FileSystem } from '../ports/index.js';

export interface AppliedChange {
  readonly path: AbsolutePath;
  readonly backup: AbsolutePath | null;
}

/**
 * Applies planned changes, keeping the original of everything it touches.
 *
 * `init` → `uninstall` returning the system to exactly its previous state is a
 * Definition-of-Done item (spec §16), and it is only achievable if the previous
 * state was saved at the moment it was replaced.
 */
export class ApplyChanges {
  constructor(
    private readonly files: FileSystem,
    private readonly backupDir: AbsolutePath,
    private readonly audit: AuditLog,
    private readonly clock: Clock,
  ) {}

  async execute(changes: readonly PlannedChange[]): Promise<readonly AppliedChange[]> {
    const applied: AppliedChange[] = [];

    for (const change of changes) {
      if (change.before === change.after) continue;

      const backup = change.before === null ? null : await this.backup(change);
      if (change.after === null) await this.files.remove(change.path);
      else await this.files.write(change.path, change.after, modeFor(change.path));

      await this.audit.append({
        at: this.clock.now(),
        event: 'install.change',
        details: {
          path: change.path.value,
          summary: change.summary,
          backup: backup?.value ?? null,
          removed: change.after === null,
        },
      });
      applied.push({ path: change.path, backup });
    }
    return applied;
  }

  /** Restores from the backups written by `execute`. */
  async revert(applied: readonly AppliedChange[]): Promise<void> {
    for (const change of [...applied].reverse()) {
      if (change.backup === null) {
        await this.files.remove(change.path);
        continue;
      }
      const original = await this.files.read(change.backup);
      if (original !== null) await this.files.write(change.path, original, modeFor(change.path));
    }
  }

  private async backup(change: PlannedChange): Promise<AbsolutePath> {
    const stamp = this.clock.now().toISOString().replace(/[:.]/g, '-');
    const name = `${stamp}--${change.path.value.replace(/\//g, '_')}`;
    const target = this.backupDir.join(name);
    await this.files.write(target, change.before as string);
    return target;
  }
}

/** Hook scripts have to be executable; state files must not be world-readable. */
function modeFor(path: AbsolutePath): number {
  return path.value.includes('/git-hooks/') ? 0o700 : 0o600;
}
