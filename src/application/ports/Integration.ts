import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

/**
 * One file an install step would change, with both sides shown.
 *
 * Spec §10.1 requires a line-by-line diff and confirmation before anything is
 * touched. Describing the change instead of performing it is what makes that
 * possible — and what makes `uninstall` an exact inverse rather than a
 * best-effort cleanup.
 */
export interface PlannedChange {
  readonly path: AbsolutePath;
  readonly before: string | null;
  readonly after: string | null;
  readonly summary: string;
}

/** Something `init` can set up and `uninstall` can take away again. */
export interface Integration {
  readonly id: string;
  readonly description: string;
  plan(): Promise<readonly PlannedChange[]>;
  uninstallPlan(): Promise<readonly PlannedChange[]>;
  isInstalled(): Promise<boolean>;
}
