import { realpathSync } from 'node:fs';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

/**
 * Resolves symlinks before a path is allowed into a policy.
 *
 * Not a nicety. The kernel enforces the sandbox against *resolved* paths, so on
 * macOS a rule written for `/var/folders/...` never fires — the real path is
 * `/private/var/folders/...`. A policy built from unresolved paths looks
 * correct in every unit test and protects nothing at runtime, which is the
 * worst failure this project can have.
 */
export class RealPathResolver {
  resolve(path: AbsolutePath): AbsolutePath {
    try {
      return AbsolutePath.of(realpathSync(path.value));
    } catch {
      // The target may not exist yet (a temp dir, a state dir on first run).
      // Resolve the deepest existing ancestor and re-attach the missing tail.
      return this.resolveNearestExisting(path);
    }
  }

  resolveAll(paths: readonly AbsolutePath[]): readonly AbsolutePath[] {
    return paths.map((path) => this.resolve(path));
  }

  private resolveNearestExisting(path: AbsolutePath): AbsolutePath {
    const tail: string[] = [];
    let current = path;

    while (current.value !== '/') {
      const parent = current.parent;
      tail.unshift(current.basename);
      try {
        return AbsolutePath.of(realpathSync(parent.value)).join(...tail);
      } catch {
        current = parent;
      }
    }
    return path;
  }
}
