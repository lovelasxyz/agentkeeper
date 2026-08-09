import { access, constants, realpath } from 'node:fs/promises';
import { delimiter } from 'node:path';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

const WINDOWS_EXTENSIONS = ['.exe', '.cmd', '.bat', '.com'] as const;

/** Resolves original agent CLIs before agentkeeper prepends its shim directory. */
export class ExecutableResolver {
  async resolve(
    executable: string,
    searchPath: string,
    excludedRoots: readonly AbsolutePath[] = [],
  ): Promise<AbsolutePath | null> {
    if (executable.length === 0 || /[\0\n\r]/.test(executable)) return null;

    const direct = this.directCandidate(executable);
    const candidates =
      direct === null
        ? this.pathCandidates(executable, searchPath)
        : [direct];
    const results = await Promise.all(
      candidates.map(async (candidate) => {
        if (excludedRoots.some((root) => root.contains(candidate))) return null;
        try {
          await access(
            candidate.value,
            process.platform === 'win32' ? constants.F_OK : constants.X_OK,
          );
          return AbsolutePath.of(await realpath(candidate.value));
        } catch {
          return null;
        }
      }),
    );
    return results.find((candidate): candidate is AbsolutePath => candidate !== null) ?? null;
  }

  async resolveMany(
    executables: readonly string[],
    searchPath: string,
    excludedRoots: readonly AbsolutePath[] = [],
  ): Promise<Readonly<Record<string, AbsolutePath>>> {
    const resolved = await Promise.all(
      executables.map(async (name) => [
        name,
        await this.resolve(name, searchPath, excludedRoots),
      ] as const),
    );
    return Object.freeze(
      Object.fromEntries(
        resolved.filter(
          (entry): entry is readonly [string, AbsolutePath] => entry[1] !== null,
        ),
      ),
    );
  }

  private directCandidate(executable: string): AbsolutePath | null {
    try {
      return AbsolutePath.of(executable);
    } catch {
      return null;
    }
  }

  private pathCandidates(executable: string, searchPath: string): AbsolutePath[] {
    const separator = process.platform === 'win32' ? ';' : delimiter;
    const extensions =
      process.platform === 'win32' && !/\.[a-z0-9]+$/i.test(executable)
        ? WINDOWS_EXTENSIONS
        : [''];
    const candidates: AbsolutePath[] = [];
    for (const directory of searchPath.split(separator)) {
      if (directory.length === 0) continue;
      let root: AbsolutePath;
      try {
        root = AbsolutePath.of(directory);
      } catch {
        continue;
      }
      for (const extension of extensions) candidates.push(root.join(`${executable}${extension}`));
    }
    return candidates;
  }
}
