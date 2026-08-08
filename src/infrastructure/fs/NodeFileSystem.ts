import { randomBytes } from 'node:crypto';
import { appendFile, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import { RealPathResolver } from './RealPathResolver.js';
import type { FileStat, FileSystem, ListOptions } from '../../application/ports/index.js';

/** Directories never worth walking when scanning a workspace. */
const DEFAULT_IGNORES = [
  'node_modules',
  '.venv',
  'venv',
  'dist',
  'build',
  'target',
  'vendor',
  '.next',
  '.turbo',
  '.cache',
  'coverage',
];

const MAX_ARTIFACT_BYTES = 512 * 1024;

export class NodeFileSystem implements FileSystem {
  constructor(private readonly realPaths = new RealPathResolver()) {}

  async read(path: AbsolutePath): Promise<string | null> {
    try {
      const info = await stat(path.value);
      // A rule reads text. Anything this large is a build artifact, and holding
      // it in memory would blow the scan budget for no benefit.
      if (info.size > MAX_ARTIFACT_BYTES) return null;
      return await readFile(path.value, 'utf8');
    } catch {
      return null;
    }
  }

  /** Atomic write (spec §10.4): a crash must not leave a half-written allowlist. */
  async write(path: AbsolutePath, content: string, mode = 0o600): Promise<void> {
    await this.makeDirectory(path.parent);
    const temporary = `${path.value}.${randomBytes(6).toString('hex')}.tmp`;
    await writeFile(temporary, content, { mode });
    await rename(temporary, path.value);
  }

  async append(path: AbsolutePath, content: string): Promise<void> {
    await this.makeDirectory(path.parent);
    await appendFile(path.value, content, { mode: 0o600 });
  }

  async exists(path: AbsolutePath): Promise<boolean> {
    return (await this.stat(path)) !== null;
  }

  async stat(path: AbsolutePath): Promise<FileStat | null> {
    try {
      const info = await stat(path.value);
      return {
        isDirectory: info.isDirectory(),
        size: info.size,
        modifiedAt: info.mtime,
      };
    } catch {
      return null;
    }
  }

  async makeDirectory(path: AbsolutePath): Promise<void> {
    await mkdir(path.value, { recursive: true, mode: 0o700 });
  }

  async remove(path: AbsolutePath): Promise<void> {
    await rm(path.value, { recursive: true, force: true });
  }

  async list(root: AbsolutePath, options: ListOptions = {}): Promise<readonly AbsolutePath[]> {
    const ignores = new Set(options.ignoreDirectories ?? DEFAULT_IGNORES);
    const limit = options.maxEntries ?? 20_000;
    const found: AbsolutePath[] = [];

    const walk = async (directory: AbsolutePath, depth: number): Promise<void> => {
      if (found.length >= limit || depth > 12) return;

      let entries;
      try {
        entries = await readdir(directory.value, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (found.length >= limit) return;
        const child = directory.join(entry.name);

        if (entry.isDirectory()) {
          // `.git` is walked deliberately: `.git/hooks` is vector V1.
          if (ignores.has(entry.name)) continue;
          await walk(child, depth + 1);
          continue;
        }
        if (entry.isFile()) found.push(child);
      }
    };

    await walk(root, 0);
    return found;
  }

  realPath(path: AbsolutePath): AbsolutePath {
    return this.realPaths.resolve(path);
  }
}
