import { randomBytes } from 'node:crypto';
import {
  appendFile,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
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

export class FileListingLimitError extends Error {
  constructor(readonly root: AbsolutePath, readonly limit: number, readonly kind: 'entries' | 'depth') {
    super(
      `Refusing a partial filesystem result for ${root.value}: ${kind} limit ${limit} was reached`,
    );
    this.name = 'FileListingLimitError';
  }
}

export type FileOperation = 'read' | 'stat' | 'list' | 'move';

export class FileSystemAccessError extends Error {
  readonly code: string | null;

  constructor(
    readonly operation: FileOperation,
    readonly path: AbsolutePath,
    cause: unknown,
  ) {
    const code = errorCode(cause);
    super(`${operation} failed for ${path.value}${code === null ? '' : ` (${code})`}`, { cause });
    this.name = 'FileSystemAccessError';
    this.code = code;
  }
}

export class NodeFileSystem implements FileSystem {
  constructor(private readonly realPaths = new RealPathResolver()) {}

  async read(path: AbsolutePath): Promise<string | null> {
    try {
      return await readFile(path.value, 'utf8');
    } catch (cause) {
      if (isMissing(cause)) return null;
      throw new FileSystemAccessError('read', path, cause);
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

  async move(source: AbsolutePath, destination: AbsolutePath): Promise<void> {
    try {
      await this.makeDirectory(destination.parent);
      await rename(source.value, destination.value);
    } catch (cause) {
      throw new FileSystemAccessError('move', source, cause);
    }
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
    } catch (cause) {
      if (isMissing(cause)) return null;
      throw new FileSystemAccessError('stat', path, cause);
    }
  }

  async makeDirectory(path: AbsolutePath): Promise<void> {
    await mkdir(path.value, { recursive: true, mode: 0o700 });
  }

  async makeTemporaryDirectory(parent: AbsolutePath, prefix: string): Promise<AbsolutePath> {
    if (!/^[a-z0-9][a-z0-9-]*-$/i.test(prefix)) {
      throw new Error(`Unsafe temporary-directory prefix: ${JSON.stringify(prefix)}`);
    }
    await mkdir(parent.value, { recursive: true, mode: 0o700 });
    const created = AbsolutePath.of(await mkdtemp(parent.join(prefix).value));
    // mkdtemp normally honours 0700 already; chmod makes the invariant
    // explicit even under an unusual process umask.
    if (process.platform !== 'win32') await chmod(created.value, 0o700);
    return this.realPath(created);
  }

  async remove(path: AbsolutePath): Promise<void> {
    await rm(path.value, { recursive: true, force: true });
  }

  async list(root: AbsolutePath, options: ListOptions = {}): Promise<readonly AbsolutePath[]> {
    const ignores = new Set(options.ignoreDirectories ?? DEFAULT_IGNORES);
    const limit = options.maxEntries ?? 20_000;
    const maxDepth = options.maxDepth ?? 12;
    const found: AbsolutePath[] = [];

    const walk = async (directory: AbsolutePath, depth: number): Promise<void> => {
      if (found.length >= limit) {
        if (options.failOnLimit === true) throw new FileListingLimitError(root, limit, 'entries');
        return;
      }
      if (depth > maxDepth) {
        if (options.failOnLimit === true) {
          throw new FileListingLimitError(root, maxDepth, 'depth');
        }
        return;
      }

      let entries;
      try {
        entries = await readdir(directory.value, { withFileTypes: true });
      } catch (cause) {
        if (options.failOnError === true && !isMissing(cause)) {
          throw new FileSystemAccessError('list', directory, cause);
        }
        return;
      }

      for (const entry of entries) {
        if (found.length >= limit) {
          if (options.failOnLimit === true) {
            throw new FileListingLimitError(root, limit, 'entries');
          }
          return;
        }
        const child = directory.join(entry.name);

        if (entry.isDirectory()) {
          // `.git` is walked deliberately: `.git/hooks` is vector V1.
          if (ignores.has(entry.name)) continue;
          if (options.shouldDescend?.(child) === false) continue;
          await walk(child, depth + 1);
          continue;
        }
        if (entry.isFile() && options.includeFile?.(child) !== false) found.push(child);
      }
    };

    await walk(root, 0);
    return found;
  }

  realPath(path: AbsolutePath): AbsolutePath {
    return this.realPaths.resolve(path);
  }
}

function errorCode(cause: unknown): string | null {
  if (typeof cause !== 'object' || cause === null || !('code' in cause)) return null;
  const code = (cause as { readonly code?: unknown }).code;
  return typeof code === 'string' ? code : null;
}

function isMissing(cause: unknown): boolean {
  const code = errorCode(cause);
  return code === 'ENOENT' || code === 'ENOTDIR';
}
