import { lstat, readdir } from 'node:fs/promises';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import type { ResourceScope } from '../../domain/value-objects/ResourceRef.js';
import type { WindowsReadDenyScan } from './WindowsPolicyTranslator.js';

const MAX_DISCOVERY_ENTRIES = 50_000;
const MAX_DISCOVERY_DEPTH = 24;

export interface WindowsTreeEntry {
  readonly path: AbsolutePath;
  readonly directory: boolean;
}

export interface WindowsDeniedResource {
  readonly scope: ResourceScope;
  readonly path: string;
  readonly access: 'read' | 'write';
}

export class WindowsPolicyDiscoveryError extends Error {
  readonly code = 'windows.policy-discovery-failed' as const;

  constructor(message: string) {
    super(message);
    this.name = 'WindowsPolicyDiscoveryError';
  }
}

type TreeLister = (root: AbsolutePath) => Promise<readonly WindowsTreeEntry[]>;

/** Resolves read-only glob refusals to exact objects before any child starts. */
export class WindowsReadDenyScanner {
  constructor(private readonly listTree: TreeLister = boundedTree) {}

  async scan(
    scans: readonly WindowsReadDenyScan[],
    policy: SandboxPolicy,
    context: PathContext,
  ): Promise<readonly WindowsDeniedResource[]> {
    const denied: WindowsDeniedResource[] = [];
    const deniedSubtrees: AbsolutePath[] = [];

    for (const scan of scans) {
      const entries = [...(await this.listTree(scan.root.path))].sort(
        (left, right) => left.path.segments.length - right.path.segments.length,
      );
      for (const entry of entries) {
        if (!scan.root.path.contains(entry.path)) {
          throw new WindowsPolicyDiscoveryError(
            `Deny discovery escaped its granted root ${scan.root.path.value}.`,
          );
        }
        if (deniedSubtrees.some((root) => root.contains(entry.path))) continue;
        if (isOverridden(entry.path, policy)) continue;
        if (!scan.denies.some((deny) => deny.matches(entry.path, context.home))) continue;

        const resource: WindowsDeniedResource = {
          scope: entry.directory ? 'subtree' : 'file',
          path: entry.path.value,
          access: 'read',
        };
        if (!denied.some((candidate) => sameResource(candidate, resource))) denied.push(resource);
        if (entry.directory) deniedSubtrees.push(entry.path);
      }
    }
    return Object.freeze(denied);
  }
}

function isOverridden(path: AbsolutePath, policy: SandboxPolicy): boolean {
  return policy.overrides.some(
    (override) => override.access === 'read' && override.ref.covers(path),
  );
}

function sameResource(left: WindowsDeniedResource, right: WindowsDeniedResource): boolean {
  return left.scope === right.scope && left.path === right.path && left.access === right.access;
}

async function boundedTree(root: AbsolutePath): Promise<readonly WindowsTreeEntry[]> {
  const entries: WindowsTreeEntry[] = [];

  const walk = async (path: AbsolutePath, depth: number): Promise<void> => {
    if (depth > MAX_DISCOVERY_DEPTH) {
      throw new WindowsPolicyDiscoveryError(
        `Deny discovery exceeded depth ${MAX_DISCOVERY_DEPTH} under ${root.value}.`,
      );
    }
    if (entries.length >= MAX_DISCOVERY_ENTRIES) {
      throw new WindowsPolicyDiscoveryError(
        `Deny discovery exceeded ${MAX_DISCOVERY_ENTRIES} entries under ${root.value}.`,
      );
    }

    let info;
    try {
      info = await lstat(path.value);
    } catch (error) {
      if (isMissing(error) && path.equals(root)) return;
      throw new WindowsPolicyDiscoveryError(
        `Could not inspect ${path.value} while compiling Windows deny rules.`,
      );
    }
    if (info.isSymbolicLink()) {
      throw new WindowsPolicyDiscoveryError(
        `Refusing a symbolic link in Windows deny discovery: ${path.value}.`,
      );
    }
    const directory = info.isDirectory();
    entries.push({ path, directory });
    if (!directory) return;

    let children;
    try {
      children = await readdir(path.value, { withFileTypes: true });
    } catch {
      throw new WindowsPolicyDiscoveryError(
        `Could not enumerate ${path.value} while compiling Windows deny rules.`,
      );
    }
    for (const child of children) {
      if (child.isSymbolicLink()) {
        throw new WindowsPolicyDiscoveryError(
          `Refusing a symbolic link in Windows deny discovery: ${path.join(child.name).value}.`,
        );
      }
      if (!child.isDirectory() && !child.isFile()) continue;
      await walk(path.join(child.name), depth + 1);
    }
  };

  await walk(root, 0);
  return entries;
}

function isMissing(error: unknown): boolean {
  return (
    error instanceof Error &&
    'code' in error &&
    (error as NodeJS.ErrnoException).code === 'ENOENT'
  );
}
