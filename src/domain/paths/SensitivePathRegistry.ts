import { SensitivePath, type Access, type SensitivePathSpec } from './SensitivePath.js';
import { SENSITIVE_PATHS } from './registry.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { Platform } from '../value-objects/Platform.js';
import type { PathContext } from './PathContext.js';

/**
 * Registry pattern (spec §8.3): one place that answers "is this path
 * sensitive, and how badly". Constructed from data so tests can swap in a
 * fixture set without touching any rule.
 */
export class SensitivePathRegistry {
  private constructor(private readonly entries: readonly SensitivePath[]) {
    Object.freeze(this);
  }

  static default(): SensitivePathRegistry {
    return SensitivePathRegistry.fromSpecs(SENSITIVE_PATHS);
  }

  static fromSpecs(specs: readonly SensitivePathSpec[]): SensitivePathRegistry {
    const entries = specs.map((spec) => SensitivePath.fromSpec(spec));
    const duplicate = findDuplicateId(entries);
    if (duplicate) throw new Error(`Duplicate sensitive path id: ${duplicate}`);
    return new SensitivePathRegistry(Object.freeze(entries));
  }

  all(): readonly SensitivePath[] {
    return this.entries;
  }

  forPlatform(platform: Platform): readonly SensitivePath[] {
    return this.entries.filter((entry) => entry.appliesOn(platform));
  }

  /** Every entry that claims the given path, in registry order. */
  matching(path: AbsolutePath, context: PathContext): readonly SensitivePath[] {
    return this.entries.filter((entry) => entry.matches(path, context));
  }

  byId(id: string): SensitivePath | null {
    return this.entries.find((entry) => entry.id === id) ?? null;
  }

  /** Tier 2 entries relevant to the platform — the source of the deny list. */
  dangerousFor(platform: Platform, access: Access): readonly SensitivePath[] {
    return this.forPlatform(platform).filter((entry) => entry.tierFor(access).level === 2);
  }
}

function findDuplicateId(entries: readonly SensitivePath[]): string | null {
  const seen = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.id)) return entry.id;
    seen.add(entry.id);
  }
  return null;
}
