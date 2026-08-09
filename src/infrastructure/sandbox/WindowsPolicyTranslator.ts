import type { PathContext } from '../../domain/paths/PathContext.js';
import type { DenyRule } from '../../domain/policy/DenyRule.js';
import type { SandboxPolicy } from '../../domain/policy/SandboxPolicy.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../domain/value-objects/ResourceRef.js';

const AGENT_STATE_DIRECTORIES = Object.freeze([
  '.claude',
  '.gemini',
  '.cursor',
  '.codex',
  '.config/claude',
]);

export interface WindowsReadDenyScan {
  readonly root: ResourceRef;
  readonly denies: readonly DenyRule[];
}

export interface WindowsRestrictedOverlay {
  readonly home: AbsolutePath;
  /** Empty by design: canonical settings, credentials and history never enter the sandbox. */
  readonly seedFiles: readonly AbsolutePath[];
  readonly directories: readonly AbsolutePath[];
}

export interface WindowsPolicyPlan {
  readonly reads: readonly ResourceRef[];
  readonly writes: readonly ResourceRef[];
  readonly readDenyScans: readonly WindowsReadDenyScan[];
  readonly overlay: WindowsRestrictedOverlay;
  readonly gaps: readonly string[];
}

/**
 * Produces the effective Windows profile without weakening the domain policy.
 *
 * Windows AppContainer path capabilities cannot subtract a glob from a writable
 * directory. Canonical agent state is therefore replaced by an empty, private,
 * disposable HOME. Agents can create their normal runtime state there, but
 * settings, credentials and persistence targets are neither copied in nor
 * synced back. Read-only trees are safe to grant after exact denied entries are
 * discovered and given explicit deny ACEs by the native launcher.
 */
export class WindowsPolicyTranslator {
  plan(
    policy: SandboxPolicy,
    context: PathContext,
    overlayHome: AbsolutePath,
  ): WindowsPolicyPlan {
    const canonicalAgentState = AGENT_STATE_DIRECTORIES.map((relative) =>
      context.home.join(relative),
    );
    const isCanonicalAgentRoot = (path: AbsolutePath): boolean =>
      canonicalAgentState.some((root) => root.equals(path));

    const reads = policy.reads.filter(
      (ref) => !isCanonicalAgentRoot(ref.path) && !isDeniedFile(ref, 'read', policy, context),
    );
    const writes = policy.writes.filter(
      (ref) => !isCanonicalAgentRoot(ref.path) && !isDeniedFile(ref, 'write', policy, context),
    );

    const gaps: string[] = [];
    if (context.platform !== 'win32') {
      gaps.push('The Windows restricted-profile translator can only enforce win32 policies.');
    }
    if (policy.network.length > 0) {
      gaps.push(
        'Windows AppContainer network access remains denied by default; destination rules ' +
          `${policy.network.map(String).join(', ')} require a broker and cannot be opened directly.`,
      );
    }

    for (const ref of writes) {
      if (isPrivateEphemeral(ref.path, context, overlayHome)) continue;
      for (const deny of policy.denies) {
        if (deny.access !== 'write' || isFullyOverridden(ref, deny, policy)) continue;
        if (!denyMayIntersect(ref, deny, context)) continue;
        gaps.push(
          `${deny.sourceId}: Windows AppContainer cannot safely subtract ` +
            `"${deny.pattern.raw}" from persistent writable subtree ${ref.path.value}. ` +
            'Use a private restricted profile or grant narrower mutable subpaths.',
        );
      }
    }

    const readDenyScans: WindowsReadDenyScan[] = [];
    for (const root of reads) {
      if (root.scope !== 'subtree' || isPrivateEphemeral(root.path, context, overlayHome)) continue;
      const denies = policy.denies.filter(
        (deny) =>
          deny.access === 'read' &&
          !isFullyOverridden(root, deny, policy) &&
          denyMayIntersect(root, deny, context),
      );
      if (denies.length > 0) readDenyScans.push({ root, denies });
    }

    const overlayDirectories = [
      overlayHome,
      ...AGENT_STATE_DIRECTORIES.map((relative) => overlayHome.join(relative)),
      overlayHome.join('tmp'),
    ];
    return {
      reads: deduplicate([...reads, ResourceRef.subtree(overlayHome)]),
      writes: deduplicate([...writes, ResourceRef.subtree(overlayHome)]),
      readDenyScans,
      overlay: {
        home: overlayHome,
        seedFiles: Object.freeze([]),
        directories: Object.freeze(overlayDirectories),
      },
      gaps: Object.freeze(gaps),
    };
  }
}

function isDeniedFile(
  ref: ResourceRef,
  access: 'read' | 'write',
  policy: SandboxPolicy,
  context: PathContext,
): boolean {
  if (ref.scope !== 'file') return false;
  if (policy.overrides.some((override) => override.access === access && override.ref.covers(ref.path))) {
    return false;
  }
  return policy.denies.some(
    (deny) => deny.access === access && deny.matches(ref.path, context.home),
  );
}

function isFullyOverridden(
  ref: ResourceRef,
  deny: DenyRule,
  policy: SandboxPolicy,
): boolean {
  return policy.overrides.some(
    (override) => override.access === deny.access && override.ref.subsumes(ref),
  );
}

function denyMayIntersect(ref: ResourceRef, deny: DenyRule, context: PathContext): boolean {
  if (deny.exceptWithin?.contains(ref.path) === true) return false;
  if (ref.scope === 'file') return deny.matches(ref.path, context.home);
  const prefix = deny.pattern.literalPrefix(context.home);
  if (prefix === null) return true;
  if (deny.exceptWithin?.contains(prefix) === true) return false;
  return ref.path.contains(prefix) || prefix.contains(ref.path);
}

function isPrivateEphemeral(
  path: AbsolutePath,
  context: PathContext,
  overlayHome: AbsolutePath,
): boolean {
  if (overlayHome.contains(path)) return true;
  const windowsTemp = context.home.join('AppData', 'Local', 'Temp');
  return windowsTemp.contains(path) && /^agentkeeper-[a-z0-9-]+$/i.test(path.basename);
}

function deduplicate(refs: readonly ResourceRef[]): readonly ResourceRef[] {
  const result: ResourceRef[] = [];
  for (const ref of refs) {
    if (!result.some((entry) => entry.equals(ref))) result.push(ref);
  }
  return Object.freeze(result);
}
