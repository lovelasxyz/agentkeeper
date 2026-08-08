import { DenyRule } from './DenyRule.js';
import { SandboxPolicy, type PolicyOverride } from './SandboxPolicy.js';
import { ResourceRef } from '../value-objects/ResourceRef.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { WorkspaceId } from '../value-objects/WorkspaceId.js';
import type { Grant } from '../entities/Grant.js';
import type { PathContext } from '../paths/PathContext.js';
import type { Access } from '../paths/SensitivePath.js';
import type { SensitivePathRegistry } from '../paths/SensitivePathRegistry.js';
import type { StarterProfile } from './StarterProfile.js';
import type { AccessTierResolver } from './AccessTierResolver.js';

export interface PolicyInput {
  readonly profile: StarterProfile;
  readonly grants: readonly Grant[];
  readonly context: PathContext;
  readonly workspaceId: WorkspaceId;
  /** Node installs and version managers — readable, never writable. */
  readonly toolchainRoots: readonly AbsolutePath[];
  /** agent-guard's own state. Never writable: that is AG-B005 made structural. */
  readonly stateDir: AbsolutePath;
  /** The agent's own state (session history, caches) — read and write. */
  readonly agentStateDirs: readonly AbsolutePath[];
  readonly tempDirs: readonly AbsolutePath[];
}

export type RejectionReason = 'tier-2-runtime-grant' | 'tier-2-resource' | 'out-of-scope';

export interface RejectedGrant {
  readonly resource: string;
  readonly access: Access;
  readonly reason: RejectionReason;
  readonly detail: string;
}

export interface PolicyBuildResult {
  readonly policy: SandboxPolicy;
  /** Everything that asked for access and did not get it. Surfaced, never swallowed. */
  readonly rejected: readonly RejectedGrant[];
}

/** Raised when the working directory is so broad that isolating it is meaningless. */
export class UnsafeWorkspaceError extends Error {
  constructor(
    readonly workspace: AbsolutePath,
    readonly swallowed: AbsolutePath,
    readonly sourceId: string,
  ) {
    super(
      `Refusing to isolate ${workspace.value}: it contains ${swallowed.value} (${sourceId}). ` +
        'The workspace is granted in full, so this would hand over the very files ' +
        'agent-guard exists to protect. Run the agent from a project directory instead.',
    );
    this.name = 'UnsafeWorkspaceError';
  }
}

/**
 * Turns "what this user does" into "what this process may touch" (spec §4.6).
 *
 * Builder pattern: no mutable state survives a call, and the whole thing is a
 * pure function of its input, which is why the security invariant of §4.5 can
 * be checked with a property test rather than hoped for.
 */
export class PolicyBuilder {
  constructor(
    private readonly tiers: AccessTierResolver,
    private readonly registry: SensitivePathRegistry,
  ) {}

  build(input: PolicyInput): PolicyBuildResult {
    const { context } = input;
    this.assertWorkspaceIsSane(context);
    const rejected: RejectedGrant[] = [];

    const reads: ResourceRef[] = [
      ResourceRef.subtree(context.workspace),
      ...input.toolchainRoots.map((path) => ResourceRef.subtree(path)),
      ...input.agentStateDirs.map((path) => ResourceRef.subtree(path)),
      ...input.tempDirs.map((path) => ResourceRef.subtree(path)),
      // Readable so the agent can be told what it is allowed to do; never writable.
      ResourceRef.subtree(input.stateDir),
    ];
    const writes: ResourceRef[] = [
      ResourceRef.subtree(context.workspace),
      ...input.agentStateDirs.map((path) => ResourceRef.subtree(path)),
      ...input.tempDirs.map((path) => ResourceRef.subtree(path)),
    ];

    this.collectProfile(input, reads, writes, rejected);

    const overrides: PolicyOverride[] = [];
    this.collectGrants(input, reads, writes, overrides, rejected);

    return {
      policy: new SandboxPolicy({
        workspace: context.workspace,
        reads,
        writes,
        denies: this.denyRules(context),
        overrides,
        network: input.profile.network,
      }),
      rejected,
    };
  }

  /**
   * The workspace is granted wholesale, so a workspace that contains the user's
   * credentials would hand them over by definition. Running the agent directly
   * in `~` is the realistic way that happens.
   *
   * Spec §4.6: the refusal is loud. Starting anyway with a hole this size would
   * leave the user believing they are protected, which is worse than not
   * running at all.
   */
  private assertWorkspaceIsSane(context: PathContext): void {
    const swallowed = this.registry
      .dangerousFor(context.platform, 'read')
      .map((entry) => ({ entry, anchor: entry.literalPrefix(context.home) }))
      .find(({ anchor }) => anchor !== null && context.workspace.contains(anchor));

    if (swallowed) {
      throw new UnsafeWorkspaceError(
        context.workspace,
        swallowed.anchor as AbsolutePath,
        swallowed.entry.id,
      );
    }
  }

  /** Trailing refusals derived from the registry — the same data the rules use. */
  private denyRules(context: PathContext): readonly DenyRule[] {
    const rules: DenyRule[] = [];
    for (const access of ['read', 'write'] as const) {
      for (const entry of this.registry.dangerousFor(context.platform, access)) {
        rules.push(
          new DenyRule(
            entry.id,
            entry.pattern,
            access,
            entry.rationale,
            entry.outsideWorkspaceOnly ? context.workspace : null,
          ),
        );
      }
    }
    return rules;
  }

  private collectProfile(
    input: PolicyInput,
    reads: ResourceRef[],
    writes: ResourceRef[],
    rejected: RejectedGrant[],
  ): void {
    const { context } = input;
    const add = (ref: ResourceRef, access: Access, target: ResourceRef[]): void => {
      if (this.tiers.canGrantAtRuntime(ref, access, context)) {
        target.push(ref);
        return;
      }
      rejected.push({
        resource: ref.toResourceString(context.home),
        access,
        reason: 'tier-2-resource',
        detail: `starter profile "${input.profile.id}" asks for a tier 2 resource`,
      });
    };

    for (const ref of input.profile.reads(context.home)) add(ref, 'read', reads);
    for (const ref of input.profile.writes(context.home)) add(ref, 'write', writes);
  }

  private collectGrants(
    input: PolicyInput,
    reads: ResourceRef[],
    writes: ResourceRef[],
    overrides: PolicyOverride[],
    rejected: RejectedGrant[],
  ): void {
    const { context } = input;

    for (const grant of input.grants) {
      if (!grant.appliesTo(input.workspaceId)) continue;

      const target = grant.access === 'read' ? reads : writes;
      if (this.tiers.canGrantAtRuntime(grant.resource, grant.access, context)) {
        target.push(grant.resource);
        continue;
      }

      if (grant.origin === 'manual') {
        // Typed by hand, outside the agent's reach: the documented — and only —
        // way to reach tier 2 (spec §4.5).
        overrides.push({
          ref: grant.resource,
          access: grant.access,
          reason: grant.reason,
        });
        target.push(grant.resource);
        continue;
      }

      rejected.push({
        resource: grant.resource.toResourceString(context.home),
        access: grant.access,
        reason: 'tier-2-runtime-grant',
        detail: 'tier 2 access cannot be granted while the agent is running',
      });
    }
  }
}
