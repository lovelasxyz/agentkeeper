import { Grant } from '../../domain/entities/Grant.js';
import { GrantScope } from '../../domain/value-objects/GrantScope.js';
import { WorkspaceId } from '../../domain/value-objects/WorkspaceId.js';
import type { ResourceRef } from '../../domain/value-objects/ResourceRef.js';
import type { Access } from '../../domain/paths/SensitivePath.js';
import type { PathContext } from '../../domain/paths/PathContext.js';
import type { AccessTierResolver } from '../../domain/policy/AccessTierResolver.js';
import type { AuditLog, Clock, GrantStore } from '../ports/index.js';

export type GrantOutcome =
  | { readonly kind: 'granted'; readonly grant: Grant; readonly takesEffect: 'next-run' }
  | { readonly kind: 'refused'; readonly message: string };

export interface GrantRequest {
  readonly resource: ResourceRef;
  readonly access: Access;
  readonly reason: string;
  readonly scope: 'global' | 'workspace';
  readonly context: PathContext;
}

/**
 * Adds a runtime grant (spec §4.3).
 *
 * Two things this deliberately does not do. It never grants tier 2 — that is
 * §4.5, and the refusal carries no "allow anyway" affordance, because an
 * injected prompt can produce the request but cannot open the user's editor.
 * And it never claims the grant is live: both Seatbelt and bubblewrap fix the
 * profile at process start, so the honest answer is "next run", and hiding that
 * would leave the user thinking the tool is broken.
 */
export class GrantAccess {
  constructor(
    private readonly grants: GrantStore,
    private readonly tiers: AccessTierResolver,
    private readonly audit: AuditLog,
    private readonly clock: Clock,
  ) {}

  async execute(request: GrantRequest): Promise<GrantOutcome> {
    const { resource, access, context } = request;

    if (!this.tiers.canGrantAtRuntime(resource, access, context)) {
      const reason = this.tiers.explain(resource.path, access, context);
      await this.audit.append({
        at: this.clock.now(),
        event: 'grant.refused',
        details: {
          resource: resource.toResourceString(context.home),
          access,
          registryEntry: reason?.id ?? null,
        },
      });
      return {
        kind: 'refused',
        message:
          `Access to ${resource.toResourceString(context.home)} is not configurable while the ` +
          `agent is running.${reason === null ? '' : ` ${reason.rationale}`} ` +
          'It can only be changed by editing ~/.agent-guard/allowlist.json yourself.',
      };
    }

    const grant = Grant.create({
      resource,
      access,
      scope:
        request.scope === 'global'
          ? GrantScope.global()
          : GrantScope.forWorkspace(WorkspaceId.fromPath(context.workspace)),
      grantedAt: this.clock.now(),
      reason: request.reason,
      origin: 'runtime',
    });

    await this.grants.add(grant);
    await this.audit.append({
      at: this.clock.now(),
      event: 'grant.added',
      details: {
        id: grant.id,
        resource: resource.toResourceString(context.home),
        access,
        scope: grant.scope.toString(),
      },
    });

    return { kind: 'granted', grant, takesEffect: 'next-run' };
  }
}
