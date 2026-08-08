import { createHash } from 'node:crypto';
import { GrantScope } from '../value-objects/GrantScope.js';
import { ResourceRef } from '../value-objects/ResourceRef.js';
import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { WorkspaceId } from '../value-objects/WorkspaceId.js';
import type { Access } from '../paths/SensitivePath.js';

/**
 * Where a grant came from.
 *
 * `runtime` was produced by answering a prompt while the agent was running and
 * is therefore reachable by an injected instruction; it may only ever widen
 * tier 1. `manual` was typed into `allowlist.json` in a text editor, outside
 * the agent's world — the one path spec §4.5 leaves open for tier 2. The
 * distinction is enforced structurally, not by trust: the sandbox never makes
 * `~/.agent-guard` writable, so the agent cannot forge a `manual` entry.
 */
export type GrantOrigin = 'runtime' | 'manual';

export interface GrantProps {
  readonly resource: ResourceRef;
  readonly access: Access;
  readonly scope: GrantScope;
  readonly grantedAt: Date;
  readonly reason: string;
  readonly origin: GrantOrigin;
}

/** Serialised shape of one `allowlist.json` entry. */
export interface GrantJSON {
  readonly resource: string;
  readonly access: string;
  readonly scope: string;
  readonly grantedAt?: string;
  readonly reason?: string;
  readonly origin?: string;
}

const ACCESSES: readonly string[] = ['read', 'write'];
const ORIGINS: readonly string[] = ['runtime', 'manual'];

export class Grant {
  readonly id: string;

  private constructor(private readonly props: GrantProps) {
    this.id = createHash('sha256')
      .update(`${props.resource.toString()}|${props.access}|${props.scope.toString()}`)
      .digest('hex')
      .slice(0, 12);
    Object.freeze(this);
  }

  static create(props: GrantProps): Grant {
    if (props.reason.trim().length === 0) {
      throw new Error('A grant needs a reason: it is what makes the allowlist auditable');
    }
    return new Grant({ ...props, reason: props.reason.trim() });
  }

  static fromJSON(raw: GrantJSON, home: AbsolutePath): Grant {
    if (!ACCESSES.includes(raw.access)) {
      throw new Error(`Unknown grant access: ${JSON.stringify(raw.access)}`);
    }
    const origin = raw.origin ?? 'manual';
    if (!ORIGINS.includes(origin)) {
      throw new Error(`Unknown grant origin: ${JSON.stringify(raw.origin)}`);
    }
    return Grant.create({
      resource: ResourceRef.parse(raw.resource, home),
      access: raw.access as Access,
      scope: GrantScope.parse(raw.scope),
      grantedAt: raw.grantedAt === undefined ? new Date(0) : new Date(raw.grantedAt),
      reason: raw.reason ?? 'hand-written entry',
      // A hand-edited file has no origin field; treating that as `manual` is the
      // whole point of the escape hatch.
      origin: origin as GrantOrigin,
    });
  }

  get resource(): ResourceRef {
    return this.props.resource;
  }

  get access(): Access {
    return this.props.access;
  }

  get scope(): GrantScope {
    return this.props.scope;
  }

  get grantedAt(): Date {
    return this.props.grantedAt;
  }

  get reason(): string {
    return this.props.reason;
  }

  get origin(): GrantOrigin {
    return this.props.origin;
  }

  appliesTo(workspace: WorkspaceId): boolean {
    return this.props.scope.appliesTo(workspace);
  }

  covers(access: Access, workspace: WorkspaceId): boolean {
    return this.props.access === access && this.appliesTo(workspace);
  }

  toJSON(home: AbsolutePath): Required<GrantJSON> {
    return {
      resource: this.props.resource.toResourceString(home),
      access: this.props.access,
      scope: this.props.scope.toString(),
      grantedAt: this.props.grantedAt.toISOString(),
      reason: this.props.reason,
      origin: this.props.origin,
    };
  }
}
