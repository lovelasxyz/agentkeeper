import { WorkspaceId } from './WorkspaceId.js';

/** Where a grant applies: everywhere, or in one working directory (spec §4.3). */
export class GrantScope {
  private constructor(private readonly workspace: WorkspaceId | null) {
    Object.freeze(this);
  }

  static global(): GrantScope {
    return new GrantScope(null);
  }

  static forWorkspace(id: WorkspaceId): GrantScope {
    return new GrantScope(id);
  }

  static parse(raw: string): GrantScope {
    if (raw === 'global') return GrantScope.global();
    if (raw.startsWith('workspace:')) {
      return GrantScope.forWorkspace(WorkspaceId.parse(raw.slice('workspace:'.length)));
    }
    throw new Error(`Malformed grant scope: ${JSON.stringify(raw)}`);
  }

  get isGlobal(): boolean {
    return this.workspace === null;
  }

  appliesTo(id: WorkspaceId): boolean {
    return this.workspace === null || this.workspace.equals(id);
  }

  toString(): string {
    return this.workspace === null ? 'global' : `workspace:${this.workspace.toString()}`;
  }

  toJSON(): string {
    return this.toString();
  }
}
