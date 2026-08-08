import { describe, expect, it } from 'vitest';
import { PolicyBuilder } from '../../../../src/domain/policy/PolicyBuilder.js';
import { StarterProfile } from '../../../../src/domain/policy/StarterProfile.js';
import { AccessTierResolver } from '../../../../src/domain/policy/AccessTierResolver.js';
import { SensitivePathRegistry } from '../../../../src/domain/paths/SensitivePathRegistry.js';
import { Grant } from '../../../../src/domain/entities/Grant.js';
import { GrantScope } from '../../../../src/domain/value-objects/GrantScope.js';
import { WorkspaceId } from '../../../../src/domain/value-objects/WorkspaceId.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';
import type { PolicyInput } from '../../../../src/domain/policy/PolicyBuilder.js';

const HOME = AbsolutePath.of('/Users/dev');
const WORKSPACE = AbsolutePath.of('/Users/dev/projects/app');
const CTX: PathContext = { home: HOME, workspace: WORKSPACE, platform: 'darwin' };
const WORKSPACE_ID = WorkspaceId.fromPath(WORKSPACE);

const registry = SensitivePathRegistry.default();
const builder = new PolicyBuilder(new AccessTierResolver(registry), registry);

const PROFILE = StarterProfile.fromSpec({
  id: 'web',
  name: 'Web development',
  description: 'Node toolchain, git, editors',
  reads: ['file:~/.gitconfig', 'dir:~/.npm'],
  writes: ['dir:~/.npm/_cacache'],
  network: ['tcp:443', 'udp:53', 'loopback'],
});

const at = (raw: string): AbsolutePath => AbsolutePath.fromUserPath(raw, HOME);

const input = (overrides: Partial<PolicyInput> = {}): PolicyInput => ({
  profile: PROFILE,
  grants: [],
  context: CTX,
  workspaceId: WORKSPACE_ID,
  toolchainRoots: [at('~/.nvm')],
  stateDir: at('~/.agent-guard'),
  agentStateDirs: [at('~/.claude')],
  tempDirs: [AbsolutePath.of('/tmp')],
  ...overrides,
});

const runtimeGrant = (resource: ResourceRef, access: 'read' | 'write' = 'read'): Grant =>
  Grant.create({
    resource,
    access,
    scope: GrantScope.global(),
    grantedAt: new Date('2026-08-07T00:00:00Z'),
    reason: 'test',
    origin: 'runtime',
  });

describe('PolicyBuilder', () => {
  describe('the workspace', () => {
    it('is readable', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('read', at('~/projects/app/src/index.ts'), CTX)).toBe(true);
    });

    it('is writable', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('write', at('~/projects/app/dist/out.js'), CTX)).toBe(true);
    });
  });

  describe('what stays closed with no grants at all', () => {
    it.each([
      '~/.ssh/id_rsa',
      '~/.aws/credentials',
      '~/.zsh_history',
      '~/Library/Keychains/login.keychain-db',
      '~/projects/other/.env',
    ])('denies reading %s', (raw) => {
      const { policy } = builder.build(input());
      expect(policy.allows('read', at(raw), CTX)).toBe(false);
    });

    it.each(['~/.zshenv', '~/.zshrc', '~/Library/LaunchAgents/x.plist', '~/.gitconfig'])(
      'denies writing %s',
      (raw) => {
        const { policy } = builder.build(input());
        expect(policy.allows('write', at(raw), CTX)).toBe(false);
      },
    );

    it('denies reading a sibling project', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('read', at('~/projects/other/src/a.ts'), CTX)).toBe(false);
    });

    it('denies writing to its own state directory, so grants cannot be self-issued', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('write', at('~/.agent-guard/allowlist.json'), CTX)).toBe(false);
    });
  });

  describe('the starter profile', () => {
    it('opens the paths it lists for reading', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('read', at('~/.gitconfig'), CTX)).toBe(true);
      expect(policy.allows('read', at('~/.npm/_cacache/index/aa'), CTX)).toBe(true);
    });

    it('opens only what it lists for writing', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('write', at('~/.npm/_cacache/tmp/x'), CTX)).toBe(true);
      expect(policy.allows('write', at('~/.npm/other'), CTX)).toBe(false);
    });

    it('cannot open a tier 2 path even if the profile asks for one', () => {
      const reckless = StarterProfile.fromSpec({
        id: 'reckless',
        name: 'Reckless',
        description: 'A profile that should not get its way',
        reads: ['dir:~/.ssh'],
        writes: [],
        network: [],
      });
      const { policy, rejected } = builder.build(input({ profile: reckless }));
      expect(policy.allows('read', at('~/.ssh/id_rsa'), CTX)).toBe(false);
      expect(rejected.map((entry) => entry.reason)).toContain('tier-2-resource');
    });
  });

  describe('the agent state directory', () => {
    it('is readable and writable so sessions and caches keep working', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('read', at('~/.claude/history.jsonl'), CTX)).toBe(true);
      expect(policy.allows('write', at('~/.claude/history.jsonl'), CTX)).toBe(true);
    });

    it('still refuses the agent settings file, which is vector V2', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('write', at('~/.claude/settings.json'), CTX)).toBe(false);
    });
  });

  describe('grants', () => {
    it('applies a tier 1 grant', () => {
      const grant = runtimeGrant(ResourceRef.subtree(at('~/projects/library')));
      const { policy } = builder.build(input({ grants: [grant] }));
      expect(policy.allows('read', at('~/projects/library/src/a.ts'), CTX)).toBe(true);
    });

    it('rejects a runtime grant for a tier 2 resource', () => {
      const grant = runtimeGrant(ResourceRef.file(at('~/.ssh/id_rsa')));
      const { policy, rejected } = builder.build(input({ grants: [grant] }));
      expect(policy.allows('read', at('~/.ssh/id_rsa'), CTX)).toBe(false);
      expect(rejected).toHaveLength(1);
      expect(rejected[0]?.reason).toBe('tier-2-runtime-grant');
    });

    it('honours a hand-written tier 2 grant, because that is the documented escape hatch', () => {
      const manual = Grant.create({
        resource: ResourceRef.file(at('~/.ssh/id_rsa')),
        access: 'read',
        scope: GrantScope.global(),
        grantedAt: new Date('2026-08-07T00:00:00Z'),
        reason: 'deploy key needed by the build',
        origin: 'manual',
      });
      const { policy, rejected } = builder.build(input({ grants: [manual] }));
      expect(policy.allows('read', at('~/.ssh/id_rsa'), CTX)).toBe(true);
      expect(rejected).toHaveLength(0);
    });

    it('keeps a hand-written grant narrow: siblings stay closed', () => {
      const manual = Grant.create({
        resource: ResourceRef.file(at('~/.ssh/id_rsa')),
        access: 'read',
        scope: GrantScope.global(),
        grantedAt: new Date('2026-08-07T00:00:00Z'),
        reason: 'deploy key needed by the build',
        origin: 'manual',
      });
      const { policy } = builder.build(input({ grants: [manual] }));
      expect(policy.allows('read', at('~/.ssh/id_ed25519'), CTX)).toBe(false);
    });

    it('ignores a grant scoped to another workspace', () => {
      const other = WorkspaceId.fromPath(at('~/projects/other'));
      const grant = Grant.create({
        resource: ResourceRef.subtree(at('~/projects/library')),
        access: 'read',
        scope: GrantScope.forWorkspace(other),
        grantedAt: new Date('2026-08-07T00:00:00Z'),
        reason: 'test',
        origin: 'runtime',
      });
      const { policy } = builder.build(input({ grants: [grant] }));
      expect(policy.allows('read', at('~/projects/library/a.ts'), CTX)).toBe(false);
    });

    it('applies a grant scoped to this workspace', () => {
      const grant = Grant.create({
        resource: ResourceRef.subtree(at('~/projects/library')),
        access: 'read',
        scope: GrantScope.forWorkspace(WORKSPACE_ID),
        grantedAt: new Date('2026-08-07T00:00:00Z'),
        reason: 'test',
        origin: 'runtime',
      });
      const { policy } = builder.build(input({ grants: [grant] }));
      expect(policy.allows('read', at('~/projects/library/a.ts'), CTX)).toBe(true);
    });

    it('a read grant does not imply a write grant', () => {
      const grant = runtimeGrant(ResourceRef.subtree(at('~/projects/library')), 'read');
      const { policy } = builder.build(input({ grants: [grant] }));
      expect(policy.allows('write', at('~/projects/library/a.ts'), CTX)).toBe(false);
    });
  });

  describe('network', () => {
    it('takes its rules from the profile', () => {
      const { policy } = builder.build(input());
      expect(policy.network.map(String)).toEqual(['tcp://*:443', 'udp://*:53', 'ip://localhost:*']);
    });

    it('has no rules when the profile lists none', () => {
      const offline = StarterProfile.fromSpec({
        id: 'offline',
        name: 'Offline',
        description: 'No outbound access',
        reads: [],
        writes: [],
        network: [],
      });
      const { policy } = builder.build(input({ profile: offline }));
      expect(policy.network).toEqual([]);
    });
  });

  describe('the toolchain', () => {
    it('is readable so node and version managers keep working', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('read', at('~/.nvm/versions/node/v22/bin/node'), CTX)).toBe(true);
    });

    it('is not writable', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('write', at('~/.nvm/versions/node/v22/bin/node'), CTX)).toBe(false);
    });
  });

  describe('temporary directories', () => {
    it('are readable and writable', () => {
      const { policy } = builder.build(input());
      expect(policy.allows('write', AbsolutePath.of('/tmp/build/out'), CTX)).toBe(true);
    });
  });

  it('exposes the deny rules it derived from the registry', () => {
    const { policy } = builder.build(input());
    const ids = policy.denies.map((deny) => deny.sourceId);
    expect(ids).toContain('ssh-keys');
    expect(ids).toContain('zsh-env');
    expect(ids).not.toContain('systemd-user-units'); // Linux-only, host is darwin
  });
});

describe('an unsafe workspace is refused loudly (spec §4.6)', () => {
  it('refuses to isolate the home directory itself', () => {
    const homeAsWorkspace: PathContext = { home: HOME, workspace: HOME, platform: 'darwin' };
    expect(() =>
      builder.build(input({ context: homeAsWorkspace, workspaceId: WorkspaceId.fromPath(HOME) })),
    ).toThrow(/Refusing to isolate/);
  });

  it('names what would have been handed over', () => {
    const homeAsWorkspace: PathContext = { home: HOME, workspace: HOME, platform: 'darwin' };
    expect(() =>
      builder.build(input({ context: homeAsWorkspace, workspaceId: WorkspaceId.fromPath(HOME) })),
    ).toThrow(/\.ssh/);
  });

  it('accepts an ordinary project directory', () => {
    expect(() => builder.build(input())).not.toThrow();
  });
});
