import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { PolicyBuilder } from '../../../../src/domain/policy/PolicyBuilder.js';
import { StarterProfile } from '../../../../src/domain/policy/StarterProfile.js';
import { AccessTierResolver } from '../../../../src/domain/policy/AccessTierResolver.js';
import { SensitivePathRegistry } from '../../../../src/domain/paths/SensitivePathRegistry.js';
import { Grant } from '../../../../src/domain/entities/Grant.js';
import { GrantScope } from '../../../../src/domain/value-objects/GrantScope.js';
import { WorkspaceId } from '../../../../src/domain/value-objects/WorkspaceId.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { ContentHash } from '../../../../src/domain/value-objects/ContentHash.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';
import type { Access } from '../../../../src/domain/paths/SensitivePath.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';

const HOME = AbsolutePath.of('/Users/dev');
const WORKSPACE = AbsolutePath.of('/Users/dev/projects/app');
const CTX: PathContext = { home: HOME, workspace: WORKSPACE, platform: 'darwin' };
const WORKSPACE_ID = WorkspaceId.fromPath(WORKSPACE);

const registry = SensitivePathRegistry.default();
const builder = new PolicyBuilder(new AccessTierResolver(registry), registry);

const EMPTY_PROFILE = StarterProfile.fromSpec({
  id: 'empty',
  name: 'Empty',
  description: 'nothing pre-granted',
  reads: [],
  writes: [],
  network: [],
});

/**
 * Concrete paths an attacker would actually want, one per tier 2 registry entry
 * that applies to this platform. Generated from the registry rather than typed
 * out, so a new entry is covered the moment it is added.
 */
function dangerousSamples(access: Access): { path: AbsolutePath; id: string }[] {
  const samples: { path: AbsolutePath; id: string }[] = [];
  for (const entry of registry.dangerousFor('darwin', access)) {
    const anchor = entry.literalPrefix(HOME);
    if (anchor === null) {
      // Patterns with no fixed anchor, e.g. `**/.env`: probe a plausible location.
      samples.push({ path: AbsolutePath.of('/Users/dev/projects/other/.env'), id: entry.id });
      continue;
    }
    const probe = entry.pattern.raw.includes('*') ? anchor.join('probe') : anchor;
    if (entry.matches(probe, CTX)) samples.push({ path: probe, id: entry.id });
    if (entry.matches(anchor, CTX)) samples.push({ path: anchor, id: entry.id });
  }
  return samples;
}

const pathSegment = fc
  .stringMatching(/^[A-Za-z0-9._-]{1,12}$/)
  .filter((segment) => segment !== '.' && segment !== '..');

const arbitraryRef: fc.Arbitrary<ResourceRef> = fc
  .tuple(fc.array(pathSegment, { minLength: 0, maxLength: 4 }), fc.boolean())
  .map(([segments, isDir]) => {
    const path = segments.length === 0 ? HOME : HOME.join(...segments);
    return isDir ? ResourceRef.subtree(path) : ResourceRef.file(path);
  });

const arbitraryRuntimeGrant: fc.Arbitrary<Grant> = fc
  .tuple(arbitraryRef, fc.constantFrom<Access>('read', 'write'), fc.boolean())
  .map(([resource, access, global]) =>
    Grant.create({
      resource,
      access,
      scope: global ? GrantScope.global() : GrantScope.forWorkspace(WORKSPACE_ID),
      grantedAt: new Date('2026-08-07T00:00:00Z'),
      reason: 'generated',
      origin: 'runtime',
    }),
  );

describe('security invariant: tier 2 is unreachable at runtime (spec §4.5, §9.6)', () => {
  it('has samples to check', () => {
    expect(dangerousSamples('read').length).toBeGreaterThan(15);
    expect(dangerousSamples('write').length).toBeGreaterThan(15);
  });

  it('holds for any set of runtime grants', () => {
    const readSamples = dangerousSamples('read');
    const writeSamples = dangerousSamples('write');

    fc.assert(
      fc.property(fc.array(arbitraryRuntimeGrant, { maxLength: 12 }), (grants) => {
        const { policy } = builder.build({
          profile: EMPTY_PROFILE,
          grants,
          context: CTX,
          workspaceId: WORKSPACE_ID,
          toolchainRoots: [],
          stateDir: HOME.join('.agent-guard'),
          agentStateDirs: [HOME.join('.claude')],
          tempDirs: [AbsolutePath.of('/tmp')],
        });

        for (const sample of readSamples) {
          if (policy.allows('read', sample.path, CTX)) {
            throw new Error(`read of ${sample.path} leaked via ${sample.id}`);
          }
        }
        for (const sample of writeSamples) {
          if (policy.allows('write', sample.path, CTX)) {
            throw new Error(`write to ${sample.path} leaked via ${sample.id}`);
          }
        }
        return true;
      }),
      { numRuns: 300 },
    );
  });

  it('rejects every runtime grant that reached for tier 2', () => {
    const grant = Grant.create({
      resource: ResourceRef.subtree(HOME),
      access: 'read',
      scope: GrantScope.global(),
      grantedAt: new Date(),
      reason: 'generated',
      origin: 'runtime',
    });
    const { rejected } = builder.build({
      profile: EMPTY_PROFILE,
      grants: [grant],
      context: CTX,
      workspaceId: WORKSPACE_ID,
      toolchainRoots: [],
      stateDir: HOME.join('.agent-guard'),
      agentStateDirs: [],
      tempDirs: [],
    });
    expect(rejected).toHaveLength(1);
  });
});

describe('ContentHash is a pure function (spec §9.6)', () => {
  it('is deterministic', () => {
    fc.assert(
      fc.property(fc.string(), (content) =>
        ContentHash.fromContent(content).equals(ContentHash.fromContent(content)),
      ),
    );
  });

  it('round-trips through its serialised form', () => {
    fc.assert(
      fc.property(fc.string(), (content) => {
        const hash = ContentHash.fromContent(content);
        return ContentHash.parse(hash.toString()).equals(hash);
      }),
    );
  });

  it('separates different content', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) =>
        a === b || !ContentHash.fromContent(a).equals(ContentHash.fromContent(b)),
      ),
    );
  });
});
