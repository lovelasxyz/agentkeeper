import { describe, expect, it } from 'vitest';
import { Grant } from '../../../../src/domain/entities/Grant.js';
import { GrantScope } from '../../../../src/domain/value-objects/GrantScope.js';
import { WorkspaceId } from '../../../../src/domain/value-objects/WorkspaceId.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';

const HOME = AbsolutePath.of('/Users/dev');
const APP = WorkspaceId.fromPath(AbsolutePath.of('/Users/dev/projects/app'));
const OTHER = WorkspaceId.fromPath(AbsolutePath.of('/Users/dev/projects/other'));
const AT = new Date('2026-08-07T14:22:11Z');

describe('WorkspaceId', () => {
  it('is stable for the same path', () => {
    expect(WorkspaceId.fromPath(AbsolutePath.of('/a/b')).toString()).toBe(
      WorkspaceId.fromPath(AbsolutePath.of('/a/b')).toString(),
    );
  });

  it('differs between paths', () => {
    expect(APP.equals(OTHER)).toBe(false);
  });

  it('is short enough to read in a config file', () => {
    expect(APP.toString()).toMatch(/^[0-9a-f]{16}$/);
  });

  it('parses back from its serialised form', () => {
    expect(WorkspaceId.parse(APP.toString()).equals(APP)).toBe(true);
  });

  it('rejects a malformed id', () => {
    expect(() => WorkspaceId.parse('nope')).toThrow(/workspace id/i);
  });
});

describe('GrantScope', () => {
  it('global applies to every workspace', () => {
    expect(GrantScope.global().appliesTo(APP)).toBe(true);
    expect(GrantScope.global().appliesTo(OTHER)).toBe(true);
  });

  it('workspace scope applies only to its own workspace', () => {
    const scope = GrantScope.forWorkspace(APP);
    expect(scope.appliesTo(APP)).toBe(true);
    expect(scope.appliesTo(OTHER)).toBe(false);
  });

  it('round-trips through its serialised form', () => {
    expect(GrantScope.parse('global').toString()).toBe('global');
    expect(GrantScope.parse(`workspace:${APP.toString()}`).appliesTo(APP)).toBe(true);
  });

  it('rejects a malformed scope', () => {
    expect(() => GrantScope.parse('project:xyz')).toThrow(/scope/i);
  });
});

describe('Grant', () => {
  const grant = Grant.create({
    resource: ResourceRef.file(AbsolutePath.of('/Users/dev/.gitconfig')),
    access: 'read',
    scope: GrantScope.global(),
    grantedAt: AT,
    reason: 'git operations',
    origin: 'runtime',
  });

  it('exposes its parts', () => {
    expect(grant.access).toBe('read');
    expect(grant.reason).toBe('git operations');
    expect(grant.origin).toBe('runtime');
  });

  it('derives a stable id from resource, access and scope', () => {
    const same = Grant.create({
      resource: ResourceRef.file(AbsolutePath.of('/Users/dev/.gitconfig')),
      access: 'read',
      scope: GrantScope.global(),
      grantedAt: new Date('2027-01-01T00:00:00Z'),
      reason: 'different reason',
      origin: 'manual',
    });
    expect(same.id).toBe(grant.id);
  });

  it('gives a different id to a different access', () => {
    const write = Grant.create({
      resource: ResourceRef.file(AbsolutePath.of('/Users/dev/.gitconfig')),
      access: 'write',
      scope: GrantScope.global(),
      grantedAt: AT,
      reason: 'x',
      origin: 'manual',
    });
    expect(write.id).not.toBe(grant.id);
  });

  it('applies to a workspace when its scope does', () => {
    expect(grant.appliesTo(APP)).toBe(true);
  });

  it('rejects an empty reason', () => {
    expect(() =>
      Grant.create({
        resource: ResourceRef.file(AbsolutePath.of('/Users/dev/.gitconfig')),
        access: 'read',
        scope: GrantScope.global(),
        grantedAt: AT,
        reason: '   ',
        origin: 'runtime',
      }),
    ).toThrow(/reason/i);
  });

  it('serialises to the documented allowlist shape', () => {
    expect(grant.toJSON(HOME)).toEqual({
      resource: 'file:~/.gitconfig',
      access: 'read',
      scope: 'global',
      grantedAt: '2026-08-07T14:22:11.000Z',
      reason: 'git operations',
      origin: 'runtime',
    });
  });

  it('parses back from the allowlist shape', () => {
    const restored = Grant.fromJSON(grant.toJSON(HOME), HOME);
    expect(restored.id).toBe(grant.id);
    expect(restored.grantedAt.toISOString()).toBe(AT.toISOString());
  });

  it('treats a hand-written entry without an origin as manual', () => {
    const restored = Grant.fromJSON(
      { resource: 'dir:~/work', access: 'read', scope: 'global', reason: 'shared library' },
      HOME,
    );
    expect(restored.origin).toBe('manual');
  });

  it('rejects an entry with an unknown access', () => {
    expect(() =>
      Grant.fromJSON({ resource: 'dir:~/work', access: 'execute', scope: 'global' }, HOME),
    ).toThrow(/access/i);
  });
});
