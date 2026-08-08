import { describe, expect, it } from 'vitest';
import { AccessTierResolver } from '../../../../src/domain/policy/AccessTierResolver.js';
import { SensitivePathRegistry } from '../../../../src/domain/paths/SensitivePathRegistry.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { AccessTier } from '../../../../src/domain/value-objects/AccessTier.js';
import { Disposition } from '../../../../src/domain/value-objects/Disposition.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';

const HOME = AbsolutePath.of('/Users/dev');
const WORKSPACE = AbsolutePath.of('/Users/dev/projects/app');
const CTX: PathContext = { home: HOME, workspace: WORKSPACE, platform: 'darwin' };

const resolver = new AccessTierResolver(SensitivePathRegistry.default());
const at = (raw: string): AbsolutePath => AbsolutePath.fromUserPath(raw, HOME);

describe('AccessTierResolver', () => {
  describe('tier of a path', () => {
    it('reports tier 2 for reading a credential path', () => {
      expect(resolver.tierOf(at('~/.ssh/id_rsa'), 'read', CTX)).toBe(AccessTier.DANGEROUS);
    });

    it('reports tier 2 for writing a persistence path', () => {
      expect(resolver.tierOf(at('~/.zshenv'), 'write', CTX)).toBe(AccessTier.DANGEROUS);
    });

    it('reports tier 1 for an ordinary path outside the registry', () => {
      expect(resolver.tierOf(at('~/projects/other-app'), 'read', CTX)).toBe(AccessTier.EVERYDAY);
    });

    it('reports tier 1 for developer tool configuration', () => {
      expect(resolver.tierOf(at('~/.config/nvim/init.lua'), 'read', CTX)).toBe(
        AccessTier.EVERYDAY,
      );
    });

    it('separates read and write for ~/.gitconfig', () => {
      expect(resolver.tierOf(at('~/.gitconfig'), 'read', CTX)).toBe(AccessTier.EVERYDAY);
      expect(resolver.tierOf(at('~/.gitconfig'), 'write', CTX)).toBe(AccessTier.DANGEROUS);
    });

    it('takes the strictest tier when several entries match', () => {
      // ~/.config/gh/** is tier 2 while the generic ~/.config/** entry is tier 1.
      expect(resolver.tierOf(at('~/.config/gh/hosts.yml'), 'read', CTX)).toBe(
        AccessTier.DANGEROUS,
      );
    });
  });

  describe('dispositions', () => {
    it('blocks reads of a credential path', () => {
      expect(resolver.dispositionOf(at('~/.aws/credentials'), 'read', CTX)).toBe(
        Disposition.BLOCK,
      );
    });

    it('observes reads of tool configuration', () => {
      expect(resolver.dispositionOf(at('~/.config/nvim/init.lua'), 'read', CTX)).toBe(
        Disposition.OBSERVE,
      );
    });

    it('observes an unlisted path', () => {
      expect(resolver.dispositionOf(at('~/projects/app/src/a.ts'), 'read', CTX)).toBe(
        Disposition.OBSERVE,
      );
    });
  });

  describe('runtime grants', () => {
    it('permits a tier 1 file', () => {
      expect(
        resolver.canGrantAtRuntime(ResourceRef.file(at('~/.gitconfig')), 'read', CTX),
      ).toBe(true);
    });

    it('refuses writing the same tier 1 read target', () => {
      expect(
        resolver.canGrantAtRuntime(ResourceRef.file(at('~/.gitconfig')), 'write', CTX),
      ).toBe(false);
    });

    it('refuses a tier 2 file', () => {
      expect(
        resolver.canGrantAtRuntime(ResourceRef.file(at('~/.ssh/id_rsa')), 'read', CTX),
      ).toBe(false);
    });

    it('refuses a subtree that merely contains a tier 2 path', () => {
      expect(resolver.canGrantAtRuntime(ResourceRef.subtree(HOME), 'read', CTX)).toBe(false);
    });

    it('refuses the filesystem root', () => {
      expect(
        resolver.canGrantAtRuntime(ResourceRef.subtree(AbsolutePath.of('/')), 'read', CTX),
      ).toBe(false);
    });

    it('permits a sibling project directory', () => {
      expect(
        resolver.canGrantAtRuntime(ResourceRef.subtree(at('~/projects/library')), 'read', CTX),
      ).toBe(true);
    });

    it('permits a project parent directory', () => {
      // Sibling `.env` files inside stay unreadable: the policy always emits
      // trailing deny rules for tier 2 patterns, which outrank any grant.
      expect(
        resolver.canGrantAtRuntime(ResourceRef.subtree(at('~/projects')), 'read', CTX),
      ).toBe(true);
    });
  });

  describe('explanations', () => {
    it('names the registry entry that made a path dangerous', () => {
      const reason = resolver.explain(at('~/.aws/credentials'), 'read', CTX);
      expect(reason?.id).toBe('aws-credentials');
      expect(reason?.rationale).toMatch(/cloud/i);
    });

    it('returns null for an ordinary path', () => {
      expect(resolver.explain(at('~/projects/app/README.md'), 'read', CTX)).toBeNull();
    });
  });
});
