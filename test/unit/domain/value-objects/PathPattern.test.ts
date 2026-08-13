import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { PathPattern } from '../../../../src/domain/value-objects/PathPattern.js';

const HOME = AbsolutePath.of('/Users/dev');
const p = (s: string): AbsolutePath => AbsolutePath.of(s);

describe('PathPattern', () => {
  describe('literal patterns', () => {
    const pattern = PathPattern.of('~/.netrc');

    it('matches the exact path', () => {
      expect(pattern.matches(p('/Users/dev/.netrc'), HOME)).toBe(true);
    });

    it('does not match a different path', () => {
      expect(pattern.matches(p('/Users/dev/.netrc.bak'), HOME)).toBe(false);
    });

    it('does not match a descendant', () => {
      expect(pattern.matches(p('/Users/dev/.netrc/inner'), HOME)).toBe(false);
    });
  });

  describe('single-segment wildcard', () => {
    const pattern = PathPattern.of('~/.aws/*');

    it('matches a direct child', () => {
      expect(pattern.matches(p('/Users/dev/.aws/credentials'), HOME)).toBe(true);
    });

    it('does not match a grandchild', () => {
      expect(pattern.matches(p('/Users/dev/.aws/sso/cache'), HOME)).toBe(false);
    });

    it('does not match the directory itself', () => {
      expect(pattern.matches(p('/Users/dev/.aws'), HOME)).toBe(false);
    });
  });

  describe('partial wildcard inside a segment', () => {
    const pattern = PathPattern.of('~/.z*_history');

    it('matches a segment with the given prefix and suffix', () => {
      expect(pattern.matches(p('/Users/dev/.zsh_history'), HOME)).toBe(true);
    });

    it('does not let the wildcard cross a separator', () => {
      expect(pattern.matches(p('/Users/dev/.z/sh_history'), HOME)).toBe(false);
    });
  });

  describe('recursive wildcard', () => {
    const pattern = PathPattern.of('~/.ssh/**');

    it('matches the directory itself so the subtree is fully covered', () => {
      expect(pattern.matches(p('/Users/dev/.ssh'), HOME)).toBe(true);
    });

    it('matches a direct child', () => {
      expect(pattern.matches(p('/Users/dev/.ssh/id_rsa'), HOME)).toBe(true);
    });

    it('matches a deeply nested descendant', () => {
      expect(pattern.matches(p('/Users/dev/.ssh/keys/prod/id_ed25519'), HOME)).toBe(true);
    });

    it('does not match a sibling directory', () => {
      expect(pattern.matches(p('/Users/dev/.sshd'), HOME)).toBe(false);
    });
  });

  describe('leading recursive wildcard', () => {
    const pattern = PathPattern.of('**/.env');

    it('matches the file at any depth', () => {
      expect(pattern.matches(p('/srv/app/config/.env'), HOME)).toBe(true);
    });

    it('matches the file at the root', () => {
      expect(pattern.matches(p('/.env'), HOME)).toBe(true);
    });

    it('does not match a file with a longer name', () => {
      expect(pattern.matches(p('/srv/app/.env.local'), HOME)).toBe(false);
    });
  });

  describe('anchoring', () => {
    it('treats a home-relative pattern as anchored to the given home', () => {
      const pattern = PathPattern.of('~/.npmrc');
      expect(pattern.matches(p('/Users/other/.npmrc'), HOME)).toBe(false);
    });

    it('supports absolute patterns', () => {
      const pattern = PathPattern.of('/etc/shadow');
      expect(pattern.matches(p('/etc/shadow'), HOME)).toBe(true);
    });

    it('rejects a relative pattern that is neither absolute nor home-anchored', () => {
      expect(() => PathPattern.of('.ssh/id_rsa')).toThrow(/anchored/i);
    });
  });

  describe('literal prefix', () => {
    it('reports the wildcard-free prefix of a recursive pattern', () => {
      expect(PathPattern.of('~/.ssh/**').literalPrefix(HOME)?.toString()).toBe('/Users/dev/.ssh');
    });

    it('reports the full path for a literal pattern', () => {
      expect(PathPattern.of('~/.netrc').literalPrefix(HOME)?.toString()).toBe('/Users/dev/.netrc');
    });

    it('reports null when the pattern starts with a wildcard', () => {
      expect(PathPattern.of('**/.env').literalPrefix(HOME)).toBeNull();
    });
  });

  describe('depth below the literal prefix', () => {
    // A watcher registers one handle per directory under a budget. Recursing
    // into an anchor that the pattern never reaches below spends that budget
    // on nothing — and `~/.claude` alone holds thousands of session
    // directories, which starves every target registered after it.
    it('does not descend for a single wildcard segment', () => {
      expect(PathPattern.of('~/.claude/settings*.json').descendsBelowPrefix()).toBe(false);
      expect(PathPattern.of('~/Library/LaunchAgents/*.plist').descendsBelowPrefix()).toBe(false);
    });

    it('does not descend for a fully literal pattern', () => {
      expect(PathPattern.of('~/.netrc').descendsBelowPrefix()).toBe(false);
    });

    it('descends for a recursive wildcard', () => {
      expect(PathPattern.of('~/.ssh/**').descendsBelowPrefix()).toBe(true);
      expect(PathPattern.of('**/.env').descendsBelowPrefix()).toBe(true);
    });

    it('descends when a wildcard segment is followed by more segments', () => {
      expect(PathPattern.of('~/.mozilla/firefox/*/logins.json').descendsBelowPrefix()).toBe(true);
    });
  });

  it('exposes its raw source', () => {
    expect(PathPattern.of('~/.ssh/**').raw).toBe('~/.ssh/**');
  });
});
