import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';

describe('AbsolutePath', () => {
  describe('construction', () => {
    it('accepts an absolute posix path', () => {
      expect(AbsolutePath.of('/usr/bin').toString()).toBe('/usr/bin');
    });

    it('normalises redundant separators and dot segments', () => {
      expect(AbsolutePath.of('/usr//bin/./../lib/').toString()).toBe('/usr/lib');
    });

    it('keeps the root path as a single slash', () => {
      expect(AbsolutePath.of('/').toString()).toBe('/');
    });

    it('rejects a relative path', () => {
      expect(() => AbsolutePath.of('usr/bin')).toThrow(/absolute/i);
    });

    it('rejects an empty path', () => {
      expect(() => AbsolutePath.of('')).toThrow(/absolute/i);
    });

    it('rejects a path containing a NUL byte', () => {
      expect(() => AbsolutePath.of('/tmp/\0evil')).toThrow(/NUL/i);
    });
  });

  describe('fromUserPath', () => {
    const home = AbsolutePath.of('/Users/dev');

    it('expands a bare tilde to the home directory', () => {
      expect(AbsolutePath.fromUserPath('~', home).toString()).toBe('/Users/dev');
    });

    it('expands a tilde prefix', () => {
      expect(AbsolutePath.fromUserPath('~/.ssh/id_rsa', home).toString()).toBe(
        '/Users/dev/.ssh/id_rsa',
      );
    });

    it('does not expand a tilde that is not a path prefix', () => {
      expect(() => AbsolutePath.fromUserPath('~other/file', home)).toThrow(/absolute/i);
    });

    it('passes an already absolute path through', () => {
      expect(AbsolutePath.fromUserPath('/etc/hosts', home).toString()).toBe('/etc/hosts');
    });
  });

  describe('containment', () => {
    const usr = AbsolutePath.of('/usr');

    it('contains a descendant', () => {
      expect(usr.contains(AbsolutePath.of('/usr/local/bin'))).toBe(true);
    });

    it('contains itself', () => {
      expect(usr.contains(AbsolutePath.of('/usr'))).toBe(true);
    });

    it('does not contain a sibling with a shared string prefix', () => {
      expect(usr.contains(AbsolutePath.of('/usr-local'))).toBe(false);
    });

    it('does not contain an ancestor', () => {
      expect(usr.contains(AbsolutePath.of('/'))).toBe(false);
    });

    it('root contains everything', () => {
      expect(AbsolutePath.of('/').contains(AbsolutePath.of('/anything/at/all'))).toBe(true);
    });
  });

  describe('value semantics', () => {
    it('is equal to another instance with the same normalised value', () => {
      expect(AbsolutePath.of('/a/b').equals(AbsolutePath.of('/a/./b/'))).toBe(true);
    });

    it('is not equal to a different path', () => {
      expect(AbsolutePath.of('/a/b').equals(AbsolutePath.of('/a/c'))).toBe(false);
    });

    it('exposes segments without empty entries', () => {
      expect(AbsolutePath.of('/a/b/c').segments).toEqual(['a', 'b', 'c']);
    });

    it('exposes no segments for the root', () => {
      expect(AbsolutePath.of('/').segments).toEqual([]);
    });

    it('joins child segments', () => {
      expect(AbsolutePath.of('/a').join('b', 'c').toString()).toBe('/a/b/c');
    });

    it('is frozen', () => {
      expect(Object.isFrozen(AbsolutePath.of('/a'))).toBe(true);
    });
  });
});
