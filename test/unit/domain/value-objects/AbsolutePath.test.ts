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

    it('preserves POSIX case and treats a backslash as a filename character', () => {
      expect(AbsolutePath.of(String.raw`/Users/Dev/a\b`).toString()).toBe(
        String.raw`/Users/Dev/a\b`,
      );
    });

    it('normalises a Windows drive path to stable forward-slash form', () => {
      const raw = `${String.raw`c:\Users\Dev\.\projects\..\App`}\\`;
      expect(AbsolutePath.of(raw).toString()).toBe('C:/users/dev/app');
    });

    it('normalises a UNC path without losing its share root', () => {
      const raw = `${String.raw`\\Server\Share\Team\.\project\..\App`}\\`;
      expect(AbsolutePath.of(raw).toString()).toBe('//server/share/team/app');
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

    it('rejects a Windows drive-relative path', () => {
      expect(() => AbsolutePath.of(String.raw`C:Users\dev`)).toThrow(/absolute/i);
    });

    it('rejects a UNC path without a share root', () => {
      expect(() => AbsolutePath.of(String.raw`\\server`)).toThrow(/absolute/i);
    });

    it.each([
      String.raw`\\?\C:\Users\dev`,
      String.raw`\\.\pipe\agentkeeper`,
      String.raw`\??\C:\Users\dev`,
      '//?/UNC/server/share/file',
      '//./pipe/agentkeeper',
    ])('rejects Windows device namespace path %s', (raw) => {
      expect(() => AbsolutePath.of(raw)).toThrow(/device namespace/i);
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

    it('expands a Windows tilde prefix using the home path flavour', () => {
      const windowsHome = AbsolutePath.of(String.raw`C:\Users\Dev`);
      expect(AbsolutePath.fromUserPath(String.raw`~\Documents\Project`, windowsHome).toString()).toBe(
        'C:/users/dev/documents/project',
      );
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

    it('contains Windows descendants case-insensitively', () => {
      const home = AbsolutePath.of(String.raw`C:\Users\Dev`);
      expect(home.contains(AbsolutePath.of(String.raw`c:\USERS\DEV\Projects\App`))).toBe(true);
      expect(home.contains(AbsolutePath.of(String.raw`C:\Users\Developer`))).toBe(false);
    });

    it('does not contain paths on another Windows root', () => {
      expect(
        AbsolutePath.of(String.raw`C:\Users\Dev`).contains(
          AbsolutePath.of(String.raw`D:\Users\Dev`),
        ),
      ).toBe(false);
      expect(
        AbsolutePath.of(String.raw`\\server\share\team`).contains(
          AbsolutePath.of(String.raw`\\server\other\team\app`),
        ),
      ).toBe(false);
    });
  });

  describe('value semantics', () => {
    it('is equal to another instance with the same normalised value', () => {
      expect(AbsolutePath.of('/a/b').equals(AbsolutePath.of('/a/./b/'))).toBe(true);
    });

    it('is not equal to a different path', () => {
      expect(AbsolutePath.of('/a/b').equals(AbsolutePath.of('/a/c'))).toBe(false);
    });

    it('keeps POSIX equality case-sensitive', () => {
      expect(AbsolutePath.of('/Users/Dev').equals(AbsolutePath.of('/users/dev'))).toBe(false);
    });

    it('compares drive and UNC paths case-insensitively', () => {
      expect(
        AbsolutePath.of(String.raw`C:\Users\Dev`).equals(
          AbsolutePath.of(String.raw`c:/USERS/dev`),
        ),
      ).toBe(true);
      expect(
        AbsolutePath.of(String.raw`\\Server\Share\Folder`).equals(
          AbsolutePath.of('//server/share/FOLDER'),
        ),
      ).toBe(true);
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

    it('supports drive-root segments, basename, parent and join', () => {
      const path = AbsolutePath.of(String.raw`C:\Users\Dev\Projects\App`);
      expect(path.segments).toEqual(['users', 'dev', 'projects', 'app']);
      expect(path.basename).toBe('app');
      expect(path.parent.toString()).toBe('C:/users/dev/projects');
      expect(path.parent.join(String.raw`Other\src`, '..', 'test').toString()).toBe(
        'C:/users/dev/projects/other/test',
      );
      expect(AbsolutePath.of('C:/').parent.toString()).toBe('C:/');
    });

    it('supports UNC-root segments, parent and join', () => {
      const path = AbsolutePath.of(String.raw`\\Server\Share\Team\App\index.ts`);
      expect(path.segments).toEqual(['team', 'app', 'index.ts']);
      expect(path.parent.toString()).toBe('//server/share/team/app');
      expect(path.parent.join('src', 'main.ts').toString()).toBe(
        '//server/share/team/app/src/main.ts',
      );
      expect(AbsolutePath.of('//server/share').parent.toString()).toBe('//server/share');
    });

    it('is frozen', () => {
      expect(Object.isFrozen(AbsolutePath.of('/a'))).toBe(true);
    });
  });
});
