import { describe, expect, it } from 'vitest';
import { SeatbeltProfileCompiler } from '../../../../src/infrastructure/sandbox/SeatbeltProfileCompiler.js';
import { SandboxPolicy } from '../../../../src/domain/policy/SandboxPolicy.js';
import { DenyRule } from '../../../../src/domain/policy/DenyRule.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { NetworkRule } from '../../../../src/domain/value-objects/NetworkRule.js';
import { PathPattern } from '../../../../src/domain/value-objects/PathPattern.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';

const HOME = AbsolutePath.of('/Users/dev');
const WORKSPACE = AbsolutePath.of('/Users/dev/projects/app');
const CTX: PathContext = { home: HOME, workspace: WORKSPACE, platform: 'darwin' };

const compiler = new SeatbeltProfileCompiler();

const policy = (overrides: Partial<ConstructorParameters<typeof SandboxPolicy>[0]> = {}) =>
  new SandboxPolicy({
    workspace: WORKSPACE,
    reads: [ResourceRef.subtree(WORKSPACE)],
    writes: [ResourceRef.subtree(WORKSPACE)],
    denies: [],
    overrides: [],
    network: [],
    ...overrides,
  });

describe('SeatbeltProfileCompiler', () => {
  it('starts from a deny-default profile', () => {
    const text = compiler.compile(policy(), CTX);
    expect(text.startsWith('(version 1)')).toBe(true);
    expect(text).toContain('(deny default)');
  });

  it('closes the home directory before opening anything inside it', () => {
    const text = compiler.compile(policy(), CTX);
    const homeDeny = text.indexOf('(deny file-read* (subpath "/Users/dev"))');
    const workspaceAllow = text.indexOf('(allow file-read* (subpath "/Users/dev/projects/app"))');
    expect(homeDeny).toBeGreaterThan(-1);
    expect(workspaceAllow).toBeGreaterThan(homeDeny);
  });

  it('emits the operations a process needs in order to start at all', () => {
    const text = compiler.compile(policy(), CTX);
    // Measured on macOS 26: without file-map-executable a deny-default profile
    // aborts the process in dyld before main() with no diagnostic at all.
    expect(text).toContain('(allow file-map-executable)');
    expect(text).toContain('(allow process-fork)');
    expect(text).toContain('(allow sysctl-read)');
  });

  it('translates a subtree read into a subpath rule', () => {
    const text = compiler.compile(
      policy({ reads: [ResourceRef.subtree(AbsolutePath.of('/opt/tools'))] }),
      CTX,
    );
    expect(text).toContain('(allow file-read* (subpath "/opt/tools"))');
  });

  it('translates a file read into a literal rule', () => {
    const text = compiler.compile(
      policy({ reads: [ResourceRef.file(AbsolutePath.of('/Users/dev/.gitconfig'))] }),
      CTX,
    );
    expect(text).toContain('(allow file-read* (literal "/Users/dev/.gitconfig"))');
  });

  it('translates writes separately from reads', () => {
    const text = compiler.compile(
      policy({ writes: [ResourceRef.subtree(AbsolutePath.of('/tmp/build'))] }),
      CTX,
    );
    expect(text).toContain('(allow file-write* (subpath "/tmp/build"))');
  });

  describe('deny rules', () => {
    it('emits an anchored pattern as a subpath deny', () => {
      const text = compiler.compile(
        policy({
          denies: [new DenyRule('ssh-keys', PathPattern.of('~/.ssh/**'), 'read', 'keys')],
        }),
        CTX,
      );
      expect(text).toContain('(deny file-read* (subpath "/Users/dev/.ssh"))');
    });

    it('emits an unanchored pattern as a regex deny', () => {
      const text = compiler.compile(
        policy({
          denies: [new DenyRule('env', PathPattern.of('**/.env'), 'read', 'secrets')],
        }),
        CTX,
      );
      expect(text).toMatch(/\(deny file-read\* \(regex #"[^"]*\\\.env[^"]*"\)\)/);
    });

    it('escapes regex metacharacters in a literal segment', () => {
      const text = compiler.compile(
        policy({ denies: [new DenyRule('env', PathPattern.of('**/.env.*'), 'read', 'x')] }),
        CTX,
      );
      // Single backslash: Seatbelt takes the expression verbatim, and the
      // doubled form matches nothing while looking correct.
      expect(text).toContain('\\.env\\.');
      expect(text).not.toContain('\\\\.env');
    });

    it('places every deny after every allow, so the deny wins', () => {
      const text = compiler.compile(
        policy({
          reads: [ResourceRef.subtree(HOME)],
          denies: [new DenyRule('ssh-keys', PathPattern.of('~/.ssh/**'), 'read', 'keys')],
        }),
        CTX,
      );
      expect(text.indexOf('(deny file-read* (subpath "/Users/dev/.ssh"))')).toBeGreaterThan(
        text.indexOf('(allow file-read* (subpath "/Users/dev"))'),
      );
    });

    it('places a hand-written override after the denies, so the override wins', () => {
      const text = compiler.compile(
        policy({
          denies: [new DenyRule('ssh-keys', PathPattern.of('~/.ssh/**'), 'read', 'keys')],
          overrides: [
            {
              ref: ResourceRef.file(AbsolutePath.of('/Users/dev/.ssh/deploy_key')),
              access: 'read',
              reason: 'build needs the deploy key',
            },
          ],
        }),
        CTX,
      );
      expect(text.indexOf('(allow file-read* (literal "/Users/dev/.ssh/deploy_key"))')).toBeGreaterThan(
        text.indexOf('(deny file-read* (subpath "/Users/dev/.ssh"))'),
      );
    });
  });

  describe('network', () => {
    it('emits nothing outbound when the policy has no network rules', () => {
      const text = compiler.compile(policy(), CTX);
      expect(text).not.toContain('network-outbound');
    });

    it('emits a port rule', () => {
      const text = compiler.compile(policy({ network: [NetworkRule.tcp(443)] }), CTX);
      expect(text).toContain('(allow network-outbound (remote tcp "*:443"))');
    });

    it('emits loopback access as an ip rule and allows binding', () => {
      const text = compiler.compile(policy({ network: [NetworkRule.loopback()] }), CTX);
      expect(text).toContain('(allow network-outbound (remote ip "localhost:*"))');
      expect(text).toContain('(allow network-bind (local ip "localhost:*"))');
    });

    it('allows the unix socket used for DNS resolution only when networking is on', () => {
      expect(compiler.compile(policy({ network: [NetworkRule.tcp(443)] }), CTX)).toContain(
        '(remote unix-socket)',
      );
      expect(compiler.compile(policy(), CTX)).not.toContain('unix-socket');
    });
  });

  describe('hostile input', () => {
    it('refuses a path containing a double quote', () => {
      const evil = AbsolutePath.of('/tmp/a"b');
      expect(() => compiler.compile(policy({ reads: [ResourceRef.subtree(evil)] }), CTX)).toThrow(
        /quote|escape/i,
      );
    });

    it('refuses a path containing a newline', () => {
      const evil = AbsolutePath.of('/tmp/a\nb');
      expect(() => compiler.compile(policy({ reads: [ResourceRef.subtree(evil)] }), CTX)).toThrow(
        /newline|escape/i,
      );
    });
  });

  it('produces a profile that is stable for the same policy', () => {
    expect(compiler.compile(policy(), CTX)).toBe(compiler.compile(policy(), CTX));
  });
});
