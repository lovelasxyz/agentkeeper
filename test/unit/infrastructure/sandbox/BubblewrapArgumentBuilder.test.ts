import { describe, expect, it } from 'vitest';
import { BubblewrapArgumentBuilder } from '../../../../src/infrastructure/sandbox/BubblewrapArgumentBuilder.js';
import { BubblewrapRunner } from '../../../../src/infrastructure/sandbox/BubblewrapRunner.js';
import { NoopRunner } from '../../../../src/infrastructure/sandbox/NoopRunner.js';
import { SandboxPolicy } from '../../../../src/domain/policy/SandboxPolicy.js';
import { DenyRule } from '../../../../src/domain/policy/DenyRule.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { NetworkRule } from '../../../../src/domain/value-objects/NetworkRule.js';
import { PathPattern } from '../../../../src/domain/value-objects/PathPattern.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';
import type { SandboxCommand } from '../../../../src/application/ports/SandboxRunner.js';

const HOME = AbsolutePath.of('/home/dev');
const WORKSPACE = AbsolutePath.of('/home/dev/projects/app');
const CTX: PathContext = { home: HOME, workspace: WORKSPACE, platform: 'linux' };

const COMMAND: SandboxCommand = {
  executable: '/usr/bin/claude',
  args: ['--help'],
  cwd: WORKSPACE,
  env: {},
};

const builder = new BubblewrapArgumentBuilder();

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

/** Finds `flag value` pairs, so assertions do not depend on argument order. */
const hasPair = (args: readonly string[], flag: string, value: string): boolean =>
  args.some((arg, index) => arg === flag && args[index + 1] === value);

describe('BubblewrapArgumentBuilder', () => {
  it('replaces the home directory with an empty tmpfs', () => {
    expect(hasPair(builder.build(policy(), CTX, COMMAND), '--tmpfs', '/home/dev')).toBe(true);
  });

  it('binds the workspace read-write', () => {
    const args = builder.build(policy(), CTX, COMMAND);
    expect(hasPair(args, '--bind-try', WORKSPACE.value)).toBe(true);
  });

  it('binds an extra read grant read-only', () => {
    const args = builder.build(
      policy({ reads: [ResourceRef.subtree(AbsolutePath.of('/home/dev/shared'))] }),
      CTX,
      COMMAND,
    );
    expect(hasPair(args, '--ro-bind-try', '/home/dev/shared')).toBe(true);
  });

  it('does not re-bind a path already covered by a system root', () => {
    const args = builder.build(
      policy({ reads: [ResourceRef.subtree(AbsolutePath.of('/usr/lib/node_modules'))] }),
      CTX,
      COMMAND,
    );
    expect(hasPair(args, '--ro-bind-try', '/usr/lib/node_modules')).toBe(false);
  });

  it('unshares the network when the policy allows none', () => {
    expect(builder.build(policy(), CTX, COMMAND)).toContain('--unshare-net');
  });

  it('keeps the network when the policy allows any', () => {
    const args = builder.build(policy({ network: [NetworkRule.tcp(443)] }), CTX, COMMAND);
    expect(args).not.toContain('--unshare-net');
  });

  it('shadows an anchored refusal with an empty tmpfs', () => {
    const args = builder.build(
      policy({
        reads: [ResourceRef.subtree(HOME)],
        denies: [new DenyRule('ssh-keys', PathPattern.of('~/.ssh/**'), 'read', 'keys')],
      }),
      CTX,
      COMMAND,
    );
    expect(hasPair(args, '--tmpfs', '/home/dev/.ssh')).toBe(true);
  });

  it('mounts a hand-written override after the shadowing, so it survives', () => {
    const args = builder.build(
      policy({
        denies: [new DenyRule('ssh-keys', PathPattern.of('~/.ssh/**'), 'read', 'keys')],
        overrides: [
          {
            ref: ResourceRef.file(AbsolutePath.of('/home/dev/.ssh/deploy_key')),
            access: 'read',
            reason: 'build key',
          },
        ],
      }),
      CTX,
      COMMAND,
    );
    expect(args.lastIndexOf('/home/dev/.ssh/deploy_key')).toBeGreaterThan(
      args.indexOf('/home/dev/.ssh'),
    );
  });

  it('puts the command last, after a -- separator', () => {
    const args = builder.build(policy(), CTX, COMMAND);
    expect(args.slice(args.indexOf('--'))).toEqual(['--', '/usr/bin/claude', '--help']);
  });
});

describe('BubblewrapRunner honesty about its limits', () => {
  const runner = new BubblewrapRunner();

  it('reports a wildcard refusal it cannot express', () => {
    const gaps = runner.unenforceable(
      policy({ denies: [new DenyRule('env', PathPattern.of('**/.env'), 'read', 'secrets')] }),
      CTX,
    );
    expect(gaps.join(' ')).toMatch(/no fixed anchor/);
  });

  it('reports that per-port network rules degrade to all-or-nothing', () => {
    const gaps = runner.unenforceable(policy({ network: [NetworkRule.tcp(443)] }), CTX);
    expect(gaps.join(' ')).toMatch(/on or off/);
  });

  it('reports nothing when the policy fits the mechanism', () => {
    const gaps = runner.unenforceable(
      policy({ denies: [new DenyRule('ssh-keys', PathPattern.of('~/.ssh/**'), 'read', 'k')] }),
      CTX,
    );
    expect(gaps).toEqual([]);
  });

  it('describes its own capabilities', () => {
    expect(runner.capabilities).toEqual({
      mechanism: 'bubblewrap',
      fileModel: 'mount-namespace',
      networkGranularity: 'all-or-nothing',
    });
  });
});

describe('NoopRunner never pretends', () => {
  it('reports the entire policy as unenforced', () => {
    const gaps = new NoopRunner().unenforceable(policy(), CTX);
    expect(gaps).toHaveLength(1);
    expect(gaps[0]).toMatch(/full user permissions/);
  });
});
