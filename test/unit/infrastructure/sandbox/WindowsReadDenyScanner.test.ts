import { describe, expect, it } from 'vitest';
import { DenyRule } from '../../../../src/domain/policy/DenyRule.js';
import { SandboxPolicy } from '../../../../src/domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { PathPattern } from '../../../../src/domain/value-objects/PathPattern.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';
import {
  WindowsReadDenyScanner,
  type WindowsTreeEntry,
} from '../../../../src/infrastructure/sandbox/WindowsReadDenyScanner.js';

const home = AbsolutePath.of(String.raw`C:\Users\Dev`);
const workspace = home.join('projects/app');
const context = { home, workspace, platform: 'win32' as const };
const toolchain = home.join('.nvm');
const envDeny = new DenyRule(
  'env-outside-workspace',
  PathPattern.of('**/.env'),
  'read',
  'secret',
  workspace,
);
const envVariantDeny = new DenyRule(
  'env-variant-outside-workspace',
  PathPattern.of('**/.env.*'),
  'read',
  'secret',
  workspace,
);

function policy(): SandboxPolicy {
  return new SandboxPolicy({
    workspace,
    reads: [ResourceRef.subtree(toolchain)],
    writes: [],
    denies: [envDeny, envVariantDeny],
    overrides: [],
    network: [],
  });
}

describe('WindowsReadDenyScanner', () => {
  it('turns existing denied files in a read-only tree into exact native deny entries', async () => {
    const entries: readonly WindowsTreeEntry[] = [
      { path: toolchain, directory: true },
      { path: toolchain.join('node.exe'), directory: false },
      { path: toolchain.join('versions/20/.env'), directory: false },
      { path: toolchain.join('versions/20/.env.local'), directory: false },
    ];
    const scanner = new WindowsReadDenyScanner(async () => entries);

    await expect(
      scanner.scan(
        [{ root: ResourceRef.subtree(toolchain), denies: [envDeny, envVariantDeny] }],
        policy(),
        context,
      ),
    ).resolves.toEqual([
      { scope: 'file', path: toolchain.join('versions/20/.env').value, access: 'read' },
      { scope: 'file', path: toolchain.join('versions/20/.env.local').value, access: 'read' },
    ]);
  });

  it('honours a manual override instead of installing a contradictory deny ACE', async () => {
    const target = toolchain.join('versions/20/.env');
    const overridden = new SandboxPolicy({
      workspace,
      reads: [ResourceRef.subtree(toolchain)],
      writes: [],
      denies: [envDeny],
      overrides: [{ ref: ResourceRef.file(target), access: 'read', reason: 'manual' }],
      network: [],
    });
    const scanner = new WindowsReadDenyScanner(async () => [
      { path: toolchain, directory: true },
      { path: target, directory: false },
    ]);

    await expect(
      scanner.scan(
        [{ root: ResourceRef.subtree(toolchain), denies: [envDeny] }],
        overridden,
        context,
      ),
    ).resolves.toEqual([]);
  });

  it('collapses descendants when a denied directory already blocks the subtree', async () => {
    const ssh = home.join('.ssh');
    const deny = new DenyRule('ssh', PathPattern.of('~/.ssh/**'), 'read', 'keys');
    const broad = new SandboxPolicy({
      workspace,
      reads: [ResourceRef.subtree(home)],
      writes: [],
      denies: [deny],
      overrides: [],
      network: [],
    });
    const scanner = new WindowsReadDenyScanner(async () => [
      { path: home, directory: true },
      { path: ssh, directory: true },
      { path: ssh.join('id_rsa'), directory: false },
    ]);

    await expect(
      scanner.scan(
        [{ root: ResourceRef.subtree(home), denies: [deny] }],
        broad,
        context,
      ),
    ).resolves.toEqual([{ scope: 'subtree', path: ssh.value, access: 'read' }]);
  });
});
