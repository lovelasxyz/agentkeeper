import { describe, expect, it } from 'vitest';
import { AccessTierResolver } from '../../../../src/domain/policy/AccessTierResolver.js';
import { PolicyBuilder } from '../../../../src/domain/policy/PolicyBuilder.js';
import { StarterProfile } from '../../../../src/domain/policy/StarterProfile.js';
import { SensitivePathRegistry } from '../../../../src/domain/paths/SensitivePathRegistry.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';
import { WorkspaceId } from '../../../../src/domain/value-objects/WorkspaceId.js';
import {
  WindowsPolicyTranslator,
  type WindowsPolicyPlan,
} from '../../../../src/infrastructure/sandbox/WindowsPolicyTranslator.js';

const home = AbsolutePath.of(String.raw`C:\Users\Dev`);
const workspace = home.join('projects', 'app');
const context = { home, workspace, platform: 'win32' as const };
const overlayHome = AbsolutePath.of(String.raw`C:\Temp\agentkeeper-profile\home`);

function defaultPlan(): WindowsPolicyPlan {
  const registry = SensitivePathRegistry.default();
  const builder = new PolicyBuilder(new AccessTierResolver(registry), registry);
  const profile = StarterProfile.fromSpec({
    id: 'windows-offline',
    name: 'Windows offline',
    description: 'Default policy fixture',
    reads: ['file:~/.gitconfig'],
    writes: [],
    network: [],
  });
  const { policy } = builder.build({
    profile,
    grants: [],
    context,
    workspaceId: WorkspaceId.fromPath(workspace),
    toolchainRoots: [home.join('.nvm'), AbsolutePath.of('C:/Program Files/nodejs')],
    stateDir: home.join('.agentkeeper'),
    agentStateDirs: ['.claude', '.gemini', '.cursor', '.codex', '.config/claude'].map(
      (relative) => home.join(relative),
    ),
    tempDirs: [home.join('AppData/Local/Temp/agentkeeper-123')],
  });
  return new WindowsPolicyTranslator().plan(policy, context, overlayHome);
}

describe('WindowsPolicyTranslator restricted profile', () => {
  it('makes the default offline policy expressible without granting canonical agent state', () => {
    const plan = defaultPlan();

    expect(plan.gaps).toEqual([]);
    for (const relative of ['.claude', '.gemini', '.cursor', '.codex', '.config/claude']) {
      const original = home.join(relative);
      expect(plan.reads.some((ref) => ref.path.equals(original))).toBe(false);
      expect(plan.writes.some((ref) => ref.path.equals(original))).toBe(false);
    }
    expect(plan.reads).toContainEqual(ResourceRef.subtree(overlayHome));
    expect(plan.writes).toContainEqual(ResourceRef.subtree(overlayHome));
  });

  it('keeps the real workspace read/write capability and its outside-workspace env exception', () => {
    const plan = defaultPlan();

    expect(plan.reads).toContainEqual(ResourceRef.subtree(workspace));
    expect(plan.writes).toContainEqual(ResourceRef.subtree(workspace));
    expect(plan.readDenyScans.some((scan) => scan.root.path.equals(workspace))).toBe(false);
  });

  it('requires bounded exact-deny discovery only for read-only toolchain trees', () => {
    const plan = defaultPlan();
    const roots = plan.readDenyScans.map((scan) => scan.root.path.value);

    expect(roots).toContain(home.join('.nvm').value);
    expect(roots).toContain(AbsolutePath.of('C:/Program Files/nodejs').value);
    expect(plan.readDenyScans.every((scan) => scan.denies.length > 0)).toBe(true);
  });

  it('returns a precise gap for an arbitrary persistent writable subtree with deny globs', () => {
    const registry = SensitivePathRegistry.default();
    const builder = new PolicyBuilder(new AccessTierResolver(registry), registry);
    const profile = StarterProfile.fromSpec({
      id: 'unsafe-write',
      name: 'Unsafe write',
      description: 'Fixture',
      reads: [],
      writes: ['dir:~/projects/library'],
      network: [],
    });
    const { policy } = builder.build({
      profile,
      grants: [],
      context,
      workspaceId: WorkspaceId.fromPath(workspace),
      toolchainRoots: [],
      stateDir: home.join('.agentkeeper'),
      agentStateDirs: [],
      tempDirs: [],
    });

    const plan = new WindowsPolicyTranslator().plan(policy, context, overlayHome);

    expect(plan.gaps).toContainEqual(
      expect.stringMatching(/env-file-outside-workspace.*persistent writable subtree/i),
    );
  });

  it('does not stage canonical files or contents into the overlay plan', () => {
    const plan = defaultPlan();

    expect(plan.overlay.seedFiles).toEqual([]);
    expect(plan.overlay.directories.map((path) => path.value)).toEqual([
      overlayHome.value,
      overlayHome.join('.claude').value,
      overlayHome.join('.gemini').value,
      overlayHome.join('.cursor').value,
      overlayHome.join('.codex').value,
      overlayHome.join('.config/claude').value,
      overlayHome.join('tmp').value,
    ]);
  });
});
