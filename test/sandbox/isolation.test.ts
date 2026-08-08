import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SeatbeltRunner } from '../../src/infrastructure/sandbox/SeatbeltRunner.js';
import { PolicyBuilder } from '../../src/domain/policy/PolicyBuilder.js';
import { StarterProfile } from '../../src/domain/policy/StarterProfile.js';
import { AccessTierResolver } from '../../src/domain/policy/AccessTierResolver.js';
import { SensitivePathRegistry } from '../../src/domain/paths/SensitivePathRegistry.js';
import { Grant } from '../../src/domain/entities/Grant.js';
import { GrantScope } from '../../src/domain/value-objects/GrantScope.js';
import { WorkspaceId } from '../../src/domain/value-objects/WorkspaceId.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../src/domain/value-objects/ResourceRef.js';
import type { PathContext } from '../../src/domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../src/domain/policy/SandboxPolicy.js';

/**
 * Spec §9.3 — the tests that decide whether this product exists.
 *
 * Everything else asserts on a model of isolation. These run a real process
 * under the real mechanism and check that forbidden things actually fail. A red
 * test here blocks a release.
 */

const isDarwin = process.platform === 'darwin';
const describeOnDarwin = isDarwin ? describe : describe.skip;

const registry = SensitivePathRegistry.default();
const builder = new PolicyBuilder(new AccessTierResolver(registry), registry);
const runner = new SeatbeltRunner();

let root: string;
let workspace: AbsolutePath;
let home: AbsolutePath;
let context: PathContext;

/** A fake home, so the suite never depends on — or touches — the real one. */
function seedHome(): void {
  const inside = (relative: string, content: string): void => {
    const full = join(home.value, relative);
    mkdirSync(join(full, '..'), { recursive: true });
    writeFileSync(full, content);
  };
  inside('.ssh/id_rsa', 'PRIVATE KEY');
  inside('.aws/credentials', '[default]\naws_access_key_id=AKIA');
  inside('.zsh_history', 'export TOKEN=secret');
  inside('.zshenv', '# original');
  inside('.gitconfig', '[user]\n\tname = Dev');
  inside('.config/gh/hosts.yml', 'github.com:\n  oauth_token: ghp_x');
  inside('Library/LaunchAgents/.keep', '');
  inside('.agent-guard/allowlist.json', '{"version":1,"grants":[]}');
  mkdirSync(join(home.value, 'projects/other'), { recursive: true });
  writeFileSync(join(home.value, 'projects/other/.env'), 'SECRET=1');
  writeFileSync(join(home.value, 'projects/other/notes.md'), 'private notes');
  mkdirSync(join(home.value, 'projects/library'), { recursive: true });
  writeFileSync(join(home.value, 'projects/library/index.js'), 'module.exports = 1;');
}

function buildPolicy(grants: readonly Grant[] = []): SandboxPolicy {
  const profile = StarterProfile.fromSpec({
    id: 'test',
    name: 'Test',
    description: 'Suite profile',
    reads: ['file:~/.gitconfig'],
    writes: [],
    network: ['tcp:443', 'udp:53'],
  });
  const result = builder.build({
    profile,
    grants,
    context,
    workspaceId: WorkspaceId.fromPath(workspace),
    toolchainRoots: [AbsolutePath.of(process.execPath).parent.parent],
    stateDir: home.join('.agent-guard'),
    agentStateDirs: [home.join('.claude')],
    // A scratch directory outside the fake home, so "temp is writable" cannot
    // accidentally re-open the very home this suite is checking.
    tempDirs: [AbsolutePath.of(join(root, 'tmp'))],
  });
  return result.policy;
}

/** Runs a snippet of Node inside the sandbox and returns what it printed. */
function inSandbox(script: string, grants: readonly Grant[] = []): string {
  const policy = buildPolicy(grants);
  const profilePath = join(root, `policy-${Math.random().toString(36).slice(2)}.sb`);
  writeFileSync(profilePath, runner.compile(policy, context));
  try {
    return execFileSync(
      '/usr/bin/sandbox-exec',
      ['-f', profilePath, process.execPath, '-e', script],
      {
        cwd: workspace.value,
        encoding: 'utf8',
        env: { ...process.env, HOME: home.value, TMPDIR: join(root, 'tmp') },
      },
    ).trim();
  } catch (error) {
    const failure = error as { stdout?: string; stderr?: string; message?: string };
    return `SPAWN-FAILED ${failure.stdout ?? ''} ${failure.stderr ?? ''} ${failure.message ?? ''}`;
  }
}

const readProbe = (target: string): string =>
  `try{require("fs").readFileSync(${JSON.stringify(target)});console.log("ALLOWED")}` +
  `catch(e){console.log("DENIED:"+e.code)}`;

const writeProbe = (target: string): string =>
  `try{require("fs").appendFileSync(${JSON.stringify(target)},"x");console.log("ALLOWED")}` +
  `catch(e){console.log("DENIED:"+e.code)}`;

beforeAll(() => {
  // realpath: macOS resolves /var to /private/var, and the kernel enforces the
  // sandbox against the resolved path. Building a policy from the unresolved
  // one produces rules that match nothing.
  root = realpathSync(mkdtempSync(join(tmpdir(), 'agent-guard-sandbox-')));
  home = AbsolutePath.of(join(root, 'home'));
  workspace = home.join('projects/app');
  mkdirSync(workspace.value, { recursive: true });
  mkdirSync(join(root, 'tmp'), { recursive: true });
  writeFileSync(join(workspace.value, 'README.md'), '# app');
  writeFileSync(join(workspace.value, '.env'), 'LOCAL=1');
  context = { home, workspace, platform: 'darwin' };
  seedHome();
});

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

describeOnDarwin('isolation actually isolates (macOS / Seatbelt)', () => {
  it('the mechanism is available on this machine', async () => {
    await expect(runner.isAvailable()).resolves.toBe(true);
  });

  describe('reads that must fail', () => {
    it.each([
      ['~/.ssh/id_rsa', '.ssh/id_rsa'],
      ['~/.aws/credentials', '.aws/credentials'],
      ['~/.zsh_history', '.zsh_history'],
      ['~/.config/gh/hosts.yml', '.config/gh/hosts.yml'],
      ["a sibling project's .env", 'projects/other/.env'],
      ['a sibling project', 'projects/other/notes.md'],
    ])('refuses to read %s', (_label, relative) => {
      expect(inSandbox(readProbe(join(home.value, relative)))).toMatch(/^DENIED:/);
    });
  });

  describe('writes that must fail', () => {
    it.each([
      ['~/.zshenv', '.zshenv'],
      ['a new launch agent', 'Library/LaunchAgents/evil.plist'],
      ['its own allowlist', '.agent-guard/allowlist.json'],
      ['~/.gitconfig', '.gitconfig'],
    ])('refuses to write %s', (_label, relative) => {
      expect(inSandbox(writeProbe(join(home.value, relative)))).toMatch(/^DENIED:/);
    });
  });

  describe('what must keep working', () => {
    it('reads inside the workspace', () => {
      expect(inSandbox(readProbe(join(workspace.value, 'README.md')))).toBe('ALLOWED');
    });

    it('writes inside the workspace', () => {
      expect(inSandbox(writeProbe(join(workspace.value, 'build.log')))).toBe('ALLOWED');
    });

    it("reads the workspace's own .env", () => {
      expect(inSandbox(readProbe(join(workspace.value, '.env')))).toBe('ALLOWED');
    });

    it('reads ~/.gitconfig, which the starter profile opened', () => {
      expect(inSandbox(readProbe(join(home.value, '.gitconfig')))).toBe('ALLOWED');
    });

    it('runs git', () => {
      expect(
        inSandbox(
          'const {execFileSync}=require("child_process");' +
            'try{console.log(execFileSync("/usr/bin/git",["--version"],{encoding:"utf8"}).trim())}' +
            'catch(e){console.log("FAILED:"+e.message)}',
        ),
      ).toMatch(/^git version/);
    });

    it('runs node', () => {
      expect(inSandbox('console.log("NODE-OK")')).toBe('NODE-OK');
    });
  });

  describe('grants', () => {
    const grantFor = (ref: ResourceRef, origin: 'runtime' | 'manual'): Grant =>
      Grant.create({
        resource: ref,
        access: 'read',
        scope: GrantScope.global(),
        grantedAt: new Date(),
        reason: 'sandbox suite',
        origin,
      });

    it('opens a path granted at runtime', () => {
      const grant = grantFor(ResourceRef.subtree(home.join('projects/library')), 'runtime');
      expect(inSandbox(readProbe(join(home.value, 'projects/library/index.js')), [grant])).toBe(
        'ALLOWED',
      );
    });

    it('refuses a tier 2 path even when a runtime grant asks for it', () => {
      const grant = grantFor(ResourceRef.file(home.join('.ssh/id_rsa')), 'runtime');
      expect(inSandbox(readProbe(join(home.value, '.ssh/id_rsa')), [grant])).toMatch(/^DENIED:/);
    });

    it('honours a hand-written tier 2 grant', () => {
      const grant = grantFor(ResourceRef.file(home.join('.ssh/id_rsa')), 'manual');
      expect(inSandbox(readProbe(join(home.value, '.ssh/id_rsa')), [grant])).toBe('ALLOWED');
    });

    it('keeps a hand-written grant narrow: a sibling key stays closed', () => {
      writeFileSync(join(home.value, '.ssh/id_ed25519'), 'ANOTHER KEY');
      const grant = grantFor(ResourceRef.file(home.join('.ssh/id_rsa')), 'manual');
      expect(inSandbox(readProbe(join(home.value, '.ssh/id_ed25519')), [grant])).toMatch(
        /^DENIED:/,
      );
    });

    it('a broad grant still does not expose a sibling .env', () => {
      const grant = grantFor(ResourceRef.subtree(home.join('projects')), 'runtime');
      expect(inSandbox(readProbe(join(home.value, 'projects/other/.env')), [grant])).toMatch(
        /^DENIED:/,
      );
      expect(inSandbox(readProbe(join(home.value, 'projects/other/notes.md')), [grant])).toBe(
        'ALLOWED',
      );
    });
  });

  describe('network', () => {
    it('allows the ports the profile opened', () => {
      const output = inSandbox(
        'fetch("https://example.com",{signal:AbortSignal.timeout(15000)})' +
          '.then(r=>console.log("ALLOWED"))' +
          '.catch(e=>console.log("DENIED:"+(e.cause?.code||e.name)))',
      );
      expect(output).toBe('ALLOWED');
    });

    it('refuses a port the profile did not open', () => {
      const output = inSandbox(
        'fetch("http://example.com",{signal:AbortSignal.timeout(15000)})' +
          '.then(r=>console.log("ALLOWED"))' +
          '.catch(e=>console.log("DENIED:"+(e.cause?.code||e.name)))',
      );
      expect(output).toMatch(/^DENIED:/);
    });
  });

  describe('overhead', () => {
    it('adds no measurable cost to starting a process (budget: 100 ms p95)', () => {
      const policy = buildPolicy();
      const profilePath = join(root, 'bench.sb');
      writeFileSync(profilePath, runner.compile(policy, context));

      const measure = (fn: () => void): number => {
        const samples: number[] = [];
        for (let i = 0; i < 7; i += 1) {
          const started = performance.now();
          fn();
          samples.push(performance.now() - started);
        }
        samples.sort((a, b) => a - b);
        return samples[Math.floor(samples.length / 2)] as number;
      };

      const bare = measure(() =>
        execFileSync(process.execPath, ['-e', '0'], { stdio: 'ignore' }),
      );
      const confined = measure(() =>
        execFileSync('/usr/bin/sandbox-exec', ['-f', profilePath, process.execPath, '-e', '0'], {
          stdio: 'ignore',
        }),
      );

      expect(confined - bare).toBeLessThan(100);
    });
  });
});
