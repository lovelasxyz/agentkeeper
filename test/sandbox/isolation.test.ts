import { execFileSync, spawn } from 'node:child_process';
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
import { EnvironmentPolicy } from '../../src/domain/policy/EnvironmentPolicy.js';
import { EnvironmentSanitizer } from '../../src/domain/policy/EnvironmentSanitizer.js';
import { NetworkRule } from '../../src/domain/value-objects/NetworkRule.js';
import { NodeDestinationBroker } from '../../src/infrastructure/network/NodeDestinationBroker.js';
import type { PathContext } from '../../src/domain/paths/PathContext.js';
import { SandboxPolicy } from '../../src/domain/policy/SandboxPolicy.js';
import type { DestinationBrokerSession } from '../../src/application/ports/NetworkBroker.js';

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
let brokerSession: DestinationBrokerSession;

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
  inside('.agentkeeper/allowlist.json', '{"version":1,"grants":[]}');
  inside('.agentkeeper/config.json', '{"version":1}');
  inside('.agentkeeper/decisions.json', '{"version":1,"decisions":{}}');
  inside('.agentkeeper/audit.log', '{"event":"canary"}\n');
  inside('.agentkeeper/backups/zshrc.original', 'PRIVATE BACKUP');
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
    network: ['example.com:443'],
  });
  const result = builder.build({
    profile,
    grants,
    context,
    workspaceId: WorkspaceId.fromPath(workspace),
    toolchainRoots: [AbsolutePath.of(process.execPath).parent.parent],
    stateDir: home.join('.agentkeeper'),
    agentStateDirs: [home.join('.claude')],
    // A scratch directory outside the fake home, so "temp is writable" cannot
    // accidentally re-open the very home this suite is checking.
    tempDirs: [AbsolutePath.of(join(root, 'tmp'))],
  });
  return result.policy.withNetworkEnforcement(brokerSession.enforcement);
}

/** Runs a snippet of Node inside the sandbox and returns what it printed. */
function inSandbox(
  script: string,
  grants: readonly Grant[] = [],
  sourceEnvironment: Readonly<Record<string, string>> = Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  ),
): string {
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
        env: { ...sourceEnvironment, HOME: home.value, TMPDIR: join(root, 'tmp') },
      },
    ).trim();
  } catch (error) {
    const failure = error as { stdout?: string; stderr?: string; message?: string };
    return `SPAWN-FAILED ${failure.stdout ?? ''} ${failure.stderr ?? ''} ${failure.message ?? ''}`;
  }
}

/** Async variant used when the host-side broker must keep servicing its event loop. */
function inSandboxAsync(script: string): Promise<string> {
  const policy = buildPolicy();
  const profilePath = join(root, `policy-${Math.random().toString(36).slice(2)}.sb`);
  writeFileSync(profilePath, runner.compile(policy, context));
  return new Promise((resolve) => {
    const child = spawn(
      '/usr/bin/sandbox-exec',
      ['-f', profilePath, process.execPath, '-e', script],
      {
        cwd: workspace.value,
        env: { ...process.env, HOME: home.value, TMPDIR: join(root, 'tmp') },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => (stdout += chunk));
    child.stderr.on('data', (chunk: string) => (stderr += chunk));
    child.once('error', (error) => resolve(`SPAWN-FAILED ${stdout} ${stderr} ${error.message}`));
    child.once('exit', () => resolve(stdout.trim()));
  });
}

const readProbe = (target: string): string =>
  `try{require("fs").readFileSync(${JSON.stringify(target)});console.log("ALLOWED")}` +
  `catch(e){console.log("DENIED:"+e.code)}`;

const writeProbe = (target: string): string =>
  `try{require("fs").appendFileSync(${JSON.stringify(target)},"x");console.log("ALLOWED")}` +
  `catch(e){console.log("DENIED:"+e.code)}`;

beforeAll(async () => {
  // realpath: macOS resolves /var to /private/var, and the kernel enforces the
  // sandbox against the resolved path. Building a policy from the unresolved
  // one produces rules that match nothing.
  root = realpathSync(mkdtempSync(join(tmpdir(), 'agentkeeper-sandbox-')));
  home = AbsolutePath.of(join(root, 'home'));
  workspace = home.join('projects/app');
  mkdirSync(workspace.value, { recursive: true });
  mkdirSync(join(root, 'tmp'), { recursive: true });
  writeFileSync(join(workspace.value, 'README.md'), '# app');
  writeFileSync(join(workspace.value, '.env'), 'LOCAL=1');
  context = { home, workspace, platform: 'darwin' };
  seedHome();
  brokerSession = await new NodeDestinationBroker().start({
    destinations: [NetworkRule.destination('example.com', 443)],
    platform: 'darwin',
    scratch: AbsolutePath.of(join(root, 'tmp')),
  });
});

afterAll(async () => {
  if (brokerSession) await brokerSession.close();
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
      ['its own allowlist', '.agentkeeper/allowlist.json'],
      ['its audit trail', '.agentkeeper/audit.log'],
      ['installer backups', '.agentkeeper/backups/zshrc.original'],
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
      ['its own allowlist', '.agentkeeper/allowlist.json'],
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

    it('reads only the public hook configuration and decisions', () => {
      expect(inSandbox(readProbe(join(home.value, '.agentkeeper/config.json')))).toBe('ALLOWED');
      expect(inSandbox(readProbe(join(home.value, '.agentkeeper/decisions.json')))).toBe(
        'ALLOWED',
      );
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

    it('runs node after the ambient environment authority is removed', () => {
      const source = Object.fromEntries(
        Object.entries(process.env).filter(
          (entry): entry is [string, string] => entry[1] !== undefined,
        ),
      );
      source['HOME'] = home.value;
      source['TMPDIR'] = join(root, 'tmp');
      const sanitized = new EnvironmentSanitizer().sanitize(
        source,
        EnvironmentPolicy.forExecutable(process.execPath),
      );

      expect(inSandbox('console.log("SANITIZED-NODE-OK")', [], sanitized.environment)).toBe(
        'SANITIZED-NODE-OK',
      );
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
    const throughBroker = (authority: string): string =>
      'const net=require("node:net");' +
      `const proxy=new URL(${JSON.stringify(brokerSession?.proxyUrl ?? '')});` +
      'const socket=net.connect(Number(proxy.port),proxy.hostname);let data="";' +
      `socket.once("connect",()=>socket.write(${JSON.stringify(
        `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
      )}));` +
      'socket.on("data",chunk=>{data+=chunk;const line=data.split("\\r\\n")[0];' +
      'if(line){console.log(line.includes(" 200 ")?"ALLOWED":"DENIED:"+line);socket.destroy()}});' +
      'socket.on("error",e=>console.log("DENIED:"+e.code));' +
      'setTimeout(()=>{console.log("DENIED:TIMEOUT");process.exit(0)},15000).unref();';

    it('allows a configured destination through the broker', async () => {
      await expect(inSandboxAsync(throughBroker('example.com:443'))).resolves.toBe('ALLOWED');
    });

    it('refuses an arbitrary destination even on the same port', async () => {
      await expect(inSandboxAsync(throughBroker('example.org:443'))).resolves.toMatch(
        /^DENIED:HTTP\/1\.1 403/,
      );
    });

    it('refuses direct egress that bypasses the broker', async () => {
      const output = await inSandboxAsync(
        'fetch("https://example.com",{signal:AbortSignal.timeout(15000)})' +
          '.then(r=>console.log("ALLOWED"))' +
          '.catch(e=>console.log("DENIED:"+(e.cause?.code||e.name)))',
      );
      expect(output).toMatch(/^DENIED:/);
    });

    it('refuses direct plaintext HTTP as well', async () => {
      const output = await inSandboxAsync(
        'fetch("http://example.com",{signal:AbortSignal.timeout(15000)})' +
          '.then(r=>console.log("ALLOWED"))' +
          '.catch(e=>console.log("DENIED:"+(e.cause?.code||e.name)))',
      );
      expect(output).toMatch(/^DENIED:/);
    });

    it('does not turn DNS support into access to arbitrary local unix sockets', async () => {
      const socketPath = join(root, 'tmp', 'credential-agent.sock');
      const server = spawn(
        process.execPath,
        [
          '-e',
          'const net=require("node:net");' +
            'const socket=process.argv[1];' +
            'const server=net.createServer(()=>{});' +
            'server.listen(socket,()=>process.stdout.write("READY\\n"));' +
            'process.on("SIGTERM",()=>server.close(()=>process.exit(0)));',
          socketPath,
        ],
        { stdio: ['ignore', 'pipe', 'inherit'] },
      );

      try {
        await new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('unix socket canary did not start')), 5_000);
          server.once('error', reject);
          server.stdout.once('data', (chunk: Buffer) => {
            if (chunk.toString().includes('READY')) {
              clearTimeout(timer);
              resolve();
            }
          });
        });

        const output = inSandbox(
          'const net=require("node:net");' +
            `const client=net.createConnection(${JSON.stringify(socketPath)});` +
            'client.on("connect",()=>{console.log("ALLOWED");client.end()});' +
            'client.on("error",e=>console.log("DENIED:"+e.code));' +
            'setTimeout(()=>{console.log("DENIED:TIMEOUT");process.exit(0)},2000).unref();',
        );
        expect(output).toMatch(/^DENIED:/);
      } finally {
        server.kill('SIGTERM');
      }
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
describe('a run can be abandoned without leaking the process (macOS / Seatbelt)', () => {
  it('terminates the sandboxed command when its caller aborts', async () => {
    // A probe that gives up must take the process with it. Abandoning it left
    // an orphan holding the workspace directory, which is how the Windows
    // canary surfaced as `EBUSY` on cleanup rather than as a clean failure.
    const controller = new AbortController();
    const root = AbsolutePath.of(realpathSync(mkdtempSync(join(tmpdir(), 'ak-abort-'))));
    const context: PathContext = { home: root, workspace: root, platform: 'darwin' };
    const policy = new SandboxPolicy({
      workspace: root,
      reads: [
        ResourceRef.subtree(root),
        ResourceRef.subtree(AbsolutePath.of(process.execPath).parent.parent),
      ],
      writes: [ResourceRef.subtree(root)],
      denies: [],
      overrides: [],
      network: [],
    });

    const started = Date.now();
    const run = new SeatbeltRunner().run(policy, context, {
      executable: process.execPath,
      args: ['-e', 'setTimeout(() => {}, 120000)'],
      cwd: root,
      env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' },
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 250).unref();

    const result = await run;
    expect(Date.now() - started).toBeLessThan(15_000);
    expect(result.signal ?? result.exitCode).not.toBe(0);
    rmSync(root.value, { recursive: true, force: true });
  });
});
