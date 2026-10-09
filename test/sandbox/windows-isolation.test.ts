import { createServer } from 'node:net';
import { link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { NodeSandboxProbe } from '../../src/infrastructure/sandbox/NodeSandboxProbe.js';
import { WindowsSandboxRunner } from '../../src/infrastructure/sandbox/WindowsSandboxRunner.js';
import { AssessProtection } from '../../src/application/use-cases/AssessProtection.js';
import { SandboxPolicy } from '../../src/domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../src/domain/value-objects/ResourceRef.js';

const describeOnWindows = process.platform === 'win32' ? describe : describe.skip;

describeOnWindows('isolation actually isolates (Windows / AppContainer)', () => {
  const runner = new WindowsSandboxRunner();
  let root: string;
  let workspace: AbsolutePath;

  beforeAll(async () => {
    root = await mkdtemp(join(tmpdir(), 'agentkeeper-windows-sandbox-'));
    workspace = AbsolutePath.of(join(root, 'workspace'));
    await mkdir(workspace.value, { recursive: true });
  });

  afterAll(async () => {
    if (root !== undefined) await rm(root, { recursive: true, force: true });
  });

  it('passes a real direct and child-process deny canary', async () => {
    await expect(runner.isAvailable()).resolves.toBe(true);
    const result = await new NodeSandboxProbe().probe({ runner, platform: 'win32' });

    expect(result, JSON.stringify(result)).toMatchObject({
      passed: true,
      code: 'passed',
      checks: {
        workspaceReadAllowed: true,
        outsideReadDenied: true,
        childOutsideReadDenied: true,
      },
    });
  });

  it('reports DEGRADED only after the real canary passes, never from helper presence', async () => {
    const policy = new SandboxPolicy({
      workspace,
      reads: [ResourceRef.subtree(workspace)],
      writes: [ResourceRef.subtree(workspace)],
      denies: [],
      overrides: [],
      network: [],
    });
    const status = await new AssessProtection(new NodeSandboxProbe()).execute({
      platform: 'win32',
      runner,
      policy,
      context: {
        home: AbsolutePath.of(process.env['USERPROFILE'] ?? workspace.parent.value),
        workspace,
        platform: 'win32',
      },
    });

    expect(status.level, JSON.stringify(status)).toBe('DEGRADED');
    expect(status.capabilities.denyCanary).toBe('passed');
    expect(status.reasons.map((entry) => entry.code)).toContain(
      'appcontainer.compatibility-surface',
    );
  });

  it('denies loopback too when no network capability was granted', async () => {
    const server = createServer((socket) => socket.end());
    await new Promise<void>((resolveListen, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolveListen);
    });
    try {
      const address = server.address();
      if (address === null || typeof address === 'string') throw new Error('No TCP test port');
      const runtime = AbsolutePath.of(process.execPath).parent;
      const policy = new SandboxPolicy({
        workspace,
        reads: [ResourceRef.subtree(workspace), ResourceRef.subtree(runtime)],
        writes: [ResourceRef.subtree(workspace)],
        denies: [],
        overrides: [],
        network: [],
      });
      const result = await runner.run(
        policy,
        {
          home: AbsolutePath.of(process.env['USERPROFILE'] ?? workspace.parent.value),
          workspace,
          platform: 'win32',
        },
        {
          executable: process.execPath,
          args: [
            '-e',
            `const net=require('node:net');const socket=net.connect({host:'127.0.0.1',port:${address.port}},()=>process.exit(42));socket.on('error',()=>process.exit(0));setTimeout(()=>process.exit(0),2000);`,
          ],
          cwd: workspace,
          env: windowsEnvironment(),
          // The helper owns the Job Object, so it reclaims a stuck child
          // itself rather than leaving the suite to time out around it.
          deadlineMs: 20_000,
        },
      );

      expect(result.exitCode).toBe(0);
    } finally {
      await new Promise<void>((resolveClose, reject) => {
        server.close((error) => (error === undefined ? resolveClose() : reject(error)));
      });
    }
  });

  it('writes, renames and deletes workspace files with a real sanitised environment', async () => {
    const result = await runScript([
      "const fs=require('node:fs');",
      "fs.writeSync(1,'Windows confined stdout works\\n');",
      "fs.writeSync(2,'Windows confined stderr works\\n');",
      "fs.writeFileSync('workspace-edit.tmp','ok');",
      "fs.renameSync('workspace-edit.tmp','workspace-edit.txt');",
      "if(fs.readFileSync('workspace-edit.txt','utf8')!=='ok')process.exit(41);",
      "fs.unlinkSync('workspace-edit.txt');",
      "if(!process.env.SystemRoot||!process.env.APPDATA||!process.env.LOCALAPPDATA)process.exit(42);",
      "if(!process.env.APPDATA.startsWith(process.env.USERPROFILE))process.exit(43);",
    ].join(''));
    expect(result.exitCode).toBe(0);
  });

  it.each([200, 203, 208])('preserves actual child exit %i instead of declaring a native failure', async (code) => {
    expect((await runScript(`process.exit(${code})`)).exitCode).toBe(code);
  });

  it('reclaims a hung child through the helper deadline and can immediately run again', async () => {
    await expect(runScript('setInterval(()=>{},1000)', 500)).rejects.toMatchObject({
      code: 'windows.child-timed-out',
    });
    expect((await runScript('process.exit(0)')).exitCode).toBe(0);
  });

  it('supports concurrent sessions without losing each other\'s workspace ACEs', async () => {
    const results = await Promise.all(Array.from({ length: 4 }, (_, index) => runScript([
      "const fs=require('node:fs');",
      `const path='parallel-${index}.txt';`,
      "let ticks=0;const timer=setInterval(()=>{fs.writeFileSync(path,'ok');if(++ticks===8){clearInterval(timer);fs.unlinkSync(path);}},50);",
    ].join(''))));
    expect(results.map((result) => result.exitCode)).toEqual([0, 0, 0, 0]);
  });

  it('refuses an existing hardlink before granting the outside object any access', async () => {
    const outside = join(root, 'outside-hardlink-secret.txt');
    const alias = workspace.join('innocent.txt').value;
    await writeFile(outside, 'secret');
    await link(outside, alias);
    try {
      await expect(runScript("require('node:fs').writeFileSync('launched.txt','unsafe')")).rejects.toMatchObject({
        code: 'windows.unsafe-path',
      });
      await expect(readFile(workspace.join('launched.txt').value)).rejects.toMatchObject({ code: 'ENOENT' });
      expect(await readFile(outside, 'utf8')).toBe('secret');
    } finally {
      await rm(alias, { force: true });
      await rm(outside, { force: true });
    }
  });

  it('refuses a junction inside the workspace before recursively changing ACLs', async () => {
    const outside = join(root, 'outside-junction');
    const alias = workspace.join('junction').value;
    await mkdir(outside);
    await symlink(outside, alias, 'junction');
    try {
      await expect(runScript('process.exit(0)')).rejects.toMatchObject({ code: 'windows.unsafe-path' });
    } finally {
      await rm(alias, { force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  async function runScript(script: string, deadlineMs = 15_000) {
    const policy = new SandboxPolicy({
      workspace,
      reads: [ResourceRef.subtree(workspace), ResourceRef.subtree(AbsolutePath.of(process.execPath).parent)],
      writes: [ResourceRef.subtree(workspace)],
      denies: [], overrides: [], network: [],
    });
    return runner.run(policy, {
      home: AbsolutePath.of(process.env['USERPROFILE'] ?? workspace.parent.value),
      workspace, platform: 'win32',
    }, {
      executable: process.execPath, args: ['-e', script], cwd: workspace,
      // The helper obtains SystemRoot from Win32. The ambient caller must
      // neither choose it nor provide the canonical user's profile paths.
      env: { PATH: process.env['PATH'] ?? '', SystemRoot: String.raw`C:\forged-windows` },
      deadlineMs,
    });
  }
});

function windowsEnvironment(): Readonly<Record<string, string>> {
  return Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}
