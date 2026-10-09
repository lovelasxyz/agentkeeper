import { createServer } from 'node:net';
import { execFile } from 'node:child_process';
import { link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { NodeSandboxProbe } from '../../src/infrastructure/sandbox/NodeSandboxProbe.js';
import { WindowsSandboxRunner } from '../../src/infrastructure/sandbox/WindowsSandboxRunner.js';
import { AssessProtection } from '../../src/application/use-cases/AssessProtection.js';
import { SandboxPolicy } from '../../src/domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../src/domain/value-objects/ResourceRef.js';

const describeOnWindows = process.platform === 'win32' ? describe : describe.skip;
const executeFile = promisify(execFile);

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

  it.each(['inherit', 'pipe', 'ignore'] as const)('confines descendants with %s standard streams', async (stdio) => {
    const outside = join(root, `descendant-${stdio}.secret`);
    await writeFile(outside, 'secret');
    try {
      const childScript = `try{require('node:fs').readFileSync(${JSON.stringify(outside)});process.exit(42)}catch{process.exit(0)}`;
      const result = await runScript([
        "const cp=require('node:child_process');",
        `const child=cp.spawnSync(process.execPath,['-e',${JSON.stringify(childScript)}],{stdio:${JSON.stringify(stdio)},timeout:5000,killSignal:'SIGKILL'});`,
        "if(child.status!==0){console.error('descendant diagnostic',JSON.stringify({status:child.status,signal:child.signal,error:child.error?.code,stderr:child.stderr?.toString().slice(0,1000)}));process.exit(44)}",
      ].join(''));
      expect(result.exitCode).toBe(0);
    } finally {
      await rm(outside, { force: true });
    }
  });

  it('reclaims a hung child through the helper deadline and can immediately run again', async () => {
    await expect(runScript('setInterval(()=>{},1000)', 500)).rejects.toMatchObject({
      code: 'windows.child-timed-out',
    });
    expect((await runScript('process.exit(0)')).exitCode).toBe(0);
  });

  it.each(['normal', 'timeout'] as const)('removes workspace capabilities after %s exit', async (mode) => {
    const directory = workspace.join(`acl-cleanup-${mode}`);
    const existing = directory.join('existing.txt');
    const created = directory.join('created.txt');
    await mkdir(directory.value);
    await writeFile(existing.value, 'original');
    const paths = [workspace.value, directory.value, existing.value];
    const before = await Promise.all(paths.map(readDacl));
    try {
      const script = [
        "const fs=require('node:fs');",
        `fs.writeFileSync(${JSON.stringify(created.value)}, 'created');`,
        ...(mode === 'timeout' ? ['setInterval(()=>{},1000);'] : []),
      ].join('');
      if (mode === 'timeout') {
        await expect(runScript(script, 2000)).rejects.toMatchObject({ code: 'windows.child-timed-out' });
      } else {
        expect((await runScript(script)).exitCode).toBe(0);
      }
      expect(await Promise.all(paths.map(readDacl))).toEqual(before);
      // A file created during the session must lose the ephemeral package SID
      // too. Removing just the root ACE does not prove recursive rollback.
      expect(await readDacl(created.value)).not.toMatch(/S-1-15-2-\d+-/);
    } finally {
      await rm(directory.value, { recursive: true, force: true });
    }
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

async function readDacl(path: string): Promise<string> {
  const windows = process.env['SystemRoot'];
  if (windows === undefined) throw new Error('Windows directory is unavailable');
  const { stdout } = await executeFile(
    join(windows, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      "$ErrorActionPreference='Stop'; $p=$env:AGENTKEEPER_TEST_ACL_PATH; $acl=if([System.IO.Directory]::Exists($p)){[System.IO.Directory]::GetAccessControl($p)}else{[System.IO.File]::GetAccessControl($p)}; $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)"],
    { env: { ...process.env, AGENTKEEPER_TEST_ACL_PATH: path }, timeout: 10_000 },
  );
  return stdout.trim();
}
