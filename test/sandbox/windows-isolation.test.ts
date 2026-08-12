import { createServer } from 'node:net';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
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
      const runtime = AbsolutePath.of(process.execPath).parent.parent;
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
});

function windowsEnvironment(): Readonly<Record<string, string>> {
  return Object.fromEntries(
    Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
  );
}
