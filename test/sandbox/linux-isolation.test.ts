import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BubblewrapRunner } from '../../src/infrastructure/sandbox/BubblewrapRunner.js';
import { NodeDestinationBroker } from '../../src/infrastructure/network/NodeDestinationBroker.js';
import { SandboxPolicy } from '../../src/domain/policy/SandboxPolicy.js';
import { NetworkRule } from '../../src/domain/value-objects/NetworkRule.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { ResourceRef } from '../../src/domain/value-objects/ResourceRef.js';
import type { DestinationBrokerSession } from '../../src/application/ports/NetworkBroker.js';
import type { PathContext } from '../../src/domain/paths/PathContext.js';

const describeOnLinux = process.platform === 'linux' ? describe : describe.skip;
const runner = new BubblewrapRunner();

let root: string;
let home: AbsolutePath;
let workspace: AbsolutePath;
let scratch: AbsolutePath;
let secret: AbsolutePath;
let context: PathContext;
let broker: DestinationBrokerSession;

beforeAll(async () => {
  root = await realpath(await mkdtemp(join(tmpdir(), 'agentkeeper-linux-conformance-')));
  home = AbsolutePath.of(join(root, 'home'));
  workspace = home.join('workspace');
  scratch = AbsolutePath.of(join(root, 'scratch'));
  secret = home.join('private/credential');
  await mkdir(workspace.value, { recursive: true, mode: 0o700 });
  await mkdir(secret.parent.value, { recursive: true, mode: 0o700 });
  await mkdir(scratch.value, { recursive: true, mode: 0o700 });
  await writeFile(workspace.join('allowed').value, 'ok', { mode: 0o600 });
  await writeFile(secret.value, 'secret', { mode: 0o600 });
  context = { home, workspace, platform: 'linux' };
  broker = await new NodeDestinationBroker().start({
    destinations: [NetworkRule.destination('example.com', 443)],
    platform: 'linux',
    scratch,
  });
});

afterAll(async () => {
  if (broker) await broker.close();
  if (root) await rm(root, { recursive: true, force: true });
});

describeOnLinux('Linux bubblewrap + destination broker conformance', () => {
  it('has the required backend rather than silently skipping protection', async () => {
    await expect(runner.isAvailable()).resolves.toBe(true);
  });

  it('confines filesystem, children and direct network while brokered destination works', async () => {
    const runtimeRoot = AbsolutePath.of(process.execPath).parent.parent;
    const policy = new SandboxPolicy({
      workspace,
      reads: [
        ResourceRef.subtree(workspace),
        ResourceRef.subtree(runtimeRoot),
        ResourceRef.subtree(scratch),
      ],
      writes: [ResourceRef.subtree(workspace), ResourceRef.subtree(scratch)],
      denies: [],
      overrides: [],
      network: [NetworkRule.destination('example.com', 443)],
      networkEnforcement: broker.enforcement,
    });
    expect(runner.unenforceable(policy, context)).toEqual([]);

    const result = await runner.run(policy, context, {
      executable: process.execPath,
      args: ['-e', canaryScript(workspace.join('allowed').value, secret.value)],
      cwd: workspace,
      env: {
        HOME: home.value,
        TMPDIR: scratch.value,
        PATH: process.env['PATH'] ?? '/usr/bin:/bin',
        HTTP_PROXY: broker.proxyUrl,
        HTTPS_PROXY: broker.proxyUrl,
        NO_PROXY: '',
      },
    });
    expect(result).toEqual({ exitCode: 0, signal: null });
  });
});

function canaryScript(allowed: string, denied: string): string {
  return `
const fs = require('node:fs');
const cp = require('node:child_process');
const net = require('node:net');
try { fs.readFileSync(${JSON.stringify(allowed)}); } catch { process.exit(41); }
try { fs.readFileSync(${JSON.stringify(denied)}); process.exit(42); } catch {}
const child = cp.spawnSync(process.execPath, ['-e',
  'const fs=require("node:fs");try{fs.readFileSync(process.argv[1]);process.exit(42)}catch{process.exit(0)}',
  ${JSON.stringify(denied)}], { stdio: 'ignore' });
if (child.status !== 0) process.exit(43);
const proxy = new URL(process.env.HTTPS_PROXY);
function request(authority) { return new Promise((resolve) => {
  const socket = net.connect(Number(proxy.port), proxy.hostname);
  let response = '';
  const timer = setTimeout(() => { socket.destroy(); resolve(0); }, 15000);
  socket.once('connect', () => socket.write('CONNECT ' + authority +
    ' HTTP/1.1\\r\\nHost: ' + authority + '\\r\\n\\r\\n'));
  socket.on('data', (chunk) => { response += chunk; const match = /^HTTP\\/1\\.1 (\\d+)/.exec(response);
    if (match) { clearTimeout(timer); socket.destroy(); resolve(Number(match[1])); } });
  socket.once('error', () => { clearTimeout(timer); resolve(0); });
}); }
function direct() { return new Promise((resolve) => {
  const socket = net.connect(443, '93.184.216.34');
  const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 1500);
  socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolve(true); });
  socket.once('error', () => { clearTimeout(timer); resolve(false); });
}); }
(async () => {
  if (await request('example.com:443') !== 200) process.exit(44);
  if (await request('example.org:443') !== 403) process.exit(45);
  if (await direct()) process.exit(46);
  process.exit(0);
})().catch(() => process.exit(47));
`;
}
