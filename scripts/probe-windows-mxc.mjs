// Developer-only comparison with Microsoft's published native executor.
// Nothing is installed into node_modules or assembled into the npm package.
import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32') throw new Error('MXC host qualification requires Windows');
if (!['x64', 'arm64'].includes(process.arch)) throw new Error('Unsupported Windows architecture');
const npm = process.env.npm_execpath;
if (npm === undefined) throw new Error('Run through npm run probe:windows-mxc');
const execute = promisify(execFile);
const integrity = 'sha512-7aVR+GHVKveIknZmUtkAEFwUBp61qgEmhJRe1ZyKHJ274yWlKWB/ZfDP/u/whfmDyck0wRNKZN49atlF+SZt2Q==';
// Policy paths and cwd must agree on long names, including the runner's
// RUNNER~1 temporary-directory alias. Resolve them on the trusted host.
const root = await realpath(await mkdtemp(join(tmpdir(), 'agentkeeper-mxc-probe-')));
const servers = [];
try {
  const packed = await execute(process.execPath, [npm, 'pack', '@microsoft/mxc-sdk@1.0.0',
    '--ignore-scripts', '--json', '--pack-destination', root, '--cache', join(root, 'cache')],
  { timeout: 120_000, maxBuffer: 2 * 1024 * 1024 });
  const archive = join(root, 'microsoft-mxc-sdk-1.0.0.tgz');
  const actual = 'sha512-' + createHash('sha512').update(await readFile(archive)).digest('base64');
  if (actual !== integrity || JSON.parse(packed.stdout)[0]?.integrity !== integrity) {
    throw new Error('Microsoft MXC archive did not match the reviewed integrity');
  }
  const member = `package/bin/${process.arch}/wxc-exec.exe`;
  await execute('tar.exe', ['-xf', archive, '-C', root, member], { timeout: 30_000 });
  const executor = join(root, member);
  const { stdout, stderr } = await execute(executor, ['--probe'],
    { timeout: 30_000, maxBuffer: 256 * 1024 });
  console.log(stdout);
  if (stderr.trim() !== '') console.log(stderr);
  report('Microsoft MXC host support', stdout + stderr);
  const host = JSON.parse(stdout);
  if (host.tier !== 'base-container' || host.probes?.baseContainerSupportsDenyPaths !== true) {
    throw new Error('Qualification requires native Windows 11 PSEC with filesystem denies; fallback tiers do not qualify');
  }
  {
    const workspace = join(root, 'workspace');
    await mkdir(workspace);
    const outside = join(root, 'outside.secret');
    await writeFile(outside, 'must not be readable');
    await writeFile(join(root, 'ungranted.secret'), 'default-deny canary without an explicit deny entry');
    const script = join(workspace, 'qualification.cjs');
    await writeFile(script, await readFile(new URL('../test/native/windows-psec-workload.cjs', import.meta.url)));
    await writeFile(join(workspace, 'module.cjs'), 'module.exports=42;');
    await writeFile(join(workspace, 'module.mjs'), 'export default 43;');
    const git = (await execute('where.exe', ['git'])).stdout.trim().split(/\r?\n/)[0];
    if (!git) throw new Error('Git is required for Windows toolchain qualification');
    const compat = fileURLToPath(new URL('../build/windows-psec-compat.exe', import.meta.url));
    await readFile(compat);
    const pipePath = String.raw`\\.\pipe\agentkeeper-mxc-${randomUUID()}`;
    const pipe = await echoServer(pipePath);
    servers.push(pipe);
    const tcp = await echoServer({ host: '127.0.0.1', port: 0 });
    servers.push(tcp);
    const hostPort = tcp.server.address().port;
    const config = {
      version: '1.0.0', containment: 'processcontainer',
      // Node otherwise resolves the entrypoint through realpathSync('C:\\').
      // Keep the native filesystem policy intact and test its supported
      // entrypoint option instead of granting recursive access to drive roots.
      process: { commandLine: `"${process.execPath}" --preserve-symlinks --preserve-symlinks-main "${script}" "${outside}" ${hostPort} "${pipePath}" false "${git}"`, cwd: workspace, timeout: 30_000 },
      filesystem: { readwritePaths: [workspace], readonlyPaths: [dirname(process.execPath), resolve(dirname(git), '..'), compat], deniedPaths: [outside] },
      network: { egress: { default: 'deny' }, ingress: { default: 'deny', hostLoopback: 'deny' } },
      telemetry: { enabled: false },
      // Console runtimes initialise Win32k. Keep clipboard and input injection
      // denied while permitting the runtime's normal subsystem initialisation.
      ui: { disable: false, clipboard: 'none', injection: false },
    };
    try {
      let failed = false;
      for (const pipeAllowed of [false, true]) {
        if (pipeAllowed) {
          config.filesystem.readwritePaths.push(pipePath);
        }
        config.process.commandLine = `"${process.execPath}" --preserve-symlinks --preserve-symlinks-main "${script}" "${outside}" ${hostPort} "${pipePath}" ${pipeAllowed} "${git}" "${compat}"`;
        const configPath = join(root, `policy-${pipeAllowed}.json`);
        await writeFile(configPath, JSON.stringify(config));
        try {
          const requestProbe = await execute(executor, ['--probe', configPath], { timeout: 30_000 });
          report('Microsoft MXC request support', requestProbe.stdout + requestProbe.stderr);
          if (JSON.parse(requestProbe.stdout).tier !== 'base-container') {
            throw new Error('Refusing to evaluate a fallback tier');
          }
          const execution = execute(executor, [configPath], { timeout: 40_000, maxBuffer: 256 * 1024 });
          execution.child.stdin.end('host-broker-handle-canary');
          const result = await execution;
          report(`Microsoft MXC toolchain and IPC (pipe allowed: ${pipeAllowed})`, result.stdout + result.stderr);
        } catch (error) {
          failed = true;
          report(`Microsoft MXC toolchain and IPC failed (pipe allowed: ${pipeAllowed})`,
            String(error.stdout ?? '') + String(error.stderr ?? '') + '\n' + error.message);
        }
      }
      if (failed) throw new Error('Windows PSEC toolchain/IPC qualification failed');
    } catch (error) {
      report('Microsoft MXC confined descendants failed', String(error.stdout ?? '') + String(error.stderr ?? ''));
      throw error;
    }
  }
} finally {
  await Promise.all(servers.map((server) => server.close()));
  await rm(root, { recursive: true, force: true });
}

async function echoServer(address) {
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => socket.destroy());
    socket.once('close', () => sockets.delete(socket));
    socket.pipe(socket);
  });
  await new Promise((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(address, resolveListen);
  });
  return { server, close: () => new Promise((resolveClose, reject) => {
    for (const socket of sockets) socket.destroy();
    server.close((error) => error ? reject(error) : resolveClose());
  }) };
}

function report(title, details) {
  console.log(details);
  if (process.env.GITHUB_ACTIONS === 'true') {
    const escaped = details.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
    console.log(`::notice title=${title} (${process.arch})::${escaped}`);
  }
}
