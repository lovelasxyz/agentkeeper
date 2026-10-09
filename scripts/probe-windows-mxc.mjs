// Developer-only comparison with Microsoft's published native executor.
// Nothing is installed into node_modules or assembled into the npm package.
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

if (process.platform !== 'win32') throw new Error('MXC host qualification requires Windows');
if (!['x64', 'arm64'].includes(process.arch)) throw new Error('Unsupported Windows architecture');
const npm = process.env.npm_execpath;
if (npm === undefined) throw new Error('Run through npm run probe:windows-mxc');
const execute = promisify(execFile);
const integrity = 'sha512-7aVR+GHVKveIknZmUtkAEFwUBp61qgEmhJRe1ZyKHJ274yWlKWB/ZfDP/u/whfmDyck0wRNKZN49atlF+SZt2Q==';
const root = await mkdtemp(join(tmpdir(), 'agentkeeper-mxc-probe-'));
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
  const { stdout, stderr } = await execute(join(root, member), ['--probe'],
    { timeout: 30_000, maxBuffer: 256 * 1024 });
  console.log(stdout);
  if (stderr.trim() !== '') console.log(stderr);
  if (process.env.GITHUB_ACTIONS === 'true') {
    const escaped = (stdout + stderr).replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
    console.log(`::notice title=Microsoft MXC host support (${process.arch})::${escaped}`);
  }
} finally {
  await rm(root, { recursive: true, force: true });
}
