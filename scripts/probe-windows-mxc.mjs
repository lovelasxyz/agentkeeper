// Developer-only comparison with Microsoft's published native executor.
// Nothing is installed into node_modules or assembled into the npm package.
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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
  const executor = join(root, member);
  const { stdout, stderr } = await execute(executor, ['--probe'],
    { timeout: 30_000, maxBuffer: 256 * 1024 });
  console.log(stdout);
  if (stderr.trim() !== '') console.log(stderr);
  report('Microsoft MXC host support', stdout + stderr);
  const host = JSON.parse(stdout);
  if (host.tier === 'base-container' && host.probes?.baseContainerSupportsDenyPaths === true) {
    const workspace = join(root, 'workspace');
    await mkdir(workspace);
    const outside = join(root, 'outside.secret');
    await writeFile(outside, 'must not be readable');
    const script = join(workspace, 'qualification.cjs');
    await writeFile(script, [
      "const fs=require('node:fs'),cp=require('node:child_process');",
      `const outside=${JSON.stringify(outside)};`,
      "try{fs.readFileSync(outside);process.exit(42)}catch{}",
      "fs.writeFileSync('inside.txt','ok');",
      "for(const stdio of ['inherit','ignore','pipe']){",
      " const code=\"try{require('node:fs').readFileSync(process.argv[1]);process.exit(42)}catch{process.exit(0)}\";",
      " const child=cp.spawnSync(process.execPath,['-e',code,outside],{stdio,timeout:5000,killSignal:'SIGKILL'});",
      " console.log(JSON.stringify({stdio,status:child.status,signal:child.signal,error:child.error?.code}));",
      " if(child.status!==0)process.exit(44);",
      "}",
    ].join('\n'));
    const config = {
      version: '1.0.0', containment: 'processcontainer',
      // Node otherwise resolves the entrypoint through realpathSync('C:\\').
      // Keep the native filesystem policy intact and test its supported
      // entrypoint option instead of granting recursive access to drive roots.
      process: { commandLine: `"${process.execPath}" --preserve-symlinks-main "${script}"`, cwd: workspace, timeout: 20_000 },
      filesystem: { readwritePaths: [workspace], readonlyPaths: [dirname(process.execPath)], deniedPaths: [outside] },
      network: { egress: { default: 'deny' }, ingress: { default: 'deny', hostLoopback: 'deny' } },
      telemetry: { enabled: false },
      // Console runtimes initialise Win32k. Keep clipboard and input injection
      // denied while permitting the runtime's normal subsystem initialisation.
      ui: { disable: false, clipboard: 'none', injection: false },
    };
    const configPath = join(root, 'policy.json');
    await writeFile(configPath, JSON.stringify(config));
    const requestProbe = await execute(executor, ['--probe', configPath], { timeout: 30_000 });
    report('Microsoft MXC request support', requestProbe.stdout + requestProbe.stderr);
    if (JSON.parse(requestProbe.stdout).tier !== 'base-container') {
      throw new Error('Refusing to evaluate a fallback tier');
    }
    try {
      const result = await execute(executor, [configPath], { timeout: 35_000, maxBuffer: 256 * 1024 });
      report('Microsoft MXC confined descendants', result.stdout + result.stderr);
    } catch (error) {
      report('Microsoft MXC confined descendants failed', String(error.stdout ?? '') + String(error.stderr ?? ''));
      throw error;
    }
  }
} finally {
  await rm(root, { recursive: true, force: true });
}

function report(title, details) {
  console.log(details);
  if (process.env.GITHUB_ACTIONS === 'true') {
    const escaped = details.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
    console.log(`::notice title=${title} (${process.arch})::${escaped}`);
  }
}
