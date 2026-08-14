import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { arch } from 'node:process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export async function buildWindowsSandbox(targetArchitecture = arch) {
  if (process.platform !== 'win32') return null;
  if (targetArchitecture !== 'x64' && targetArchitecture !== 'arm64') {
    throw new Error(`No native Windows sandbox target is defined for ${targetArchitecture}`);
  }

  const source = join(repository, 'native', 'windows', 'agentkeeper-sandbox.cpp');
  const outputDirectory = join(repository, 'dist', 'native', `win32-${targetArchitecture}`);
  // The published directory holds the signed helper and nothing else, so the
  // compiler intermediate goes to an unpublished build tree instead.
  const objectDirectory = join(repository, 'build', 'native', `win32-${targetArchitecture}`);
  const output = join(outputDirectory, 'agentkeeper-sandbox.exe');
  const object = join(objectDirectory, 'agentkeeper-sandbox.obj');
  await Promise.all([
    mkdir(outputDirectory, { recursive: true }),
    mkdir(objectDirectory, { recursive: true }),
  ]);

  const args = [
    '/nologo',
    '/std:c++20',
    '/EHsc',
    '/permissive-',
    '/W4',
    '/O2',
    '/MT',
    '/sdl',
    '/guard:cf',
    source,
    `/Fo${object}`,
    `/Fe${output}`,
    '/link',
    '/SUBSYSTEM:CONSOLE',
    '/DYNAMICBASE',
    '/NXCOMPAT',
    '/GUARD:CF',
  ];
  if (targetArchitecture === 'x64') args.push('/CETCOMPAT');

  await run('cl.exe', args);
  return output;
}

function run(executable, args) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(executable, args, { cwd: repository, stdio: 'inherit', shell: false });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0 && signal === null) {
        resolveRun();
        return;
      }
      reject(
        new Error(
          `${executable} failed with ${signal === null ? `exit code ${String(code)}` : signal}`,
        ),
      );
    });
  });
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const output = await buildWindowsSandbox(process.argv[2] ?? arch);
  if (output !== null) console.log('windows sandbox: native helper ready at', output);
}
