import { execFile } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const repository = fileURLToPath(new URL('../', import.meta.url));

/** Developer diagnostic only; this executable never enters dist or npm. */
export async function buildWindowsPsecProbe() {
  if (process.platform !== 'win32') throw new Error('PSEC diagnostics require Windows');
  const output = join(repository, 'build', 'windows-psec-compat.exe');
  await mkdir(dirname(output), { recursive: true });
  try {
    const result = await execute('cl.exe', [
      '/nologo', '/std:c++20', '/EHsc', '/W4', '/O2', '/MT',
      join(repository, 'test', 'native', 'windows-psec-compat.cpp'),
      `/Fo${join(repository, 'build', 'windows-psec-compat.obj')}`,
      `/Fe${output}`,
    ], { cwd: repository, timeout: 60_000, maxBuffer: 1024 * 1024 });
    console.log(result.stdout);
    if (result.stderr) console.log(result.stderr);
  } catch (error) {
    if (error.stdout) console.error(error.stdout);
    if (error.stderr) console.error(error.stderr);
    throw new Error('The Win32 diagnostic must compile in an MSVC developer environment', { cause: error });
  }
  return output;
}
