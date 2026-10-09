import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const scratch = mkdtempSync(join(tmpdir(), 'agentkeeper-native-test-'));
try {
  const source = join(repository, 'test/native/windows-path-safety.cpp');
  const include = join(repository, 'native/windows');
  const output = join(scratch, process.platform === 'win32' ? 'path-safety.exe' : 'path-safety');
  if (process.platform === 'win32') {
    execFileSync('cl.exe', ['/nologo', '/std:c++20', '/EHsc', '/W4', '/WX', source, `/I${include}`, `/Fe${output}`, `/Fo${join(scratch, 'path-safety.obj')}`], { cwd: scratch, stdio: 'inherit' });
  } else {
    execFileSync(process.env.CXX || 'c++', ['-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic', '-I', include, source, '-o', output], { cwd: scratch, stdio: 'inherit' });
  }
  execFileSync(output, [], { stdio: 'inherit' });
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
