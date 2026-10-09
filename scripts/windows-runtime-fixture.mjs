// Developer-only DLL copies for the restricted-token experiment. Each runtime
// supplies its own live module inventory; Node's DLLs must not be used for Git.
import { constants } from 'node:fs';
import { copyFile, realpath, writeFile } from 'node:fs/promises';
import { basename, extname, isAbsolute, join, relative, sep } from 'node:path';

export async function createGitFixtureEnvironment(root, environment) {
  // NUL is a device, not a portable Git config file (native ARM64 Git rejects
  // it). Use a private ordinary file and leave the caller's environment alone.
  const config = join(root, 'empty.gitconfig');
  await writeFile(config, '', { flag: 'wx' });
  return { ...environment, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: config };
}

export async function copyWindowsRuntime(modules, systemRoot, destination) {
  const trusted = await realpath(systemRoot);
  const copied = new Set();
  for (const module of modules) {
    if (extname(module).toLowerCase() !== '.dll') continue;
    const source = await realpath(module);
    const within = relative(trusted, source);
    if (isAbsolute(within) || within === '..' || within.startsWith(`..${sep}`)) continue;
    const key = process.platform === 'win32' ? source.toLowerCase() : source;
    if (copied.has(key)) continue;
    // Ordinary copies, never hardlinks or modifications to system-file ACLs.
    // A basename collision is an error, not permission to replace a DLL.
    await copyFile(source, join(destination, basename(source)), constants.COPYFILE_EXCL);
    copied.add(key);
  }
  return copied.size;
}
