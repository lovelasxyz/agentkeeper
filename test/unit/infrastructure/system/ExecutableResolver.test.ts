import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { ExecutableResolver } from '../../../../src/infrastructure/system/ExecutableResolver.js';

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function workspace(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'agentkeeper-resolve-'));
  roots.push(root);
  return root;
}

/**
 * Windows decides executability by extension, not by a permission bit, so a
 * bare `agent` is not runnable there and the resolver is right to ignore it.
 * npm installs agent CLIs as `.cmd` shims, which is what this reproduces.
 */
const EXECUTABLE_SUFFIX = process.platform === 'win32' ? '.cmd' : '';

async function placeExecutable(directory: string, name: string): Promise<string> {
  await mkdir(directory, { recursive: true });
  const file = join(directory, `${name}${EXECUTABLE_SUFFIX}`);
  await writeFile(file, '#!/bin/sh\nexit 0\n');
  await chmod(file, 0o755);
  return file;
}

describe('ExecutableResolver', () => {
  it('rejects names that cannot be executed rather than searching for them', async () => {
    const resolver = new ExecutableResolver();

    expect(await resolver.resolve('', '/bin')).toBeNull();
    expect(await resolver.resolve('bad\0name', '/bin')).toBeNull();
    expect(await resolver.resolve('bad\nname', '/bin')).toBeNull();
  });

  it('resolves a direct absolute path to its canonical location', async () => {
    const root = await workspace();
    const file = await placeExecutable(root, 'agent');

    const resolved = await new ExecutableResolver().resolve(file, '');

    expect(resolved).toEqual(AbsolutePath.of(await realpath(file)));
  });

  it('returns null for a direct path that does not exist', async () => {
    const root = await workspace();

    expect(await new ExecutableResolver().resolve(join(root, 'missing'), '')).toBeNull();
  });

  it('finds an executable through the search path', async () => {
    const root = await workspace();
    const bin = join(root, 'bin');
    const file = await placeExecutable(bin, 'agent');

    const resolved = await new ExecutableResolver().resolve('agent', bin);

    expect(resolved).toEqual(AbsolutePath.of(await realpath(file)));
  });

  it('skips candidates under excluded roots and falls through to the next entry', async () => {
    const root = await workspace();
    const shim = join(root, 'shim');
    const real = join(root, 'real');
    await placeExecutable(shim, 'agent');
    const realFile = await placeExecutable(real, 'agent');
    const searchPath = [shim, real].join(delimiter);

    const resolved = await new ExecutableResolver().resolve('agent', searchPath, [
      AbsolutePath.of(shim),
    ]);

    expect(resolved).toEqual(AbsolutePath.of(await realpath(realFile)));
  });

  it('returns null when nothing on the search path matches', async () => {
    const root = await workspace();

    expect(await new ExecutableResolver().resolve('missing', root)).toBeNull();
  });

  it('ignores search path entries that are not usable directories', async () => {
    const root = await workspace();
    const bin = join(root, 'bin');
    const file = await placeExecutable(bin, 'agent');
    const searchPath = ['', join(root, 'missing-dir'), bin].join(delimiter);

    const resolved = await new ExecutableResolver().resolve('agent', searchPath);

    expect(resolved).toEqual(AbsolutePath.of(await realpath(file)));
  });

  it('resolveMany reports only the executables that resolved', async () => {
    const root = await workspace();
    const bin = join(root, 'bin');
    const file = await placeExecutable(bin, 'present');

    const resolved = await new ExecutableResolver().resolveMany(
      ['present', 'absent'],
      bin,
    );

    expect(resolved).toEqual({
      present: AbsolutePath.of(await realpath(file)),
    });
    expect(Object.isFrozen(resolved)).toBe(true);
  });
});
