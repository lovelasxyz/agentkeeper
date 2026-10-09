import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const modulePath = '../../scripts/windows-runtime-fixture.mjs';
const { copyWindowsRuntime } = await import(modulePath) as {
  copyWindowsRuntime(modules: string[], systemRoot: string, destination: string): Promise<number>;
};
const roots: string[] = [];
afterEach(async () => { await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))); });

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'agentkeeper-runtime-'));
  roots.push(root);
  const system = join(root, 'Windows');
  const node = join(root, 'Node');
  const git = join(root, 'Git');
  await Promise.all([system, node, git].map((path) => mkdir(path)));
  return { root, system, node, git };
}

describe('disposable Windows runtime fixtures', () => {
  it('keeps the DLL inventories of independently loaded Node and Git separate', async () => {
    const { system, node, git } = await fixture();
    await Promise.all(['arm64', 'x64'].map((arch) => mkdir(join(system, arch))));
    const arm = join(system, 'arm64/runtime.dll');
    const x64 = join(system, 'x64/runtime.dll');
    await writeFile(arm, 'ARM64 runtime');
    await writeFile(x64, 'x64 runtime');
    expect(await copyWindowsRuntime([arm, arm], system, node)).toBe(1);
    expect(await copyWindowsRuntime([x64], system, git)).toBe(1);
    expect(await readFile(join(node, 'runtime.dll'), 'utf8')).toBe('ARM64 runtime');
    expect(await readFile(join(git, 'runtime.dll'), 'utf8')).toBe('x64 runtime');
    await writeFile(join(node, 'runtime.dll'), 'disposable copy');
    expect(await readFile(arm, 'utf8')).toBe('ARM64 runtime');
  });

  it('excludes executables and lookalike Windows directories', async () => {
    const { root, system, node } = await fixture();
    const lookalike = join(root, 'Windows-other');
    await mkdir(lookalike);
    const dll = join(lookalike, 'outside.dll');
    const exe = join(system, 'tool.exe');
    await writeFile(dll, 'outside');
    await writeFile(exe, 'executable');
    expect(await copyWindowsRuntime([dll, exe], system, node)).toBe(0);
  });

  it('does not copy a DLL through an alias outside the trusted system tree', async () => {
    const { root, system, node } = await fixture();
    const outside = join(root, 'outside');
    await mkdir(outside);
    await writeFile(join(outside, 'escape.dll'), 'outside');
    await symlink(outside, join(system, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
    expect(await copyWindowsRuntime([join(system, 'alias/escape.dll')], system, node)).toBe(0);
  });

  it('refuses to replace an existing runtime DLL', async () => {
    const { system, node } = await fixture();
    await writeFile(join(system, 'runtime.dll'), 'system');
    await writeFile(join(node, 'runtime.dll'), 'toolchain');
    await expect(copyWindowsRuntime([join(system, 'runtime.dll')], system, node)).rejects.toThrow();
    expect(await readFile(join(node, 'runtime.dll'), 'utf8')).toBe('toolchain');
  });
});
