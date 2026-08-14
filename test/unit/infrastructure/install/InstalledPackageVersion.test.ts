import { describe, expect, it } from 'vitest';

import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { installedPackageVersion } from '../../../../src/infrastructure/install/InstalledPackageVersion.js';
import { InMemoryFileSystem } from '../../../integration/fakes.js';

/**
 * The daemon's self-observation of an upgrade: the package on disk is the
 * source of truth about what *should* be running, read rather than assumed.
 */
describe('installedPackageVersion', () => {
  const entrypoint = AbsolutePath.of('/usr/local/lib/node_modules/agentkeeper/dist/cli.js');

  it('reads the version from the package manifest beside the entrypoint', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      AbsolutePath.of('/usr/local/lib/node_modules/agentkeeper/package.json'),
      '{"name":"agentkeeper","version":"1.0.5"}',
    );

    expect(await installedPackageVersion(files, entrypoint)).toBe('1.0.5');
  });

  it('walks up from a deeper entrypoint, bounded, until it finds the manifest', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      AbsolutePath.of('/work/agentkeeper/package.json'),
      '{"name":"agentkeeper","version":"1.0.5"}',
    );

    expect(
      await installedPackageVersion(
        files,
        AbsolutePath.of('/work/agentkeeper/src/presentation/cli/main.ts'),
      ),
    ).toBe('1.0.5');
  });

  it('refuses a manifest that is not this package, and keeps walking', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      AbsolutePath.of('/work/agentkeeper/dist/package.json'),
      '{"name":"something-else","version":"9.9.9"}',
    );
    await files.write(
      AbsolutePath.of('/work/agentkeeper/package.json'),
      '{"name":"agentkeeper","version":"1.0.5"}',
    );

    expect(
      await installedPackageVersion(files, AbsolutePath.of('/work/agentkeeper/dist/cli.js')),
    ).toBe('1.0.5');
  });

  it('reports null when no agentkeeper manifest exists above the entrypoint', async () => {
    const files = new InMemoryFileSystem();
    await files.write(AbsolutePath.of('/elsewhere/package.json'), '{"name":"x","version":"1"}');

    expect(await installedPackageVersion(files, entrypoint)).toBeNull();
  });

  it('reports null for a malformed manifest instead of guessing', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      AbsolutePath.of('/usr/local/lib/node_modules/agentkeeper/package.json'),
      'not json',
    );

    expect(await installedPackageVersion(files, entrypoint)).toBeNull();
  });

  it('reports null when the manifest has no usable version field', async () => {
    const files = new InMemoryFileSystem();
    await files.write(
      AbsolutePath.of('/usr/local/lib/node_modules/agentkeeper/package.json'),
      '{"name":"agentkeeper"}',
    );

    expect(await installedPackageVersion(files, entrypoint)).toBeNull();
  });
});
