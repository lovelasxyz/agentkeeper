import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  FileListingLimitError,
  NodeFileSystem,
} from '../../../../src/infrastructure/fs/NodeFileSystem.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';

const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

describe('NodeFileSystem bounded listing', () => {
  it('fails loudly when the entry cap is reached inside one directory', async () => {
    const root = await mkdtemp(join(tmpdir(), 'agentkeeper-list-'));
    roots.push(root);
    await writeFile(join(root, 'a'), 'a');
    await writeFile(join(root, 'b'), 'b');
    await writeFile(join(root, 'c'), 'c');

    await expect(
      new NodeFileSystem().list(AbsolutePath.of(root), {
        maxEntries: 2,
        failOnLimit: true,
      }),
    ).rejects.toBeInstanceOf(FileListingLimitError);
  });
});
