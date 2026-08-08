import { chmod, readFile, writeFile } from 'node:fs/promises';

/** The shebang is added at build time so the source stays plain TypeScript. */
const entry = 'dist/presentation/cli/main.js';
const source = await readFile(entry, 'utf8');
if (!source.startsWith('#!')) {
  await writeFile(entry, `#!/usr/bin/env node\n${source}`);
}
await chmod(entry, 0o755);
console.log('postbuild: bin ready');
