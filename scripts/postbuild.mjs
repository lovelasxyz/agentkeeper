import { build } from 'esbuild';
import { chmod } from 'node:fs/promises';
import { buildWindowsSandbox } from './build-windows-sandbox.mjs';

/**
 * Bundles the CLI into a single file.
 *
 * Measured, not cosmetic: resolving and compiling ~90 ESM modules cost 52 ms
 * before any work began, against a 50 ms budget for the whole hook. One file
 * removes the resolution and the per-module compile.
 *
 * The library entry (`dist/index.js`) stays as tsc emitted it, so consumers
 * importing individual classes are unaffected.
 */
const out = 'dist/cli.js';

await build({
  entryPoints: ['src/presentation/cli/main.ts'],
  outfile: out,
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'esm',
  // Dynamic imports stay dynamic: the hook must not pay for the installer.
  // One file, not chunks: chunking re-introduces per-chunk resolution and
  // measured worse than the single bundle.
  splitting: false,
  // Smaller source parses faster, and a CLI is not read by humans.
  minify: true,
  keepNames: true,
  sourcemap: false,
  // esbuild preserves the shebang from the entry file; adding a banner too
  // produces two, and the second one is a syntax error.
  legalComments: 'none',
});

if (process.platform !== 'win32') await chmod(out, 0o755);
await buildWindowsSandbox();
console.log('postbuild: bundled CLI ready at', out);
