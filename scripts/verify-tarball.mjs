/**
 * Verifies the archive npm assembled, not the tree it was assembled from.
 *
 * Reads `npm pack --json` on stdin. The working-tree gate can pass while the
 * tarball is still wrong — a stale `files` field, an ignore rule, or a rebuild
 * between verification and packing all produce that gap, and every one of them
 * ships a package whose Windows users get no sandbox.
 *
 * Usage: npm pack --dry-run --ignore-scripts --json | node scripts/verify-tarball.mjs
 */
import { REQUIRED_PACKAGE_PATHS } from './package-contract.mjs';

const raw = await readStdin();
let listing;
try {
  listing = JSON.parse(raw);
} catch (cause) {
  throw new Error(`npm pack did not produce JSON on stdin: ${cause.message}`);
}

const packages = Array.isArray(listing) ? listing : [listing];
if (packages.length !== 1) {
  throw new Error(`Expected exactly one packed tarball, got ${packages.length}`);
}

const [tarball] = packages;
const packed = new Set(
  (tarball.files ?? []).map((entry) => String(entry.path).replace(/\\/g, '/')),
);

const missing = REQUIRED_PACKAGE_PATHS.filter((path) => !packed.has(path));
if (missing.length > 0) {
  throw new Error(`Tarball is missing required artifacts:\n  ${missing.join('\n  ')}`);
}

process.stdout.write(
  `tarball verification: ${packed.size} entries, all ${REQUIRED_PACKAGE_PATHS.length} required artifacts present\n`,
);

function readStdin() {
  return new Promise((resolve, reject) => {
    let text = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      text += chunk;
    });
    process.stdin.once('end', () => {
      resolve(text);
    });
    process.stdin.once('error', reject);
  });
}
