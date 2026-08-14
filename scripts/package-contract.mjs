/**
 * What a publishable agentkeeper tarball must contain.
 *
 * Two gates read this list: `verify-package.mjs` checks the working tree
 * before packing, `verify-tarball.mjs` checks the archive npm actually
 * assembled. One source so the gates cannot disagree.
 *
 * Native helpers are deliberately absent: the Windows AppContainer backend is
 * not shipped (production-readiness P0.1), so a tarball containing one is a
 * tarball claiming a boundary that was never proven. The verifier refuses it.
 */
export const REQUIRED_PACKAGE_PATHS = Object.freeze([
  'dist/cli.js',
  'dist/index.js',
  'dist/index.d.ts',
  'profiles/minimal.json',
  'README.md',
  'LICENSE',
  'SECURITY.md',
]);

/**
 * What a publishable tarball must *not* contain. A native helper would mean
 * the Windows backend snuck back into the release without its deny canary
 * ever having passed.
 */
export const FORBIDDEN_PACKAGE_PATH_PREFIXES = Object.freeze(['dist/native']);
