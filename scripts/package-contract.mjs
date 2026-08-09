/**
 * What a publishable agentkeeper tarball must contain.
 *
 * Two gates read this list: `verify-package.mjs` checks the working tree
 * before packing, `verify-tarball.mjs` checks the archive npm actually
 * assembled. One source so the gates cannot disagree.
 *
 * The Windows helpers are here because they are cross-compiled on other
 * runners and downloaded into `dist/`. A release built without them would
 * install cleanly and silently leave Windows users with no boundary.
 */
export const REQUIRED_PACKAGE_PATHS = Object.freeze([
  'dist/cli.js',
  'dist/index.js',
  'dist/index.d.ts',
  'dist/native/win32-x64/agentkeeper-sandbox.exe',
  'dist/native/win32-arm64/agentkeeper-sandbox.exe',
  'profiles/minimal.json',
  'README.md',
  'LICENSE',
  'SECURITY.md',
]);

/** Only the compiled helper ships; build by-products must never be published. */
export const NATIVE_ARCHITECTURES = Object.freeze(['win32-x64', 'win32-arm64']);
export const NATIVE_HELPER = 'agentkeeper-sandbox.exe';
