/**
 * The one declaration of the build-time version constant.
 *
 * Injected by the bundler from package.json, so `--version` cannot drift from
 * what was published. Kept as a build-time constant rather than a runtime
 * read: the router imports this module on the hook path, whose whole budget
 * is 50 ms, and it tree-shakes to two lines.
 */
declare const __AGENTKEEPER_VERSION__: string;

/** What an unbundled run (tests, tsx) reports: no version was injected. */
export const AGENTKEEPER_DEV_VERSION = '0.0.0-dev';

export const AGENTKEEPER_VERSION: string =
  typeof __AGENTKEEPER_VERSION__ === 'string' ? __AGENTKEEPER_VERSION__ : AGENTKEEPER_DEV_VERSION;
