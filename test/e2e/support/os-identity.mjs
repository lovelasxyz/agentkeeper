import * as real from 'node:os';

export * from 'node:os';

/**
 * Reports a throwaway identity home to the CLI under test.
 *
 * The control plane deliberately reads the home directory from the password
 * database rather than from `$HOME`, so an agent cannot point configuration,
 * grants or decisions at a directory it controls. That is exactly why the e2e
 * suite cannot fake a home with an environment variable, and why this shim
 * exists only in the test process.
 */
export function userInfo(options) {
  const identity = process.env['AGENTKEEPER_E2E_IDENTITY_HOME'];
  const actual = real.userInfo(options);
  return identity === undefined ? actual : { ...actual, homedir: identity };
}
