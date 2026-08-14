import { fileURLToPath } from 'node:url';
import * as real from 'node:child_process';

export * from 'node:child_process';

const FAKE_MANAGER = fileURLToPath(new URL('./fake-service-manager.mjs', import.meta.url));

/**
 * The executables a user-level service manager is driven through. Only the
 * exact names the production adapters use are intercepted; everything else —
 * `git`, above all — reaches the real system unchanged.
 */
const SERVICE_EXECUTABLES = new Set([
  '/bin/launchctl',
  'launchctl',
  'systemctl',
  'schtasks.exe',
  'powershell.exe',
]);

/**
 * A throwaway service manager for the e2e suite.
 *
 * A faked home cannot fake launchd: it reports the real user session whatever
 * `$HOME` says, which is why the lifecycle suite could not run on a machine
 * where agentkeeper is installed. Intercepting the executable boundary —
 * not the state — keeps every launchctl/systemctl argument, exit-code and
 * settle semantic under test exactly as production issues them.
 */
export function spawn(command, args, options) {
  if (typeof command !== 'string' || !SERVICE_EXECUTABLES.has(command)) {
    return real.spawn(command, args, options);
  }
  // The fake manager must not inherit the loader hooks again: it spawns
  // nothing itself, and a clean environment keeps it honest.
  const env = { ...(options?.env ?? process.env), NODE_OPTIONS: '' };
  return real.spawn(
    process.execPath,
    [FAKE_MANAGER, command, ...(args ?? [])],
    { ...options, env },
  );
}
