import type { InstallationProcessResult } from '../../application/ports/SystemIntegration.js';

export class SystemIntegrationCommandError extends Error {
  constructor(
    readonly executable: string,
    readonly args: readonly string[],
    readonly result: InstallationProcessResult,
  ) {
    super(
      `${executable} ${args.join(' ')} failed with exit ${result.exitCode}: ${result.stderr.trim()}`,
    );
    this.name = 'SystemIntegrationCommandError';
  }
}

export function requireSuccess(
  executable: string,
  args: readonly string[],
  result: InstallationProcessResult,
): void {
  if (result.exitCode !== 0) throw new SystemIntegrationCommandError(executable, args, result);
}
