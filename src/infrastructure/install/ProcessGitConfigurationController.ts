import type {
  GitConfigurationController,
  InstallationProcessExecutor,
} from '../../application/ports/SystemIntegration.js';
import { requireSuccess } from './SystemIntegrationErrors.js';

/** Exact global core.hooksPath reads/writes; never touches another Git key. */
export class ProcessGitConfigurationController implements GitConfigurationController {
  constructor(
    private readonly processes: InstallationProcessExecutor,
    private readonly gitExecutable = 'git',
  ) {}

  async readGlobalHooksPath(): Promise<string | null> {
    const result = await this.processes.execute(this.gitExecutable, [
      'config',
      '--global',
      '-z',
      '--get-all',
      'core.hooksPath',
    ]);
    if (result.exitCode === 1 && result.stdout.length === 0) return null;
    requireSuccess(this.gitExecutable, ['config', '--global', '-z', '--get-all', 'core.hooksPath'], result);
    const values = result.stdout.split('\0').filter((value) => value.length > 0);
    if (values.length > 1) {
      throw new Error(
        'Global core.hooksPath has multiple values; refusing to collapse them during installation',
      );
    }
    return values[0] ?? null;
  }

  async writeGlobalHooksPath(path: string | null, expected?: string | null): Promise<void> {
    const current = await this.readGlobalHooksPath();
    if (expected !== undefined && current !== expected) {
      throw new Error('Global core.hooksPath changed immediately before mutation');
    }
    if (current === path) return;
    const args =
      path === null
        ? ['config', '--global', '--unset-all', 'core.hooksPath']
        : ['config', '--global', '--replace-all', 'core.hooksPath', path];
    const result = await this.processes.execute(this.gitExecutable, args);
    // `--unset-all` returns 5 when the key was absent. The read above normally
    // makes that impossible, but treating it as idempotent closes the race.
    if (path === null && result.exitCode === 5) return;
    requireSuccess(this.gitExecutable, args, result);
  }
}
