import { describe, expect, it } from 'vitest';
import { ProcessGitConfigurationController } from '../../src/infrastructure/install/ProcessGitConfigurationController.js';
import { ScriptedProcessExecutor } from './fakes.js';

const ok = (stdout = '') => ({ exitCode: 0, stdout, stderr: '' });
const missing = () => ({ exitCode: 1, stdout: '', stderr: '' });

describe('ProcessGitConfigurationController', () => {
  it('reads NUL-delimited path bytes and changes only global core.hooksPath', async () => {
    let current: string | null = '/work/.husky';
    const processes = new ScriptedProcessExecutor((_executable, args) => {
      if (args.includes('--get-all')) return current === null ? missing() : ok(`${current}\0`);
      if (args.includes('--replace-all')) {
        current = args.at(-1) as string;
        return ok();
      }
      if (args.includes('--unset-all')) {
        current = null;
        return ok();
      }
      return { exitCode: 2, stdout: '', stderr: 'unexpected invocation' };
    });
    const git = new ProcessGitConfigurationController(processes, '/usr/bin/git');

    expect(await git.readGlobalHooksPath()).toBe('/work/.husky');
    await git.writeGlobalHooksPath('/Users/dev/.agentkeeper/git-hooks', '/work/.husky');
    expect(current).toBe('/Users/dev/.agentkeeper/git-hooks');
    await git.writeGlobalHooksPath(null, '/Users/dev/.agentkeeper/git-hooks');
    expect(current).toBeNull();
    expect(
      processes.calls.every(
        (call) => call.executable === '/usr/bin/git' && call.args[0] === 'config',
      ),
    ).toBe(true);
    expect(processes.calls.some((call) => call.args.includes('credential.helper'))).toBe(false);
  });

  it('refuses to collapse duplicate existing values', async () => {
    const git = new ProcessGitConfigurationController(
      new ScriptedProcessExecutor(() => ok('/one\0/two\0')),
    );

    await expect(git.readGlobalHooksPath()).rejects.toThrow('multiple values');
  });
});
