import { describe, expect, it } from 'vitest';
import { CommandRouter } from '../../../src/presentation/cli/CommandRouter.js';
import { parseGrantRequest } from '../../../src/presentation/cli/commands/GrantsCommand.js';
import {
  classifyIntegration,
  renderIntegrations,
} from '../../../src/presentation/cli/commands/IntegrationsCommand.js';
import { renderPolicy } from '../../../src/presentation/cli/commands/PolicyCommand.js';
import { SandboxPolicy } from '../../../src/domain/policy/SandboxPolicy.js';
import { AbsolutePath } from '../../../src/domain/value-objects/AbsolutePath.js';
import { NetworkRule } from '../../../src/domain/value-objects/NetworkRule.js';
import { ResourceRef } from '../../../src/domain/value-objects/ResourceRef.js';

const home = AbsolutePath.of('/home/dev');
const workspace = AbsolutePath.of('/home/dev/projects/app');

describe('the CLI verbs the spec names (§32)', () => {
  it('offers every documented verb without executing any of them', async () => {
    const written: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      // `help` renders the descriptor table; no command module is loaded, so
      // this asserts the surface without touching the user's machine.
      expect(await new CommandRouter().run(['help'])).toBe(0);
    } finally {
      process.stdout.write = original;
    }

    const help = written.join('');
    for (const verb of [
      'status',
      'doctor',
      'log',
      'policy',
      'allow',
      'revoke',
      'integrations',
      'repair',
      'activate',
      'uninstall',
      'run',
    ]) {
      expect(help, `missing verb: ${verb}`).toMatch(new RegExp(`^\\s+${verb}\\b`, 'm'));
    }
  });
});

describe('grant argument parsing', () => {
  it('reads the spec form: allow <path> --read --workspace', () => {
    expect(parseGrantRequest('allow', ['~/projects/shared', '--read', '--workspace'])).toEqual({
      kind: 'add',
      target: '~/projects/shared',
      access: 'read',
      scope: 'workspace',
      reason: 'added from the command line',
    });
  });

  it('defaults to a read grant and takes --write explicitly', () => {
    expect(parseGrantRequest('allow', ['/srv/data', '--write'])).toMatchObject({
      kind: 'add',
      access: 'write',
      scope: 'global',
    });
  });

  it('refuses an allow with no path instead of listing grants', () => {
    expect(parseGrantRequest('allow', [])).toMatchObject({ kind: 'error' });
  });

  it('reads revoke from a positional id and from the legacy flag alike', () => {
    expect(parseGrantRequest('revoke', ['g-17'])).toEqual({ kind: 'revoke', id: 'g-17' });
    expect(parseGrantRequest('grants', ['--revoke', 'g-17'])).toEqual({ kind: 'revoke', id: 'g-17' });
  });

  it('keeps bare grants a listing', () => {
    expect(parseGrantRequest('grants', [])).toEqual({ kind: 'list' });
  });
});

describe('integration status is derived from what exists, not from intent', () => {
  it.each([
    [{ executable: null, shimPresent: false, managedHealthy: true }, 'absent'],
    [{ executable: '/usr/bin/claude', shimPresent: false, managedHealthy: true }, 'unprotected'],
    [{ executable: '/usr/bin/claude', shimPresent: true, managedHealthy: false }, 'needs-repair'],
    [{ executable: '/usr/bin/claude', shimPresent: true, managedHealthy: true }, 'intercepted'],
  ] as const)('classifies %o as %s', (input, expected) => {
    expect(classifyIntegration({ agent: 'claude', ...input })).toBe(expected);
  });

  it('never claims every agent is covered while one still needs repair', () => {
    const lines = renderIntegrations([
      { agent: 'claude', executable: '/usr/bin/claude', shimPresent: true, managedHealthy: false },
    ]).join('\n');

    expect(lines).toMatch(/needs repair/);
    expect(lines).not.toMatch(/Every agent/);
  });

  it('names the unprotected agent in its output rather than only counting', () => {
    const lines = renderIntegrations([
      { agent: 'claude', executable: '/usr/bin/claude', shimPresent: true, managedHealthy: true },
      { agent: 'codex', executable: '/usr/bin/codex', shimPresent: false, managedHealthy: true },
    ]);

    expect(lines.join('\n')).toMatch(/codex/);
    expect(lines.join('\n')).toMatch(/unprotected/);
  });
});

describe('policy output', () => {
  it('shows the identity, the boundary and the destinations, and no secrets', () => {
    const policy = new SandboxPolicy({
      workspace,
      reads: [ResourceRef.subtree(workspace)],
      writes: [ResourceRef.subtree(workspace)],
      denies: [],
      overrides: [],
      network: [NetworkRule.destination('api.anthropic.com', 443)],
    });

    const text = renderPolicy(policy, home).join('\n');

    expect(text).toContain(policy.policyHash);
    expect(text).toContain('api.anthropic.com:443');
    expect(text).toContain('~/projects/app');
  });

  it('says egress is closed when no destination is allowed', () => {
    const policy = new SandboxPolicy({
      workspace,
      reads: [ResourceRef.subtree(workspace)],
      writes: [],
      denies: [],
      overrides: [],
      network: [],
    });

    expect(renderPolicy(policy, home).join('\n')).toMatch(/no outbound|denied/i);
  });
});

describe('a resident watcher that could never start', () => {
  it('is named at activation instead of flapping silently', async () => {
    // macOS TCC denies background agents access to Desktop, Documents and
    // Downloads. launchd registers the job, the job cannot read its own
    // entrypoint, and it respawns forever with no explanation anywhere.
    const { backgroundLaunchWarning } = await import(
      '../../../src/presentation/cli/commands/InstallationCommand.js'
    );
    const home = AbsolutePath.of('/Users/dev');

    expect(
      backgroundLaunchWarning(home.join('Desktop/agentkeeper/dist/cli.js'), home, 'darwin'),
    ).toMatch(/Desktop/);
    expect(
      backgroundLaunchWarning(home.join('Documents/x/dist/cli.js'), home, 'darwin'),
    ).not.toBeNull();
    expect(
      backgroundLaunchWarning(
        home.join('.nvm/versions/node/v22/lib/node_modules/agentkeeper/dist/cli.js'),
        home,
        'darwin',
      ),
    ).toBeNull();
    // Only macOS enforces this, so no other platform is warned.
    expect(
      backgroundLaunchWarning(home.join('Desktop/agentkeeper/dist/cli.js'), home, 'linux'),
    ).toBeNull();
  });
});
