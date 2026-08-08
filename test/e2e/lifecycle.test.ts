import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildFixture, FIXTURES, type Fixture } from '../fixtures/build.js';

/**
 * Spec §16: `init` → `uninstall` must return the system to exactly its previous
 * state, and the wrapper must be transparent. Both are checked here against the
 * built package, in a throwaway home directory.
 */

const BIN = join(process.cwd(), 'dist/presentation/cli/main.js');

let root: string;
let home: string;
let workspace: string;

interface RunResult {
  readonly stdout: string;
  readonly status: number;
}

function cli(args: readonly string[], options: { cwd?: string; input?: string } = {}): RunResult {
  try {
    const stdout = execFileSync(process.execPath, [BIN, ...args], {
      cwd: options.cwd ?? workspace,
      encoding: 'utf8',
      env: { ...process.env, HOME: home, TMPDIR: join(root, 'tmp'), CI: '1' },
      ...(options.input === undefined ? {} : { input: options.input }),
    });
    return { stdout, status: 0 };
  } catch (error) {
    const failure = error as { stdout?: string; stderr?: string; status?: number };
    return {
      stdout: `${failure.stdout ?? ''}${failure.stderr ?? ''}`,
      status: failure.status ?? 1,
    };
  }
}

beforeAll(() => {
  expect(existsSync(BIN), 'run `npm run build` before the e2e suite').toBe(true);

  root = realpathSync(mkdtempSync(join(tmpdir(), 'agent-guard-e2e-')));
  home = join(root, 'home');
  workspace = join(home, 'projects/app');
  mkdirSync(workspace, { recursive: true });
  mkdirSync(join(root, 'tmp'), { recursive: true });
  writeFileSync(join(workspace, 'README.md'), '# app\n');
});

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

describe('the package presents a usable command line', () => {
  it('prints help without a command and fails, so a bare invocation is not a silent no-op', () => {
    const result = cli([]);
    expect(result.stdout).toContain('agent-guard <command>');
    expect(result.status).toBe(1);
  });

  it('prints a version', () => {
    expect(cli(['--version']).stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('rejects an unknown command', () => {
    expect(cli(['nonsense']).status).toBe(1);
  });
});

describe('scan on a hostile repository', () => {
  it('reports the ChainDrop session hook and exits non-zero only for blocking findings', () => {
    const fixture = FIXTURES.find((entry) => entry.name === 'chaindrop-session-hook') as Fixture;
    const directory = buildFixture(fixture, join(root, 'hostile'));

    const result = cli(['scan', directory]);
    expect(result.stdout).toContain('AG-H002');
    expect(result.stdout).toMatch(/session start/i);
    expect(result.status).toBe(0); // `ask`, not `block`
  });

  it('exits 2 when a blocking rule fires', () => {
    const fixture = FIXTURES.find((entry) => entry.name === 'baseurl-override') as Fixture;
    const directory = buildFixture(fixture, join(root, 'blocking'));
    expect(cli(['scan', directory]).status).toBe(2);
  });

  it('emits machine-readable output for CI', () => {
    const fixture = FIXTURES.find((entry) => entry.name === 'gemini-env-cve-2026-12537') as Fixture;
    const directory = buildFixture(fixture, join(root, 'json'));

    const parsed = JSON.parse(cli(['scan', directory, '--json']).stdout) as {
      findings: { ruleId: string }[];
    };
    expect(parsed.findings.map((finding) => finding.ruleId)).toContain('AG-E001');
  });

  it('says nothing useful is wrong with a clean repository', () => {
    const fixture = FIXTURES.find((entry) => entry.name === 'clean') as Fixture;
    const directory = buildFixture(fixture, join(root, 'clean'));
    expect(cli(['scan', directory]).stdout).toMatch(/Nothing to report/);
  });
});

describe('the PreToolUse hook', () => {
  const hook = (payload: unknown): RunResult =>
    cli(['hook', 'pretooluse'], { input: JSON.stringify(payload) });

  it('stays silent for an ordinary tool call', () => {
    const result = hook({
      tool_name: 'Read',
      tool_input: { file_path: join(workspace, 'README.md') },
      cwd: workspace,
    });
    expect(result.stdout.trim()).toBe('');
    expect(result.status).toBe(0);
  });

  it('refuses a read of an ssh key', () => {
    const result = hook({
      tool_name: 'Read',
      tool_input: { file_path: join(home, '.ssh/id_rsa') },
      cwd: workspace,
    });
    const decision = JSON.parse(result.stdout) as {
      hookSpecificOutput: { permissionDecision: string; permissionDecisionReason: string };
    };
    expect(decision.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(decision.hookSpecificOutput.permissionDecisionReason).toMatch(/\.ssh/);
  });

  it('never offers to grant tier 2 access in its refusal', () => {
    const result = hook({
      tool_name: 'Read',
      tool_input: { file_path: join(home, '.aws/credentials') },
      cwd: workspace,
    });
    // Spec §4.5: the wording must contain no affordance for approving this.
    expect(result.stdout).not.toMatch(/allow|approve|grant .* access|press/i);
  });

  it('fails open on a payload it does not understand', () => {
    const result = cli(['hook', 'pretooluse'], { input: 'not json at all' });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('');
  });
});

describe('init and uninstall (spec §16)', () => {
  const zshrc = (): string => join(home, '.zshrc');

  it('leaves the system untouched when the user declines', () => {
    writeFileSync(zshrc(), '# my shell\nexport EDITOR=vim\n');
    const before = readFileSync(zshrc(), 'utf8');

    const result = cli(['init', '--profile', 'minimal']); // no --yes, CI has no TTY
    expect(result.stdout).toMatch(/Nothing was changed|Apply/);
    expect(readFileSync(zshrc(), 'utf8')).toBe(before);
  });

  it('installs every integration and records a baseline', () => {
    const result = cli(['init', '--yes', '--profile', 'minimal']);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/trusted baseline/);

    expect(readFileSync(zshrc(), 'utf8')).toContain('>>> agent-guard >>>');
    expect(existsSync(join(home, '.agent-guard/shell-init.sh'))).toBe(true);
    expect(existsSync(join(home, '.agent-guard/git-hooks/post-checkout'))).toBe(true);
    expect(existsSync(join(home, '.agent-guard/baseline.json'))).toBe(true);
    expect(readFileSync(join(home, '.claude/settings.json'), 'utf8')).toContain(
      'hook pretooluse',
    );
  });

  it('reports itself as active', () => {
    expect(cli(['status']).stdout).toMatch(/starter profile: minimal/);
  });

  it('wraps every agent it claims to wrap', () => {
    const script = readFileSync(join(home, '.agent-guard/shell-init.sh'), 'utf8');
    for (const agent of ['claude', 'gemini', 'codex']) {
      expect(script).toContain(`${agent}()`);
      expect(script).toContain(`agent-guard run -- ${agent}`);
    }
    // The bypass is for the user's own shell, and says so.
    expect(script).toContain('AGENT_GUARD_BYPASS');
  });

  it('restores the shell file byte for byte on uninstall', () => {
    const original = '# my shell\nexport EDITOR=vim\n';
    expect(cli(['uninstall', '--yes']).status).toBe(0);
    expect(readFileSync(zshrc(), 'utf8')).toBe(original);
  });

  it('removes the integrations it installed', () => {
    expect(existsSync(join(home, '.agent-guard/shell-init.sh'))).toBe(false);
    expect(existsSync(join(home, '.agent-guard/git-hooks/post-checkout'))).toBe(false);
    expect(readFileSync(join(home, '.claude/settings.json'), 'utf8')).not.toContain(
      'hook pretooluse',
    );
  });

  it('keeps grants and the audit log unless asked to purge', () => {
    expect(existsSync(join(home, '.agent-guard/audit.log'))).toBe(true);
  });
});

describe('grants', () => {
  it('adds a tier 1 grant and says when it takes effect', () => {
    const result = cli(['grants', '--add', `dir:${join(home, 'shared')}`, '--reason', 'shared lib']);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/next run/i);
  });

  it('lists it', () => {
    expect(cli(['grants']).stdout).toContain('shared');
  });

  it('refuses a tier 2 grant from the command line', () => {
    const result = cli(['grants', '--add', `dir:${join(home, '.ssh')}`, '--reason', 'nope']);
    expect(result.status).toBe(1);
    expect(result.stdout).toMatch(/allowlist\.json/);
  });

  it('revokes by id', () => {
    const listing = cli(['grants']).stdout;
    const id = /^([0-9a-f]{12})\s/m.exec(listing)?.[1];
    expect(id).toBeDefined();
    expect(cli(['grants', '--revoke', id as string]).status).toBe(0);
  });
});

describe('the wrapper is transparent (spec §4.6)', () => {
  it('passes through the exit code', () => {
    expect(cli(['run', '--', process.execPath, '-e', 'process.exit(7)']).status).toBe(7);
  });

  it('passes through stdout', () => {
    expect(cli(['run', '--', process.execPath, '-e', 'console.log("hello")']).stdout).toContain(
      'hello',
    );
  });

  it('refuses to run the home directory as a workspace', () => {
    const result = cli(['run', '--', process.execPath, '-e', '0'], { cwd: home });
    expect(result.status).toBe(78);
    expect(result.stdout).toMatch(/Refusing to isolate/);
  });
});
