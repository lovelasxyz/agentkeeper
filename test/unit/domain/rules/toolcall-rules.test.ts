import { describe, expect, it } from 'vitest';
import { actionRules, blockingRules } from '../../../../src/domain/rules/toolcall/index.js';
import { RuleRegistry } from '../../../../src/domain/rules/RuleRegistry.js';
import { ScanEngine } from '../../../../src/domain/services/ScanEngine.js';
import { AccessTierResolver } from '../../../../src/domain/policy/AccessTierResolver.js';
import { SensitivePathRegistry } from '../../../../src/domain/paths/SensitivePathRegistry.js';
import { ToolCall } from '../../../../src/domain/entities/ToolCall.js';
import { ShellCommand } from '../../../../src/domain/value-objects/ShellCommand.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';

const HOME = AbsolutePath.of('/Users/dev');
const WORKSPACE = AbsolutePath.of('/Users/dev/projects/app');
const CTX: PathContext = { home: HOME, workspace: WORKSPACE, platform: 'darwin' };

const tiers = new AccessTierResolver(SensitivePathRegistry.default());
const blocking = new ScanEngine(RuleRegistry.of(blockingRules(tiers)));
const actions = new ScanEngine(RuleRegistry.of(actionRules()));

const call = (tool: string, input: Record<string, unknown>): ToolCall =>
  new ToolCall({ tool, input, context: CTX });

const bash = (command: string): ToolCall => call('Bash', { command });

const blockIds = (toolCall: ToolCall): string[] =>
  blocking.scan([toolCall]).findings.map((finding) => finding.ruleId.toString());

const actionIds = (toolCall: ToolCall): string[] =>
  actions.scan([toolCall]).findings.map((finding) => finding.ruleId.toString());

describe('ShellCommand', () => {
  it('splits a pipeline into segments', () => {
    expect(ShellCommand.parse('cat a.txt | grep x').programs()).toEqual(['cat', 'grep']);
  });

  it('splits a list on && and ;', () => {
    expect(ShellCommand.parse('npm ci && npm test; echo done').programs()).toEqual([
      'npm',
      'npm',
      'echo',
    ]);
  });

  it('respects quotes when tokenising', () => {
    const segment = ShellCommand.parse('git commit -m "a; b && c"').segments[0];
    expect(segment?.args).toEqual(['commit', '-m', 'a; b && c']);
  });

  it('sees through env and sudo', () => {
    expect(ShellCommand.parse('sudo env FOO=1 rm -rf /tmp/x').programs()).toEqual(['rm']);
  });

  it('collects environment assignments', () => {
    expect(ShellCommand.parse('AGENTKEEPER_BYPASS=1 claude').assignments()).toEqual({
      AGENTKEEPER_BYPASS: '1',
    });
  });

  it('reports the first non-flag argument as the subcommand', () => {
    expect(ShellCommand.parse('git --no-pager push --force main').segments[0]?.subcommand).toBe(
      'push',
    );
  });
});

describe('ToolCall', () => {
  it('classifies read tools', () => {
    expect(call('Read', { file_path: '/x' }).access).toBe('read');
  });

  it('treats an unknown tool as a write, which is the safe assumption', () => {
    expect(call('SomeNewTool', {}).access).toBe('write');
  });

  it('resolves a relative path against the workspace', () => {
    expect(call('Read', { file_path: 'src/a.ts' }).paths().map(String)).toEqual([
      '/Users/dev/projects/app/src/a.ts',
    ]);
  });

  it('expands a tilde path', () => {
    expect(call('Read', { file_path: '~/.ssh/id_rsa' }).paths().map(String)).toEqual([
      '/Users/dev/.ssh/id_rsa',
    ]);
  });

  it('finds paths inside a shell command', () => {
    expect(bash('cat ~/.aws/credentials').paths().map(String)).toContain(
      '/Users/dev/.aws/credentials',
    );
  });

  it('ignores tokens that are not paths', () => {
    expect(bash('npm test').paths()).toEqual([]);
  });
});

describe('family B — refusals', () => {
  it('AG-B001 blocks reading an ssh key', () => {
    expect(blockIds(call('Read', { file_path: '~/.ssh/id_rsa' }))).toContain('AG-B001');
  });

  it('AG-B001 blocks reading shell history through a shell command', () => {
    expect(blockIds(bash('grep -i token ~/.zsh_history'))).toContain('AG-B001');
  });

  it('AG-B001 blocks writing ~/.zshenv', () => {
    expect(blockIds(call('Write', { file_path: '~/.zshenv' }))).toContain('AG-B001');
  });

  it('AG-B001 allows reading ~/.gitconfig, which is tier 1 for reads', () => {
    expect(blockIds(call('Read', { file_path: '~/.gitconfig' }))).not.toContain('AG-B001');
  });

  it('AG-B001 still blocks writing ~/.gitconfig', () => {
    expect(blockIds(call('Write', { file_path: '~/.gitconfig' }))).toContain('AG-B001');
  });

  it('AG-B001 leaves ordinary workspace files alone', () => {
    expect(blockIds(call('Read', { file_path: 'src/index.ts' }))).toEqual([]);
  });

  it('AG-B002 blocks a neighbouring .env', () => {
    expect(blockIds(call('Read', { file_path: '~/projects/other/.env' }))).toContain('AG-B002');
  });

  it("AG-B002 allows the workspace's own .env", () => {
    expect(blockIds(call('Read', { file_path: '.env' }))).not.toContain('AG-B002');
  });

  it('AG-B003 blocks writing global agent settings', () => {
    expect(blockIds(call('Write', { file_path: '~/.claude/settings.json' }))).toContain('AG-B003');
  });

  it('AG-B003 blocks writing a project .mcp.json through a shell redirect', () => {
    expect(blockIds(call('Write', { file_path: '.cursor/mcp.json' }))).toContain('AG-B003');
  });

  it('AG-B004 blocks repointing git hooks', () => {
    expect(blockIds(bash('git config --global core.hooksPath ~/.evil-hooks'))).toContain(
      'AG-B004',
    );
  });

  it('AG-B004 leaves ordinary git config alone', () => {
    expect(blockIds(bash('git config user.name Dev'))).not.toContain('AG-B004');
  });

  it('AG-B005 blocks editing the allowlist', () => {
    expect(blockIds(call('Write', { file_path: '~/.agentkeeper/allowlist.json' }))).toContain(
      'AG-B005',
    );
  });

  it('AG-B005 blocks revoking grants through the CLI', () => {
    expect(blockIds(bash('agentkeeper grants --revoke abc123'))).toContain('AG-B005');
  });

  it('AG-B006 blocks relaunching with the bypass variable', () => {
    expect(blockIds(bash('AGENTKEEPER_BYPASS=1 claude'))).toContain('AG-B006');
  });

  it('every family B rule refuses rather than asks', () => {
    for (const rule of blockingRules(tiers)) {
      expect(rule.defaultDisposition.stops, `${rule.id} must block`).toBe(true);
    }
  });

  it('no family B rule offers to grant access in its wording', () => {
    // Spec §4.5: tier 2 has no "allow" button, and the copy must not imply one.
    for (const rule of blockingRules(tiers)) {
      expect(rule.remediation.toLowerCase()).not.toMatch(/\ballow (it|this|the)\b|grant it/);
    }
  });
});

describe('family A — irreversible actions', () => {
  it('AG-A001 asks about a force push to main', () => {
    expect(actionIds(bash('git push --force origin main'))).toContain('AG-A001');
  });

  it('AG-A001 ignores a force push to a feature branch', () => {
    expect(actionIds(bash('git push --force origin my-feature'))).not.toContain('AG-A001');
  });

  it('AG-A002 asks about npm publish', () => {
    expect(actionIds(bash('npm publish --access public'))).toContain('AG-A002');
  });

  it('AG-A002 ignores npm install', () => {
    expect(actionIds(bash('npm install'))).not.toContain('AG-A002');
  });

  it('AG-A003 asks about rm -rf outside the workspace', () => {
    expect(actionIds(bash('rm -rf ~/Documents/old'))).toContain('AG-A003');
  });

  it('AG-A003 ignores rm -rf inside the workspace', () => {
    expect(actionIds(bash('rm -rf node_modules'))).not.toContain('AG-A003');
  });

  it('AG-A004 asks about terraform apply', () => {
    expect(actionIds(bash('terraform apply -auto-approve'))).toContain('AG-A004');
  });

  it('AG-A004 ignores a read-only cloud query', () => {
    expect(actionIds(bash('aws s3 ls'))).not.toContain('AG-A004');
  });

  it('AG-A005 asks about mounting the docker socket', () => {
    expect(actionIds(bash('docker run -v /var/run/docker.sock:/var/run/docker.sock alpine'))).toContain(
      'AG-A005',
    );
  });

  it('AG-A006 asks about editing a workflow', () => {
    expect(actionIds(call('Write', { file_path: '.github/workflows/ci.yml' }))).toContain(
      'AG-A006',
    );
  });

  it('AG-A007 asks about an outbound MCP message', () => {
    expect(actionIds(call('mcp__slack__send_message', { channel: '#general' }))).toContain(
      'AG-A007',
    );
  });

  it('AG-A007 ignores a read-only MCP call', () => {
    expect(actionIds(call('mcp__slack__list_channels', {}))).not.toContain('AG-A007');
  });

  it('stays quiet on an ordinary build command', () => {
    expect(actionIds(bash('npm run build && npm test'))).toEqual([]);
  });
});
