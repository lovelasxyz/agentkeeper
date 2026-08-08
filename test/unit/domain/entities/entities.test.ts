import { describe, expect, it } from 'vitest';
import { Artifact } from '../../../../src/domain/entities/Artifact.js';
import { Finding } from '../../../../src/domain/entities/Finding.js';
import { ScanReport } from '../../../../src/domain/entities/ScanReport.js';
import { BaselineChange } from '../../../../src/domain/entities/BaselineChange.js';
import { ToolCall } from '../../../../src/domain/entities/ToolCall.js';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { ContentHash } from '../../../../src/domain/value-objects/ContentHash.js';
import { Disposition } from '../../../../src/domain/value-objects/Disposition.js';
import { RuleId } from '../../../../src/domain/value-objects/RuleId.js';
import { Severity } from '../../../../src/domain/value-objects/Severity.js';
import { SourceLocation } from '../../../../src/domain/value-objects/SourceLocation.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';

const WORKSPACE = AbsolutePath.of('/work/app');
const HOME = AbsolutePath.of('/Users/dev');
const CTX: PathContext = { home: HOME, workspace: WORKSPACE, platform: 'darwin' };

const finding = (overrides: Partial<ConstructorParameters<typeof Finding>[0]> = {}): Finding =>
  new Finding({
    ruleId: RuleId.of('AG-H001'),
    severity: Severity.HIGH,
    disposition: Disposition.ASK,
    title: 'title',
    detail: 'detail',
    remediation: 'remediation',
    subject: 'subject',
    contentHash: null,
    location: null,
    ...overrides,
  });

describe('Artifact', () => {
  it('reports a workspace-relative path', () => {
    const artifact = new Artifact({
      path: WORKSPACE.join('src/index.ts'),
      workspace: WORKSPACE,
      content: '',
    });
    expect(artifact.relativePath).toBe('src/index.ts');
    expect(artifact.basename).toBe('index.ts');
    expect(artifact.relativeSegments).toEqual(['src', 'index.ts']);
  });

  it('falls back to the absolute path when the file is outside the workspace', () => {
    const artifact = new Artifact({
      path: AbsolutePath.of('/etc/hosts'),
      workspace: WORKSPACE,
      content: '',
    });
    expect(artifact.relativePath).toBe('/etc/hosts');
  });

  it('renders the workspace itself as "."', () => {
    const artifact = new Artifact({ path: WORKSPACE, workspace: WORKSPACE, content: '' });
    expect(artifact.relativePath).toBe('.');
    expect(artifact.toString()).toBe('.');
  });

  it('splits content into lines', () => {
    const artifact = new Artifact({ path: WORKSPACE.join('a'), workspace: WORKSPACE, content: 'a\r\nb\nc' });
    expect(artifact.lines()).toEqual(['a', 'b', 'c']);
  });

  it('parses JSON', () => {
    const artifact = new Artifact({ path: WORKSPACE.join('a.json'), workspace: WORKSPACE, content: '{"a":1}' });
    expect(artifact.json()).toEqual({ a: 1 });
  });

  it('parses JSON with comments, which editors and agents both accept', () => {
    const artifact = new Artifact({
      path: WORKSPACE.join('a.json'),
      workspace: WORKSPACE,
      content: '{\n  // a comment\n  "a": 1 /* inline */\n}',
    });
    expect(artifact.json()).toEqual({ a: 1 });
  });

  it('does not strip a // sequence inside a string', () => {
    const artifact = new Artifact({
      path: WORKSPACE.join('a.json'),
      workspace: WORKSPACE,
      content: '{"url":"https://example.com/x"}',
    });
    expect(artifact.json()).toEqual({ url: 'https://example.com/x' });
  });

  it('handles an escaped quote inside a string', () => {
    const artifact = new Artifact({
      path: WORKSPACE.join('a.json'),
      workspace: WORKSPACE,
      content: '{"a":"say \\"hi\\" // not a comment"}',
    });
    expect(artifact.json()).toEqual({ a: 'say "hi" // not a comment' });
  });

  it('returns null for content that is not JSON at all', () => {
    const artifact = new Artifact({ path: WORKSPACE.join('a'), workspace: WORKSPACE, content: 'nope' });
    expect(artifact.json()).toBeNull();
  });

  it('parses at most once', () => {
    const artifact = new Artifact({ path: WORKSPACE.join('a.json'), workspace: WORKSPACE, content: '{"a":1}' });
    expect(artifact.json()).toBe(artifact.json());
  });

  it('has no previous hash unless one is supplied', () => {
    const artifact = new Artifact({ path: WORKSPACE.join('a'), workspace: WORKSPACE, content: 'x' });
    expect(artifact.previousHash).toBeNull();
  });
});

describe('Finding', () => {
  it('keys a decision by content hash when it has one', () => {
    const hash = ContentHash.fromContent('x');
    expect(finding({ contentHash: hash }).decisionKey).toBe(hash.toString());
  });

  it('falls back to rule and subject when there is no content', () => {
    expect(finding().decisionKey).toBe('AG-H001@subject');
  });

  it('produces a copy with a different disposition', () => {
    const blocked = finding().withDisposition(Disposition.BLOCK);
    expect(blocked.disposition).toBe(Disposition.BLOCK);
    expect(blocked.ruleId.toString()).toBe('AG-H001');
  });

  it('serialises without carrying the protected content', () => {
    const json = finding({ contentHash: ContentHash.fromContent('secret') }).toJSON();
    expect(JSON.stringify(json)).not.toContain('secret');
    expect(json['ruleId']).toBe('AG-H001');
  });

  it('includes the location when there is one', () => {
    const json = finding({ location: SourceLocation.atLine(3, 'evil()') }).toJSON();
    expect(json['location']).toBe('line 3: evil()');
  });
});

describe('SourceLocation', () => {
  it('rejects a line number below one', () => {
    expect(() => SourceLocation.atLine(0)).toThrow(/line/i);
  });

  it('finds the first line matching a string', () => {
    expect(SourceLocation.firstMatch('a\nb\nc', 'b')?.line).toBe(2);
  });

  it('finds the first line matching a pattern', () => {
    expect(SourceLocation.firstMatch('a\nxyz', /y/)?.line).toBe(2);
  });

  it('returns null when nothing matches', () => {
    expect(SourceLocation.firstMatch('a', 'z')).toBeNull();
  });

  it('truncates a long excerpt', () => {
    const location = SourceLocation.atLine(1, 'x'.repeat(500));
    expect(location.toString().length).toBeLessThan(140);
  });
});

describe('ScanReport', () => {
  it('is empty by default', () => {
    expect(ScanReport.empty().isClean).toBe(true);
    expect(ScanReport.empty().worstSeverity).toBe(Severity.LOW);
  });

  it('puts the worst finding first', () => {
    const report = ScanReport.of([
      finding({ severity: Severity.LOW, ruleId: RuleId.of('AG-H001') }),
      finding({ severity: Severity.CRITICAL, ruleId: RuleId.of('AG-E004') }),
    ]);
    expect(report.findings[0]?.ruleId.toString()).toBe('AG-E004');
    expect(report.worstSeverity).toBe(Severity.CRITICAL);
  });

  it('orders equal severities by disposition, then by rule id', () => {
    const report = ScanReport.of([
      finding({ ruleId: RuleId.of('AG-H003'), disposition: Disposition.OBSERVE }),
      finding({ ruleId: RuleId.of('AG-H002'), disposition: Disposition.BLOCK }),
      finding({ ruleId: RuleId.of('AG-H001'), disposition: Disposition.OBSERVE }),
    ]);
    expect(report.findings.map((entry) => entry.ruleId.toString())).toEqual([
      'AG-H002',
      'AG-H001',
      'AG-H003',
    ]);
  });

  it('separates what blocks from what asks', () => {
    const report = ScanReport.of([
      finding({ disposition: Disposition.BLOCK }),
      finding({ disposition: Disposition.ASK }),
      finding({ disposition: Disposition.OBSERVE }),
    ]);
    expect(report.blocking()).toHaveLength(1);
    expect(report.interrupting()).toHaveLength(1);
    expect(report.overallDisposition()).toBe(Disposition.BLOCK);
  });

  it('concatenates reports', () => {
    const combined = ScanReport.of([finding()]).concat(ScanReport.of([finding()]));
    expect(combined.findings).toHaveLength(2);
  });
});

describe('BaselineChange', () => {
  const change = (content: string | null): BaselineChange =>
    new BaselineChange({
      path: HOME.join('.zshrc'),
      kind: 'modified',
      previousHash: null,
      currentHash: null,
      content,
      context: CTX,
      sandboxActive: false,
    });

  it('displays the path with a tilde', () => {
    expect(change(null).display).toBe('~/.zshrc');
  });

  it('searches its content', () => {
    expect(change('export A=1').contains('export')).toBe(true);
    expect(change('export A=1').contains(/A=\d/)).toBe(true);
  });

  it('reports no match when the content was not captured', () => {
    expect(change(null).contains('anything')).toBe(false);
  });
});

describe('ToolCall', () => {
  it('ignores an input value that is not a usable path', () => {
    const call = new ToolCall({
      tool: 'Read',
      input: { file_path: '\0not-a-path' },
      context: CTX,
    });
    expect(call.paths()).toEqual([]);
  });

  it('recognises an MCP tool', () => {
    expect(new ToolCall({ tool: 'mcp__x__y', input: {}, context: CTX }).isMcp).toBe(true);
  });

  it('has no command for a non-shell tool', () => {
    expect(new ToolCall({ tool: 'Read', input: {}, context: CTX }).command()).toBeNull();
  });

  it('has no command when the shell input carries none', () => {
    expect(new ToolCall({ tool: 'Bash', input: {}, context: CTX }).command()).toBeNull();
  });

  it('describes itself with its command', () => {
    const call = new ToolCall({ tool: 'Bash', input: { command: 'ls' }, context: CTX });
    expect(call.toString()).toBe('Bash: ls');
  });

  it('describes a non-shell tool by name', () => {
    expect(new ToolCall({ tool: 'Read', input: {}, context: CTX }).toString()).toBe('Read');
  });
});
