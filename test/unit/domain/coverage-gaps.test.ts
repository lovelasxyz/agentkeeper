import { describe, expect, it } from 'vitest';
import { isPlatform, PLATFORMS, POSIX_PLATFORMS } from '../../../src/domain/value-objects/Platform.js';
import { AccessTier } from '../../../src/domain/value-objects/AccessTier.js';
import { Disposition } from '../../../src/domain/value-objects/Disposition.js';
import { Severity } from '../../../src/domain/value-objects/Severity.js';
import { GrantScope } from '../../../src/domain/value-objects/GrantScope.js';
import { WorkspaceId } from '../../../src/domain/value-objects/WorkspaceId.js';
import { RuleId } from '../../../src/domain/value-objects/RuleId.js';
import { PathPattern } from '../../../src/domain/value-objects/PathPattern.js';
import { ShellCommand } from '../../../src/domain/value-objects/ShellCommand.js';
import { AbsolutePath } from '../../../src/domain/value-objects/AbsolutePath.js';
import { DenyRule } from '../../../src/domain/policy/DenyRule.js';
import { RuleRegistry } from '../../../src/domain/rules/RuleRegistry.js';
import { StarterProfile } from '../../../src/domain/policy/StarterProfile.js';
import { ARTIFACT_RULES } from '../../../src/domain/rules/artifact/index.js';
import { ScanEngine } from '../../../src/domain/services/ScanEngine.js';
import { Artifact } from '../../../src/domain/entities/Artifact.js';

const HOME = AbsolutePath.of('/Users/dev');
const WORKSPACE = AbsolutePath.of('/work/app');

describe('Platform', () => {
  it('recognises the platforms the product knows', () => {
    for (const platform of PLATFORMS) expect(isPlatform(platform)).toBe(true);
  });

  it('rejects anything else', () => {
    expect(isPlatform('haiku')).toBe(false);
  });

  it('treats macOS and Linux as the POSIX pair', () => {
    expect([...POSIX_PLATFORMS]).toEqual(['darwin', 'linux']);
  });
});

describe('value object rendering', () => {
  it('describes an access tier readably', () => {
    expect(AccessTier.DANGEROUS.toString()).toBe('tier 2');
    expect(AccessTier.EVERYDAY.toJSON()).toBe(1);
  });

  it('describes a disposition readably', () => {
    expect(Disposition.BLOCK.toString()).toBe('block');
    expect(Disposition.ASK.toJSON()).toBe('ask');
    expect(Disposition.values()).toHaveLength(3);
  });

  it('describes a severity readably', () => {
    expect(Severity.HIGH.toString()).toBe('high');
    expect(Severity.HIGH.toJSON()).toBe('high');
    expect(Severity.values()).toHaveLength(4);
  });

  it('describes a rule id readably', () => {
    expect(RuleId.of('AG-B005').toJSON()).toBe('AG-B005');
    expect(RuleId.of('AG-B005').number).toBe(5);
  });

  it('describes a workspace id readably', () => {
    const id = WorkspaceId.fromPath(WORKSPACE);
    expect(id.toJSON()).toBe(id.toString());
  });

  it('describes a grant scope readably', () => {
    expect(GrantScope.global().isGlobal).toBe(true);
    expect(GrantScope.global().toJSON()).toBe('global');
    expect(GrantScope.forWorkspace(WorkspaceId.fromPath(WORKSPACE)).isGlobal).toBe(false);
  });

  it('describes a path pattern readably', () => {
    expect(PathPattern.of('~/.ssh/**').toString()).toBe('~/.ssh/**');
  });

  it('describes a deny rule readably', () => {
    const rule = new DenyRule('ssh-keys', PathPattern.of('~/.ssh/**'), 'read', 'keys');
    expect(rule.toString()).toBe('deny read ~/.ssh/** (ssh-keys)');
  });

  it('mentions the exception in a scoped deny rule', () => {
    const rule = new DenyRule('env', PathPattern.of('**/.env'), 'read', 'x', WORKSPACE);
    expect(rule.toString()).toContain('except /work/app');
  });
});

describe('AbsolutePath extras', () => {
  it('renders a path outside the home unchanged', () => {
    expect(AbsolutePath.of('/etc/hosts').toDisplay(HOME)).toBe('/etc/hosts');
  });

  it('renders the home itself as a bare tilde', () => {
    expect(HOME.toDisplay(HOME)).toBe('~');
  });

  it('serialises to its string form', () => {
    expect(JSON.parse(JSON.stringify({ p: HOME })).p).toBe('/Users/dev');
  });

  it('reports its parent', () => {
    expect(HOME.parent.value).toBe('/Users');
  });
});

describe('PathPattern edge cases', () => {
  it('matches a bare home pattern', () => {
    expect(PathPattern.of('~').matches(HOME, HOME)).toBe(true);
  });

  it('does not match a path outside the home for a home-anchored pattern', () => {
    expect(PathPattern.of('~/x').matches(AbsolutePath.of('/etc/x'), HOME)).toBe(false);
  });

  it('rejects a pattern containing a NUL byte', () => {
    expect(() => PathPattern.of('~/\0')).toThrow(/NUL/i);
  });

  it('reports the home as the literal prefix of a bare home pattern', () => {
    expect(PathPattern.of('~').literalPrefix(HOME)?.value).toBe('/Users/dev');
  });

  it('handles several wildcards in one segment', () => {
    const pattern = PathPattern.of('/var/a*b*c');
    expect(pattern.matches(AbsolutePath.of('/var/aXbYc'), HOME)).toBe(true);
    expect(pattern.matches(AbsolutePath.of('/var/aXc'), HOME)).toBe(false);
  });
});

describe('ShellCommand edge cases', () => {
  it('has no program for an empty command', () => {
    expect(ShellCommand.parse('   ').programs()).toEqual([]);
  });

  it('reports whether a program is invoked, including by full path', () => {
    expect(ShellCommand.parse('/usr/bin/git status').invokes('git')).toBe(true);
    expect(ShellCommand.parse('npm test').invokes('git')).toBe(false);
  });

  it('finds every invocation of a program', () => {
    expect(ShellCommand.parse('git add . && git commit -m x').invocationsOf('git')).toHaveLength(2);
  });

  it('has no subcommand when every argument is a flag', () => {
    expect(ShellCommand.parse('ls -la').segments[0]?.subcommand).toBeNull();
  });

  it('keeps a single-quoted backslash literal', () => {
    expect(ShellCommand.parse("echo 'a\\b'").segments[0]?.args).toEqual(['a\\b']);
  });

  it('describes a segment readably', () => {
    expect(ShellCommand.parse('git push').segments[0]?.toString()).toBe('git push');
  });
});

describe('RuleRegistry', () => {
  it('refuses duplicate ids', () => {
    expect(() => RuleRegistry.of([ARTIFACT_RULES[0] as never, ARTIFACT_RULES[0] as never])).toThrow(
      /duplicate/i,
    );
  });

  it('finds a rule by id', () => {
    const registry = RuleRegistry.of(ARTIFACT_RULES);
    expect(registry.byId('AG-H001')?.id.toString()).toBe('AG-H001');
    expect(registry.byId('AG-Z999')).toBeNull();
  });

  it('honours a disabled rule', () => {
    const registry = RuleRegistry.of(ARTIFACT_RULES);
    const enabled = registry.enabled({ isEnabled: (id) => id !== 'AG-H006' });
    expect(enabled.some((rule) => rule.id.toString() === 'AG-H006')).toBe(false);
  });

  it('keeps a blocking rule even when configuration tries to disable it', () => {
    // Spec §10.3: configuration may reduce noise, never remove a refusal.
    const registry = RuleRegistry.of(ARTIFACT_RULES);
    const enabled = registry.enabled({ isEnabled: () => false });
    expect(enabled.some((rule) => rule.id.toString() === 'AG-E004')).toBe(true);
  });
});

describe('ScanEngine', () => {
  it('does not mutate the subjects it was given', () => {
    const artifacts = [
      new Artifact({
        path: WORKSPACE.join('.claude/settings.json'),
        workspace: WORKSPACE,
        content: '{"hooks":{"SessionStart":[]}}',
      }),
    ];
    const snapshot = artifacts.map((artifact) => artifact.content);
    new ScanEngine(RuleRegistry.of(ARTIFACT_RULES)).scan(artifacts);
    expect(artifacts.map((artifact) => artifact.content)).toEqual(snapshot);
  });

  it('returns an empty report for no subjects', () => {
    expect(new ScanEngine(RuleRegistry.of(ARTIFACT_RULES)).scan([]).isClean).toBe(true);
  });
});

describe('StarterProfile', () => {
  it('rejects a profile with no id', () => {
    expect(() =>
      StarterProfile.fromSpec({ id: '  ', name: 'x', description: 'y', reads: [], writes: [], network: [] }),
    ).toThrow(/id/i);
  });

  it('rejects an unknown network rule', () => {
    expect(() =>
      StarterProfile.fromSpec({
        id: 'x',
        name: 'x',
        description: 'y',
        reads: [],
        writes: [],
        network: ['icmp:0'],
      }),
    ).toThrow(/network/i);
  });

  it('rejects a network rule without legacy protocol or destination syntax', () => {
    expect(() =>
      StarterProfile.fromSpec({
        id: 'x',
        name: 'x',
        description: 'y',
        reads: [],
        writes: [],
        network: ['not-a-rule'],
      }),
    ).toThrow(/unknown network rule/i);
  });

  it('accepts a wildcard port', () => {
    const profile = StarterProfile.fromSpec({
      id: 'x',
      name: 'x',
      description: 'y',
      reads: [],
      writes: [],
      network: ['tcp:*'],
    });
    expect(profile.network[0]?.toString()).toBe('tcp://*:*');
  });

  it('resolves its reads and writes against a home directory', () => {
    const profile = StarterProfile.fromSpec({
      id: 'x',
      name: 'x',
      description: 'y',
      reads: ['file:~/.gitconfig'],
      writes: ['dir:~/.npm'],
      network: [],
    });
    expect(profile.reads(HOME)[0]?.path.value).toBe('/Users/dev/.gitconfig');
    expect(profile.writes(HOME)[0]?.path.value).toBe('/Users/dev/.npm');
  });
});
