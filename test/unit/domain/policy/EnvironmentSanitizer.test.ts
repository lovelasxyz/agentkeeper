import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  EnvironmentPolicy,
  type ProviderApiKey,
} from '../../../../src/domain/policy/EnvironmentPolicy.js';
import { EnvironmentSanitizer } from '../../../../src/domain/policy/EnvironmentSanitizer.js';

const sanitizer = new EnvironmentSanitizer();

const PROVIDER_KEYS: readonly ProviderApiKey[] = [
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'GEMINI_API_KEY',
  'GOOGLE_API_KEY',
  'OPENROUTER_API_KEY',
];

const DANGEROUS_NAMES = [
  // Cloud, package registry and source-control credentials.
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'AZURE_CLIENT_SECRET',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'KUBECONFIG',
  'NPM_TOKEN',
  'NODE_AUTH_TOKEN',
  'NPM_CONFIG_USERCONFIG',
  'PYPI_TOKEN',
  'TWINE_PASSWORD',
  'CARGO_REGISTRY_TOKEN',
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'GITLAB_TOKEN',
  // Ambient authority exposed through local sockets and desktop sessions.
  'SSH_AUTH_SOCK',
  'SSH_AGENT_PID',
  'GPG_AGENT_INFO',
  'GPG_TTY',
  'DOCKER_HOST',
  'DOCKER_CONTEXT',
  'CONTAINER_HOST',
  'DBUS_SESSION_BUS_ADDRESS',
  'DISPLAY',
  'WAYLAND_DISPLAY',
  // Endpoint, proxy, loader and interpreter injection.
  'HTTP_PROXY',
  'https_proxy',
  'ALL_PROXY',
  'NO_PROXY',
  'ANTHROPIC_BASE_URL',
  'OPENAI_BASE_URL',
  'AZURE_OPENAI_ENDPOINT',
  'NODE_OPTIONS',
  'NODE_PATH',
  'LD_PRELOAD',
  'DYLD_INSERT_LIBRARIES',
  'PYTHONPATH',
  'PYTHONHOME',
  'RUBYOPT',
  'PERL5OPT',
  'BASH_ENV',
  'ENV',
  'ZDOTDIR',
  'PROMPT_COMMAND',
  'GIT_SSH_COMMAND',
  'GIT_ASKPASS',
  'GIT_CONFIG_COUNT',
  'SSL_CERT_FILE',
  'NODE_EXTRA_CA_CERTS',
  'LC_SECRET',
  // Guard state is set by the launcher, never inherited from its caller.
  'AGENTKEEPER_BYPASS',
  'agent_guard_bypass',
  'AGENTKEEPER_ACTIVE',
  'SOME_UNKNOWN_SECRET',
] as const;

describe('EnvironmentPolicy', () => {
  it('allows only non-authority terminal, locale and execution variables by default', () => {
    const policy = EnvironmentPolicy.strict();
    const safe = {
      PATH: '/usr/bin:/bin',
      SHELL: '/bin/zsh',
      TERM: 'xterm-256color',
      COLORTERM: 'truecolor',
      TERM_PROGRAM: 'iTerm.app',
      LANG: 'en_US.UTF-8',
      LC_ALL: 'en_US.UTF-8',
      LC_CTYPE: 'UTF-8',
      TZ: 'UTC',
      COLUMNS: '120',
      LINES: '40',
      NO_COLOR: '1',
      FORCE_COLOR: '1',
      CI: '1',
    };
    const launcherOwned = {
      HOME: '/attacker/home',
      PWD: '/attacker/project',
      TMPDIR: '/Users/dev',
      TMP: '/Users/dev',
      TEMP: '/Users/dev',
      SystemRoot: 'C:\\Windows',
      ComSpec: 'C:\\Windows\\System32\\cmd.exe',
      PATHEXT: '.EXE;.CMD',
      USERPROFILE: 'C:\\Users\\attacker',
      LOCALAPPDATA: 'C:\\Users\\dev\\AppData\\Local',
    };

    const result = sanitizer.sanitize({ ...safe, ...launcherOwned }, policy);

    expect(result.environment).toEqual(safe);
    expect(result.removedNames).toEqual(Object.keys(launcherOwned).sort());
  });

  it('removes ambient credentials, sockets, endpoints, proxies and injection variables', () => {
    const input = Object.fromEntries(DANGEROUS_NAMES.map((name) => [name, `value-of-${name}`]));

    const result = sanitizer.sanitize(input, EnvironmentPolicy.strict());

    expect(result.environment).toEqual({});
    expect(result.removedNames).toEqual([...DANGEROUS_NAMES].sort());
    expect(result.removedCount).toBe(DANGEROUS_NAMES.length);
  });

  it.each([
    ['claude', ['ANTHROPIC_API_KEY']],
    ['claude-code', ['ANTHROPIC_API_KEY']],
    ['/usr/local/bin/codex', ['OPENAI_API_KEY']],
    ['C:\\tools\\codex.cmd', ['OPENAI_API_KEY']],
    ['gemini.exe', ['GEMINI_API_KEY', 'GOOGLE_API_KEY']],
    [
      'opencode',
      [
        'ANTHROPIC_API_KEY',
        'OPENAI_API_KEY',
        'GEMINI_API_KEY',
        'GOOGLE_API_KEY',
        'OPENROUTER_API_KEY',
      ],
    ],
    ['aider', [...PROVIDER_KEYS]],
    ['node', []],
  ] as const)('scopes provider credentials to %s', (executable, expected) => {
    const input = Object.fromEntries(PROVIDER_KEYS.map((name) => [name, `secret-${name}`]));
    const result = sanitizer.sanitize(input, EnvironmentPolicy.forExecutable(executable));

    expect(Object.keys(result.environment).sort()).toEqual([...expected].sort());
    expect(result.removedNames).toEqual(
      PROVIDER_KEYS.filter((name) => !expected.includes(name as never)).sort(),
    );
  });

  it('does not let an endpoint override ride alongside an allowed provider key', () => {
    const result = sanitizer.sanitize(
      {
        ANTHROPIC_API_KEY: 'needed-by-claude',
        ANTHROPIC_BASE_URL: 'https://collector.invalid',
        HTTPS_PROXY: 'https://collector.invalid',
      },
      EnvironmentPolicy.forExecutable('claude'),
    );

    expect(result.environment).toEqual({ ANTHROPIC_API_KEY: 'needed-by-claude' });
    expect(result.removedNames).toEqual(['ANTHROPIC_BASE_URL', 'HTTPS_PROXY']);
  });

  it('rejects credentials outside the closed provider-key vocabulary', () => {
    expect(() =>
      EnvironmentPolicy.strict(['AWS_SECRET_ACCESS_KEY' as ProviderApiKey]),
    ).toThrow(/Unknown provider environment credential/);
  });

  it('deduplicates, sorts and freezes its explicit provider credentials', () => {
    const policy = EnvironmentPolicy.strict([
      'OPENAI_API_KEY',
      'ANTHROPIC_API_KEY',
      'OPENAI_API_KEY',
    ]);

    expect(policy.providerApiKeys).toEqual(['ANTHROPIC_API_KEY', 'OPENAI_API_KEY']);
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.providerApiKeys)).toBe(true);
  });
});

describe('EnvironmentSanitizer', () => {
  it('returns a deeply immutable result without mutating its input', () => {
    const input: Record<string, string> = { PATH: '/usr/bin', AWS_SECRET_ACCESS_KEY: 'secret' };
    const before = { ...input };
    const result = sanitizer.sanitize(input, EnvironmentPolicy.strict());

    expect(input).toEqual(before);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.environment)).toBe(true);
    expect(Object.isFrozen(result.removedNames)).toBe(true);
    expect(() => {
      (result.environment as Record<string, string>)['PATH'] = '/evil';
    }).toThrow();
    expect(() => {
      (result.removedNames as string[]).push('PATH');
    }).toThrow();
  });

  it('rejects a non-string runtime value instead of producing a malformed child environment', () => {
    const malformed = { PATH: undefined } as unknown as Readonly<Record<string, string>>;
    const result = sanitizer.sanitize(malformed, EnvironmentPolicy.strict());

    expect(result.environment).toEqual({});
    expect(result.removedNames).toEqual(['PATH']);
  });

  it('is deterministic and partitions every input name (property)', () => {
    const variableName = fc.stringMatching(/^[A-Za-z_][A-Za-z0-9_]{0,40}$/);
    const environment = fc.dictionary(variableName, fc.string({ maxLength: 80 }));

    fc.assert(
      fc.property(environment, fc.constantFrom('claude', 'codex', 'gemini', 'opencode', 'node'), (input, executable) => {
        const snapshot = { ...input };
        const policy = EnvironmentPolicy.forExecutable(executable);
        const first = sanitizer.sanitize(input, policy);
        const second = sanitizer.sanitize(input, policy);

        expect(input).toEqual(snapshot);
        expect(first.environment).toEqual(second.environment);
        expect(first.removedNames).toEqual(second.removedNames);
        expect(first.removedNames).toEqual([...first.removedNames].sort());
        expect(first.environment['AGENTKEEPER_BYPASS']).toBeUndefined();

        const kept = Object.keys(first.environment);
        expect(new Set([...kept, ...first.removedNames])).toEqual(new Set(Object.keys(input)));
        expect(kept.every((name) => policy.allows(name))).toBe(true);
        expect(first.removedNames.every((name) => !policy.allows(name))).toBe(true);
      }),
      { numRuns: 100 },
    );
  });
});
