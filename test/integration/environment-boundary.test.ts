import { describe, expect, it } from 'vitest';
import { RunSandboxed } from '../../src/application/use-cases/RunSandboxed.js';
import { PolicyBuilder } from '../../src/domain/policy/PolicyBuilder.js';
import { StarterProfile } from '../../src/domain/policy/StarterProfile.js';
import { AccessTierResolver } from '../../src/domain/policy/AccessTierResolver.js';
import { SensitivePathRegistry } from '../../src/domain/paths/SensitivePathRegistry.js';
import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import { JsonGrantStore } from '../../src/infrastructure/store/stores.js';
import {
  FakeEnvironment,
  FixedClock,
  InMemoryFileSystem,
  RecordingAudit,
  RecordingLogger,
} from './fakes.js';
import type { PathContext } from '../../src/domain/paths/PathContext.js';
import type { SandboxPolicy } from '../../src/domain/policy/SandboxPolicy.js';
import type {
  SandboxCapabilities,
  SandboxCommand,
  SandboxRunResult,
  SandboxRunner,
} from '../../src/application/ports/index.js';

const HOME = AbsolutePath.of('/Users/dev');
const WORKSPACE = HOME.join('projects/app');
const PROFILE = StarterProfile.fromSpec({
  id: 'minimal',
  name: 'Minimal',
  description: 'test',
  reads: [],
  writes: [],
  network: [],
});

const paths = SensitivePathRegistry.default();
const policies = new PolicyBuilder(new AccessTierResolver(paths), paths);

class CapturingRunner implements SandboxRunner {
  command: SandboxCommand | null = null;
  context: PathContext | null = null;
  policy: SandboxPolicy | null = null;

  constructor(
    readonly capabilities: SandboxCapabilities = {
      mechanism: 'seatbelt',
      fileModel: 'path-rules',
      networkGranularity: 'port',
    },
  ) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  unenforceable(): readonly string[] {
    return [];
  }

  async run(
    policy: SandboxPolicy,
    context: PathContext,
    command: SandboxCommand,
  ): Promise<SandboxRunResult> {
    this.policy = policy;
    this.context = context;
    this.command = command;
    return { exitCode: 0, signal: null };
  }
}

function build(runner: SandboxRunner | null, unconfined: CapturingRunner) {
  const files = new InMemoryFileSystem();
  const clock = new FixedClock();
  const audit = new RecordingAudit();
  const logger = new RecordingLogger();
  const variables = {
    HOME: HOME.value,
    PATH: '/usr/bin:/bin',
    TERM: 'xterm-256color',
    LANG: 'en_US.UTF-8',
    ANTHROPIC_API_KEY: 'anthropic-needed',
    OPENAI_API_KEY: 'openai-not-needed-by-claude',
    AWS_SECRET_ACCESS_KEY: 'cloud-secret-value',
    NPM_TOKEN: 'package-secret-value',
    GH_TOKEN: 'github-secret-value',
    SSH_AUTH_SOCK: '/tmp/private-ssh-agent.sock',
    GPG_AGENT_INFO: '/tmp/private-gpg-agent.sock',
    DOCKER_HOST: 'unix:///tmp/private-docker.sock',
    HTTPS_PROXY: 'https://collector.invalid',
    ANTHROPIC_BASE_URL: 'https://collector.invalid',
    NODE_OPTIONS: '--require /tmp/injected.js',
    AGENTKEEPER_BYPASS: '1',
    AGENTKEEPER_ACTIVE: 'spoofed',
  };
  const environment = new FakeEnvironment(
    HOME,
    WORKSPACE,
    'darwin',
    AbsolutePath.of('/tmp'),
    variables,
  );
  const grants = new JsonGrantStore(files, HOME.join('.agentkeeper'), HOME);
  const useCase = new RunSandboxed(
    runner,
    unconfined,
    policies,
    grants,
    environment,
    files,
    audit,
    clock,
    logger,
  );
  return { audit, logger, useCase, variables };
}

describe('RunSandboxed environment boundary', () => {
  it('passes only safe ambient state and the provider credential required by the agent', async () => {
    const runner = new CapturingRunner();
    const { useCase } = build(runner, runner);

    await useCase.execute({
      executable: 'claude',
      args: [],
      profile: PROFILE,
      onUnavailable: 'fail',
    });

    expect(runner.command?.env).toEqual({
      AGENTKEEPER_ACTIVE: '1',
      ANTHROPIC_API_KEY: 'anthropic-needed',
      HOME: HOME.value,
      LANG: 'en_US.UTF-8',
      PATH: '/usr/bin:/bin',
      PWD: WORKSPACE.value,
      TERM: 'xterm-256color',
      TEMP: '/private/tmp/agentkeeper-1',
      TMP: '/private/tmp/agentkeeper-1',
      TMPDIR: '/private/tmp/agentkeeper-1',
    });
    expect(runner.command?.env['AGENTKEEPER_BYPASS']).toBeUndefined();
    expect(runner.command?.env['OPENAI_API_KEY']).toBeUndefined();
  });

  it('derives the protected home and scratch directory from trusted identity, not HOME/TMPDIR', async () => {
    const runner = new CapturingRunner();
    const unconfined = new CapturingRunner();
    const files = new InMemoryFileSystem();
    const forgedHome = AbsolutePath.of('/private/tmp/attacker-home');
    const environment = new FakeEnvironment(
      forgedHome,
      WORKSPACE,
      'darwin',
      HOME,
      {
        HOME: forgedHome.value,
        TMPDIR: HOME.value,
        TMP: HOME.value,
        TEMP: HOME.value,
        PATH: '/usr/bin:/bin',
      },
      HOME,
    );
    const grants = new JsonGrantStore(files, forgedHome.join('.agentkeeper'), forgedHome);
    const useCase = new RunSandboxed(
      runner,
      unconfined,
      policies,
      grants,
      environment,
      files,
      new RecordingAudit(),
      new FixedClock(),
      new RecordingLogger(),
    );

    await useCase.execute({
      executable: 'node',
      args: [],
      profile: PROFILE,
      onUnavailable: 'fail',
    });

    expect(runner.context?.home).toEqual(HOME);
    expect(runner.command?.env).toMatchObject({
      HOME: HOME.value,
      PWD: WORKSPACE.value,
      TEMP: '/private/tmp/agentkeeper-1',
      TMP: '/private/tmp/agentkeeper-1',
      TMPDIR: '/private/tmp/agentkeeper-1',
    });
    expect(runner.policy?.reads.some((ref) => ref.path.equals(forgedHome))).toBe(false);
    expect(runner.policy?.writes.some((ref) => ref.path.equals(HOME))).toBe(false);
    expect(await files.exists(AbsolutePath.of('/private/tmp/agentkeeper-1'))).toBe(false);
  });

  it('audits removed variable names and count, never their values', async () => {
    const runner = new CapturingRunner();
    const { audit, useCase, variables } = build(runner, runner);

    await useCase.execute({
      executable: 'claude',
      args: [],
      profile: PROFILE,
      onUnavailable: 'fail',
    });

    const start = audit.entries.find((entry) => entry.event === 'run.start');
    expect(start?.details['environmentRemovedNames']).toEqual([
      'AGENTKEEPER_ACTIVE',
      'AGENTKEEPER_BYPASS',
      'ANTHROPIC_BASE_URL',
      'AWS_SECRET_ACCESS_KEY',
      'DOCKER_HOST',
      'GH_TOKEN',
      'GPG_AGENT_INFO',
      'HOME',
      'HTTPS_PROXY',
      'NODE_OPTIONS',
      'NPM_TOKEN',
      'OPENAI_API_KEY',
      'SSH_AUTH_SOCK',
    ]);
    expect(start?.details['environmentRemovedCount']).toBe(13);

    const recorded = JSON.stringify(audit.entries);
    for (const [name, value] of Object.entries(variables)) {
      if (name === 'HOME') continue; // The existing run metadata contains the workspace path.
      if (name === 'PATH' || name === 'TERM' || name === 'LANG') continue;
      // The literal "1" legitimately occurs in timestamps, counts and exit codes;
      // presence of the variable name above proves the bypass was removed.
      if (name === 'AGENTKEEPER_BYPASS') continue;
      expect(recorded).not.toContain(value);
    }
  });

  it('never reaches Noop even when legacy configuration says warn', async () => {
    const unconfined = new CapturingRunner({
      mechanism: 'none',
      fileModel: 'none',
      networkGranularity: 'none',
    });
    const { useCase } = build(null, unconfined);

    await expect(
      useCase.execute({
        executable: 'claude',
        args: [],
        profile: PROFILE,
        onUnavailable: 'warn',
      }),
    ).rejects.toMatchObject({ reason: 'backend-unavailable', mechanism: 'none' });

    expect(unconfined.command).toBeNull();
  });
});
