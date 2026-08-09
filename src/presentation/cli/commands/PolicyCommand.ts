import { Container } from '../../../composition/Container.js';
import type { SandboxPolicy } from '../../../domain/policy/SandboxPolicy.js';
import type { AbsolutePath } from '../../../domain/value-objects/AbsolutePath.js';
import { WorkspaceId } from '../../../domain/value-objects/WorkspaceId.js';
import { Palette } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';

/**
 * `agentkeeper policy` (spec §32) — the boundary that would apply here.
 *
 * Printed from the same `PolicyBuilder` result a protected launch uses, so
 * what the user reads is what the backend compiles rather than a summary of
 * the configuration files that fed it.
 */
export class PolicyCommand implements Command {
  readonly name = 'policy';
  readonly usage = 'policy [--json]';
  readonly summary = 'Show the effective policy for this directory and its identity hash';

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const container = new Container({ quiet: flags.has('json'), interactive: false });
    const config = await container.config();
    const home = container.files.realPath(container.environment.identityHome);
    const workspace = container.files.realPath(container.environment.cwd);
    const context = { home, workspace, platform: container.environment.platform } as const;
    const profile = await (await container.profiles()).load(config.starterProfile);

    const { policy, rejected } = container.policies.build({
      profile,
      grants: await container.grants.all(),
      context,
      workspaceId: WorkspaceId.fromPath(workspace),
      toolchainRoots: container.environment
        .toolchainRoots()
        .map((path) => container.files.realPath(path)),
      stateDir: home.join('.agentkeeper'),
      agentStateDirs: [],
      tempDirs: [],
    });

    if (flags.has('json')) {
      process.stdout.write(
        `${JSON.stringify(
          {
            policyHash: policy.policyHash,
            profile: config.starterProfile,
            workspace: workspace.value,
            reads: policy.reads.map(String),
            writes: policy.writes.map(String),
            denies: policy.denies.map(String),
            network: policy.network.map(String),
            rejectedGrants: rejected.map((entry) => entry.reason),
          },
          null,
          2,
        )}\n`,
      );
      return 0;
    }

    process.stdout.write(`${renderPolicy(policy, home, config.starterProfile).join('\n')}\n`);
    for (const entry of rejected) {
      process.stderr.write(`${Palette.forStream(process.stderr).yellow('refused')} ${entry.reason}\n`);
    }
    return 0;
  }
}

/**
 * Renders the policy for a human.
 *
 * Paths are shown home-relative because that is how people recognise them, and
 * because an absolute path in a pasted bug report leaks a username for no gain.
 */
export function renderPolicy(
  policy: SandboxPolicy,
  home: AbsolutePath,
  profile?: string,
): readonly string[] {
  const palette = Palette.forStream(process.stdout);
  // Rules print as `scope:path` or `deny read <pattern> except <path>`, so the
  // home prefix is replaced wherever it appears rather than only at the start.
  const shorten = (value: string): string => value.split(home.value).join('~');
  const list = (label: string, values: readonly { toString(): string }[]): string[] =>
    values.length === 0
      ? [`  ${label}: none`]
      : [`  ${label}:`, ...values.map((value) => `    ${shorten(value.toString())}`)];

  return [
    `${palette.bold('policy')} ${policy.policyHash}`,
    ...(profile === undefined ? [] : [`  profile: ${profile}`]),
    `  workspace: ${shorten(policy.workspace.value)}`,
    ...list('readable', policy.reads),
    ...list('writable', policy.writes),
    ...list('refused', policy.denies),
    ...(policy.network.length === 0
      ? ['  network: no outbound destination is allowed; egress is denied']
      : ['  network:', ...policy.network.map((rule) => `    ${describe(rule)}`)]),
  ];
}

function describe(rule: { host: string; port: number | '*'; toString(): string }): string {
  if (rule.host === 'loopback') return 'localhost (local dev servers and MCP)';
  if (rule.host === 'any') return `${rule.toString()} (legacy any-host rule; not brokerable)`;
  return `${rule.host}:${String(rule.port)}`;
}
