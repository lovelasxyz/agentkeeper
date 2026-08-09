import { Container } from '../../../composition/Container.js';
import { ResourceRef } from '../../../domain/value-objects/ResourceRef.js';
import { MESSAGES, Palette } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';

/**
 * `agentkeeper grants` (spec §10.2) — what is open, and how to close it.
 *
 * `--add` exists for tier 1 only. There is deliberately no flag that grants
 * tier 2: adding one would recreate the very affordance §4.5 removes, since a
 * shell command is exactly what an injected instruction can produce.
 */
export type GrantsMode = 'grants' | 'allow' | 'revoke';

export type GrantRequest =
  | { readonly kind: 'list' }
  | {
      readonly kind: 'add';
      readonly target: string;
      readonly access: 'read' | 'write';
      readonly scope: 'global' | 'workspace';
      readonly reason: string;
    }
  | { readonly kind: 'revoke'; readonly id: string }
  | { readonly kind: 'error'; readonly message: string };

const USAGE: Readonly<Record<GrantsMode, string>> = {
  grants: 'grants [--add <dir:path>] [--write] [--revoke <id>]',
  allow: 'allow <path> [--read|--write] [--workspace] [--reason <text>]',
  revoke: 'revoke <id>',
};

/**
 * Turns argv into one intent.
 *
 * Kept separate from execution because this is where the spec's two named
 * verbs (§27) and the older flag form have to agree: `allow ~/x --read` and
 * `grants --add ~/x` must produce exactly the same grant, or the two entry
 * points would drift into different security behaviour.
 */
export function parseGrantRequest(mode: GrantsMode, args: readonly string[]): GrantRequest {
  const flags = Flags.parse(args);
  const reason = flags.value('reason') ?? 'added from the command line';
  const scope = flags.has('workspace') ? 'workspace' : 'global';
  const access = flags.has('write') ? 'write' : 'read';

  if (mode === 'revoke' || flags.value('revoke') !== null) {
    const id = flags.value('revoke') ?? flags.positional[0];
    return id === undefined
      ? { kind: 'error', message: `Usage: agentkeeper ${USAGE.revoke}` }
      : { kind: 'revoke', id };
  }

  const target = flags.value('add') ?? (mode === 'allow' ? flags.positional[0] : undefined);
  if (target === undefined) {
    return mode === 'allow'
      ? { kind: 'error', message: `Usage: agentkeeper ${USAGE.allow}` }
      : { kind: 'list' };
  }
  return { kind: 'add', target, access, scope, reason };
}

export class GrantsCommand implements Command {
  readonly name: string;
  readonly usage: string;
  readonly summary: string;

  constructor(private readonly mode: GrantsMode = 'grants') {
    this.name = mode;
    this.usage = USAGE[mode];
    this.summary =
      mode === 'allow'
        ? 'Open one tier 1 path to the sandbox'
        : mode === 'revoke'
          ? 'Close a grant by id'
          : 'List, add or revoke what the sandbox opens';
  }

  async execute(args: readonly string[]): Promise<number> {
    const request = parseGrantRequest(this.mode, args);
    const container = new Container();
    const palette = Palette.forStream(process.stdout);
    const home = container.files.realPath(container.environment.identityHome);

    if (request.kind === 'error') {
      process.stderr.write(`${request.message}\n`);
      return 1;
    }

    if (request.kind === 'revoke') {
      const removed = await container.grants.revoke(request.id);
      process.stdout.write(
        removed
          ? `Revoked ${request.id}. Takes effect on the next run.\n`
          : `No grant with id ${request.id}.\n`,
      );
      return removed ? 0 : 1;
    }

    if (request.kind === 'add') {
      const outcome = await container.grantAccess().execute({
        resource: ResourceRef.parse(request.target, home),
        access: request.access,
        reason: request.reason,
        scope: request.scope,
        context: {
          home: container.files.realPath(home),
          workspace: container.files.realPath(container.environment.cwd),
          platform: container.environment.platform,
        },
      });

      if (outcome.kind === 'refused') {
        process.stderr.write(`${outcome.message}\n`);
        return 1;
      }
      process.stdout.write(`${palette.green('✓')} ${MESSAGES.grantTakesEffectNextRun}\n`);
      return 0;
    }

    const grants = await container.grants.all();
    if (grants.length === 0) {
      process.stdout.write('No grants. The workspace and the toolchain are all that is open.\n');
      return 0;
    }

    for (const grant of grants) {
      const origin = grant.origin === 'manual' ? palette.yellow('hand-written') : 'runtime';
      process.stdout.write(
        `${palette.bold(grant.id)}  ${grant.access.padEnd(5)} ` +
          `${grant.resource.toResourceString(home)}\n` +
          `  ${palette.dim(`${grant.scope.toString()} · ${origin} · ${grant.reason}`)}\n`,
      );
    }
    return 0;
  }
}
