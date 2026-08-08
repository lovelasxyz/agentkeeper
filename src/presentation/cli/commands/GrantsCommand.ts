import { Container } from '../../../composition/Container.js';
import { ResourceRef } from '../../../domain/value-objects/ResourceRef.js';
import { MESSAGES, Palette } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';

/**
 * `agent-guard grants` (spec §10.2) — what is open, and how to close it.
 *
 * `--add` exists for tier 1 only. There is deliberately no flag that grants
 * tier 2: adding one would recreate the very affordance §4.5 removes, since a
 * shell command is exactly what an injected instruction can produce.
 */
export class GrantsCommand implements Command {
  readonly name = 'grants';
  readonly usage = 'grants [--add <dir:path>] [--write] [--revoke <id>]';
  readonly summary = 'List, add or revoke what the sandbox opens';

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const container = new Container();
    const palette = Palette.forStream(process.stdout);
    const home = container.environment.home;

    const revoke = flags.value('revoke');
    if (revoke !== null) {
      const removed = await container.grants.revoke(revoke);
      process.stdout.write(
        removed
          ? `Revoked ${revoke}. Takes effect on the next run.\n`
          : `No grant with id ${revoke}.\n`,
      );
      return removed ? 0 : 1;
    }

    const add = flags.value('add');
    if (add !== null) {
      const outcome = await container.grantAccess().execute({
        resource: ResourceRef.parse(add, home),
        access: flags.has('write') ? 'write' : 'read',
        reason: flags.value('reason') ?? 'added from the command line',
        scope: flags.has('workspace') ? 'workspace' : 'global',
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
