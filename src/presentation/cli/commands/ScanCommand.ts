import { Container } from '../../../composition/Container.js';
import { AbsolutePath } from '../../../domain/value-objects/AbsolutePath.js';
import { MESSAGES, Palette, renderFinding } from '../../messages/render.js';
import { Flags, type Command } from '../Command.js';

/**
 * `agentkeeper scan [path]` — layer 2 on demand (spec §10.2).
 *
 * Also the body of the git hook, which is why `--quiet` exists: after a
 * checkout the user wants silence unless something is wrong.
 */
export class ScanCommand implements Command {
  readonly name = 'scan';
  readonly usage = 'scan [path] [--quiet] [--json]';
  readonly summary = 'Inspect a workspace for autorun artifacts and injected instructions';

  async execute(args: readonly string[]): Promise<number> {
    const flags = Flags.parse(args);
    const quiet = flags.has('quiet');
    const json = flags.has('json');
    const source = flags.value('source') ?? 'cli';
    const interactive = shouldReviewInteractively({ quiet, json, source });
    const container = new Container({ quiet: quiet || json, interactive });

    const workspace = container.files.realPath(
      resolveTarget(
        flags.positional[0],
        container.environment.cwd,
        container.environment.identityHome,
      ),
    );

    const useCase = await container.scanWorkspace();
    const scanned = await useCase.execute(workspace);
    const report = interactive
      ? (await (await container.reviewFindings()).execute(scanned.report)).report
      : scanned.report;
    const { filesInspected } = scanned;

    if (json) {
      process.stdout.write(
        `${JSON.stringify(
          { workspace: workspace.value, filesInspected, findings: report.findings },
          null,
          2,
        )}\n`,
      );
      return report.blocking().length > 0 ? 2 : 0;
    }

    const palette = Palette.forStream(process.stdout);

    if (report.isClean) {
      if (!quiet) {
        process.stdout.write(
          `${palette.green('✓')} ${MESSAGES.scanClean} ${palette.dim(
            `(${filesInspected} file(s) inspected)`,
          )}\n`,
        );
      }
      return 0;
    }

    process.stdout.write(
      `${report.findings.map((finding) => renderFinding(finding, palette)).join('\n\n')}\n`,
    );

    await container.audit.append({
      at: container.clock.now(),
      event: 'scan.completed',
      details: {
        workspace: workspace.value,
        source,
        findings: report.findings.length,
        worst: report.worstSeverity.name,
      },
    });

    return report.blocking().length > 0 ? 2 : 0;
  }
}

export function shouldReviewInteractively(input: {
  readonly quiet: boolean;
  readonly json: boolean;
  readonly source: string;
}): boolean {
  return !input.quiet && !input.json && input.source !== 'git' && !input.source.startsWith('git-');
}

/** Accepts what a shell would hand over: nothing, `.`, `~/x`, `/abs`, `sub/dir`. */
export function resolveTarget(
  raw: string | undefined,
  cwd: AbsolutePath,
  home: AbsolutePath,
): AbsolutePath {
  if (raw === undefined) return cwd;
  if (raw.startsWith('/') || raw.startsWith('~')) return AbsolutePath.fromUserPath(raw, home);
  return cwd.join(raw);
}
