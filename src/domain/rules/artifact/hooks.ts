import { ArtifactRule } from './ArtifactRule.js';
import { Disposition } from '../../value-objects/Disposition.js';
import { RuleId } from '../../value-objects/RuleId.js';
import { Severity } from '../../value-objects/Severity.js';
import { SourceLocation } from '../../value-objects/SourceLocation.js';
import type { Artifact } from '../../entities/Artifact.js';
import type { Finding } from '../../entities/Finding.js';

const AGENT_SETTINGS = ['.claude/settings.json', '.claude/settings.local.json'];

/** Hook names that fire without the user asking for anything. */
const AUTORUN_HOOKS = ['SessionStart', 'SessionEnd', 'PreToolUse', 'PostToolUse', 'Notification'];

/** V2 — any hook at all in repository-level agent settings. */
export class RepositoryHookRule extends ArtifactRule {
  readonly id = RuleId.of('AG-H001');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Repository settings define an agent hook';
  readonly remediation =
    'Open the file and read the command. A hook committed to a repository runs on your machine ' +
    'with your permissions, every session, without asking.';

  protected readonly paths = AGENT_SETTINGS;

  inspect(artifact: Artifact): readonly Finding[] {
    const hooks = ArtifactRule.at(artifact.json(), 'hooks');
    if (!ArtifactRule.isRecord(hooks)) return this.none();

    const names = Object.keys(hooks);
    if (names.length === 0) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} defines ${names.length} hook (${names.join(', ')}).`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: SourceLocation.firstMatch(artifact.content, '"hooks"'),
      }),
    ];
  }
}

/** V2 — the ChainDrop signature specifically: execution at session start. */
export class SessionStartHookRule extends ArtifactRule {
  readonly id = RuleId.of('AG-H002');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Hook runs at session start';
  readonly remediation =
    'This is the ChainDrop pattern: a compromised dependency plants a SessionStart hook that ' +
    'fires the next time the agent opens. Read the command before allowing it.';

  protected readonly paths = AGENT_SETTINGS;

  inspect(artifact: Artifact): readonly Finding[] {
    const hooks = ArtifactRule.at(artifact.json(), 'hooks');
    if (!ArtifactRule.isRecord(hooks)) return this.none();

    return Object.keys(hooks)
      .filter((name) => name === 'SessionStart')
      .map((name) =>
        this.finding({
          title: this.title,
          detail: `${artifact.relativePath} runs a command on every ${name}.`,
          subject: artifact.relativePath,
          contentHash: artifact.hash,
          location: SourceLocation.firstMatch(artifact.content, name),
        }),
      );
  }
}

/** V1 — a VS Code task that executes as soon as the folder is opened. */
export class FolderOpenTaskRule extends ArtifactRule {
  readonly id = RuleId.of('AG-H003');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'VS Code task runs on folder open';
  readonly remediation =
    'Opening this repository in your editor executes the task. Remove runOptions.runOn or read ' +
    'the command first.';

  protected readonly paths = ['.vscode/tasks.json'];

  inspect(artifact: Artifact): readonly Finding[] {
    const tasks = ArtifactRule.at(artifact.json(), 'tasks');
    if (!Array.isArray(tasks)) return this.none();

    return tasks
      .filter((task) => ArtifactRule.at(task, 'runOptions', 'runOn') === 'folderOpen')
      .map((task) =>
        this.finding({
          title: this.title,
          detail:
            `Task ${JSON.stringify(ArtifactRule.at(task, 'label') ?? 'unnamed')} runs ` +
            `${JSON.stringify(ArtifactRule.at(task, 'command') ?? '')} when the folder opens.`,
          subject: artifact.relativePath,
          contentHash: artifact.hash,
          location: SourceLocation.firstMatch(artifact.content, 'folderOpen'),
        }),
      );
  }
}

const LIFECYCLE = ['initializeCommand', 'onCreateCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand'];

/** V1 — devcontainer lifecycle commands. */
export class DevcontainerLifecycleRule extends ArtifactRule {
  readonly id = RuleId.of('AG-H004');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Dev container runs a lifecycle command';
  readonly remediation =
    'initializeCommand runs on the host, not in the container. Read it before reopening the ' +
    'folder in a container.';

  protected readonly paths = ['.devcontainer/devcontainer.json', '.devcontainer/**/devcontainer.json'];

  inspect(artifact: Artifact): readonly Finding[] {
    const document = artifact.json();
    if (!ArtifactRule.isRecord(document)) return this.none();

    const present = LIFECYCLE.filter((key) => document[key] !== undefined);
    if (present.length === 0) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} defines ${present.join(', ')}.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: SourceLocation.firstMatch(artifact.content, present[0] as string),
      }),
    ];
  }
}

/** V1 — an executable hook inside a freshly cloned repository. */
export class ClonedGitHookRule extends ArtifactRule {
  readonly id = RuleId.of('AG-H005');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Repository carries a git hook';
  readonly remediation =
    'Hooks in .git/hooks run on checkout, merge and commit. Read the script, then remove it or ' +
    'allow it deliberately.';

  protected readonly paths = ['.git/hooks/*'];

  inspect(artifact: Artifact): readonly Finding[] {
    // git ships every hook as a `.sample`; those are inert by design.
    if (artifact.basename.endsWith('.sample')) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} will run during ordinary git operations.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: SourceLocation.atLine(1, artifact.lines()[0] ?? null),
      }),
    ];
  }
}

/** V1 — direnv. Common and usually legitimate, so it is recorded, not asked about. */
export class DirenvRule extends ArtifactRule {
  readonly id = RuleId.of('AG-H006');
  readonly severity = Severity.MEDIUM;
  readonly defaultDisposition = Disposition.OBSERVE;
  readonly title = 'Repository carries a .envrc';
  readonly remediation =
    'With direnv installed, this file executes when you enter the directory. `direnv allow` is ' +
    'the moment to read it.';

  protected readonly paths = ['.envrc'];

  inspect(artifact: Artifact): readonly Finding[] {
    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} executes on directory entry when direnv is installed.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: null,
      }),
    ];
  }
}
