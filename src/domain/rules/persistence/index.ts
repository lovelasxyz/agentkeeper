import { Rule } from '../Rule.js';
import { Disposition } from '../../value-objects/Disposition.js';
import { PathPattern } from '../../value-objects/PathPattern.js';
import { RuleId } from '../../value-objects/RuleId.js';
import { Severity } from '../../value-objects/Severity.js';
import { SourceLocation } from '../../value-objects/SourceLocation.js';
import type { BaselineChange } from '../../entities/BaselineChange.js';
import type { Finding } from '../../entities/Finding.js';

/**
 * Family P — zone B of the resident daemon (spec §6.6).
 *
 * These watch the parts of the system that outlive the repository. With
 * isolation working they should never fire; when one does, the severity is
 * raised a level, because the interesting fact is no longer "a file changed"
 * but "something wrote outside the boundary".
 */
export abstract class PersistenceRule extends Rule<BaselineChange> {
  protected abstract readonly patterns: readonly string[];

  private compiled: readonly PathPattern[] | null = null;

  appliesTo(change: BaselineChange): boolean {
    this.compiled ??= this.patterns.map((raw) => PathPattern.of(raw));
    return this.compiled.some((pattern) => pattern.matches(change.path, change.context.home));
  }

  inspect(change: BaselineChange): readonly Finding[] {
    const detail = this.describe(change);
    if (detail === null) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: change.sandboxActive
          ? `${detail} This happened while isolation was active, so something got around it.`
          : detail,
        subject: change.display,
        contentHash: change.currentHash,
        severity: change.sandboxActive ? this.severity.escalated() : this.severity,
        location:
          change.content === null ? null : SourceLocation.firstMatch(change.content, this.needle()),
      }),
    ];
  }

  /** Returns null when this particular change is not worth reporting. */
  protected describe(change: BaselineChange): string | null {
    return `${change.display} was ${change.kind}.`;
  }

  /** What to point at inside the file, when there is something specific. */
  protected needle(): RegExp {
    return /.*/;
  }
}

export class ZshEnvRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P001');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = '~/.zshenv changed';
  readonly remediation =
    '~/.zshenv is read by every zsh process, including non-interactive ones. Review the diff; ' +
    'the previous version is in ~/.agentkeeper/backups/.';

  protected readonly patterns = ['~/.zshenv'];
}

export class ShellStartupRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P002');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'A shell startup file changed';
  readonly remediation =
    'Version managers and plugin frameworks edit these legitimately on update. Confirm the change ' +
    'matches something you just installed.';

  protected readonly patterns = [
    '~/.zshrc',
    '~/.bashrc',
    '~/.bash_profile',
    '~/.profile',
    '~/.config/fish/config.fish',
    '~/.config/fish/conf.d/**',
  ];
}

/**
 * Both spellings, because they are the same setting written two ways: the CLI
 * says `core.hooksPath`, the file says `[core]` + `hooksPath`. Matching only
 * the CLI form means never firing on an actual config file.
 */
const DANGEROUS_GIT_KEYS = /(hooksPath|sshCommand|\[alias\]|\[credential\]|credential\.helper)/i;

export class GitConfigRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P003');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Global git configuration gained an executable setting';
  readonly remediation =
    'core.hooksPath, credential.helper and shell aliases each run a command during ordinary git ' +
    'use. Remove the entry if you did not add it.';

  protected readonly patterns = ['~/.gitconfig', '~/.config/git/config'];

  protected override describe(change: BaselineChange): string | null {
    if (!change.contains(DANGEROUS_GIT_KEYS)) return null;
    return `${change.display} now contains a setting that executes a command.`;
  }

  protected override needle(): RegExp {
    return DANGEROUS_GIT_KEYS;
  }
}

export class AutostartUnitRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P004');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'A login-time service appeared or changed';
  readonly remediation =
    'A launch agent or user unit starts on every login and restarts itself. Remove it unless you ' +
    'installed it deliberately.';

  protected readonly patterns = ['~/Library/LaunchAgents/**', '~/.config/systemd/user/**'];
}

export class CrontabRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P005');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Scheduled tasks changed';
  readonly remediation = 'A cron entry runs on a schedule regardless of what you are doing. Review it.';

  protected readonly patterns = ['/private/var/at/tabs/**', '/var/spool/cron/**'];
}

const SSH_EXECUTION = /(ProxyCommand|LocalCommand|PermitLocalCommand)/;

export class SshPersistenceRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P006');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'SSH access or configuration changed';
  readonly remediation =
    'A key in authorized_keys is permanent remote access; ProxyCommand runs on every connection. ' +
    'Both are worth reading line by line.';

  protected readonly patterns = ['~/.ssh/authorized_keys', '~/.ssh/config'];

  protected override describe(change: BaselineChange): string | null {
    if (change.path.basename === 'authorized_keys') {
      return `${change.display} changed: someone may now be able to log in to this machine.`;
    }
    if (!change.contains(SSH_EXECUTION)) return `${change.display} was ${change.kind}.`;
    return `${change.display} now runs a command on every SSH connection.`;
  }

  protected override needle(): RegExp {
    return SSH_EXECUTION;
  }
}

const NPM_SENSITIVE = /(registry\s*=|_authToken|_auth\s*=)/;

export class NpmrcRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P007');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = '~/.npmrc registry or token changed';
  readonly remediation =
    'A changed registry redirects every install to a server of somebody else’s choosing. A new ' +
    'token is worth explaining.';

  protected readonly patterns = ['~/.npmrc'];

  protected override describe(change: BaselineChange): string | null {
    if (!change.contains(NPM_SENSITIVE)) return null;
    return `${change.display} changed its registry or an authentication token.`;
  }

  protected override needle(): RegExp {
    return NPM_SENSITIVE;
  }
}

export class AgentConfigDriftRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P008');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Agent configuration changed outside agentkeeper';
  readonly remediation =
    'Hooks and MCP servers in global agent settings apply to every project you open. Confirm you ' +
    'made this change.';

  protected readonly patterns = [
    '~/.claude/settings*.json',
    '~/.claude.json',
    '~/.gemini/settings.json',
    '~/.cursor/mcp.json',
  ];
}

export class AgentkeeperControlPlaneDriftRule extends PersistenceRule {
  readonly id = RuleId.of('AG-P009');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Agentkeeper protected configuration changed';
  readonly remediation =
    'Run `agentkeeper repair` and review the pending persistence incident. Do not approve it ' +
    'unless the checksum change matches an installation or configuration action you initiated.';

  protected readonly patterns = [
    '~/.agentkeeper/config.json',
    '~/.agentkeeper/allowlist.json',
    '~/.agentkeeper/installation/**',
    '~/.agentkeeper/shell/**',
    '~/.agentkeeper/shims/**',
  ];
}

export const PERSISTENCE_RULES: readonly PersistenceRule[] = Object.freeze([
  new ZshEnvRule(),
  new ShellStartupRule(),
  new GitConfigRule(),
  new AutostartUnitRule(),
  new CrontabRule(),
  new SshPersistenceRule(),
  new NpmrcRule(),
  new AgentConfigDriftRule(),
  new AgentkeeperControlPlaneDriftRule(),
]);
