import { Rule } from '../Rule.js';
import { Disposition } from '../../value-objects/Disposition.js';
import { RuleId } from '../../value-objects/RuleId.js';
import { Severity } from '../../value-objects/Severity.js';
import type { AbsolutePath } from '../../value-objects/AbsolutePath.js';
import type { Finding } from '../../entities/Finding.js';
import type { ToolCall } from '../../entities/ToolCall.js';
import type { AccessTierResolver } from '../../policy/AccessTierResolver.js';

export abstract class ToolCallRule extends Rule<ToolCall> {}

/**
 * AG-B001 — the agent reaches for something the sandbox already refuses.
 *
 * Redundant with layer 1 by design, and worth having anyway: it turns an
 * `EPERM` the model may misread into a recorded, explained refusal, and it is
 * the only signal available when the sandbox is unavailable (spec §4.8).
 */
export class SensitivePathAccessRule extends ToolCallRule {
  readonly id = RuleId.of('AG-B001');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.BLOCK;
  readonly title = 'Tool call reaches for a protected path';
  readonly remediation =
    'Access to credentials, persistence and shell history is configured by editing ' +
    '~/.agentkeeper/allowlist.json in a text editor. There is no prompt for it, by design.';

  constructor(private readonly tiers: AccessTierResolver) {
    super();
  }

  appliesTo(call: ToolCall): boolean {
    return call.paths().length > 0;
  }

  inspect(call: ToolCall): readonly Finding[] {
    const access = call.access;
    return call
      .paths()
      .filter((path) => !this.tiers.tierOf(path, access, call.context).canBeGrantedAtRuntime)
      .map((path) => {
        const reason = this.tiers.explain(path, access, call.context);
        return this.finding({
          title: this.title,
          detail:
            `${call.tool} would ${access} ${display(path, call)}. ` +
            (reason?.rationale ?? 'This path holds credentials or grants persistence.'),
          subject: display(path, call),
          location: null,
        });
      });
  }
}

/** AG-B002 — reading a neighbouring project's environment file. */
export class ForeignEnvFileRule extends ToolCallRule {
  readonly id = RuleId.of('AG-B002');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.BLOCK;
  readonly title = 'Tool call reads an environment file outside the workspace';
  readonly remediation =
    'The current project’s own .env is available. Another project’s is not, and no task in this ' +
    'repository needs it.';

  appliesTo(call: ToolCall): boolean {
    return call.paths().some((path) => isEnvFile(path));
  }

  inspect(call: ToolCall): readonly Finding[] {
    return call
      .paths()
      .filter((path) => isEnvFile(path) && !call.context.workspace.contains(path))
      .map((path) =>
        this.finding({
          title: this.title,
          detail: `${call.tool} would read ${display(path, call)}, which belongs to another project.`,
          subject: display(path, call),
          location: null,
        }),
      );
  }
}

const AGENT_CONFIG = /(^|\/)\.(claude|gemini|cursor|codex|aider)(\.json|\/(settings|mcp)[^/]*\.json)$/;

/** AG-B003 — writing the agent's own configuration (vector V2). */
export class AgentConfigWriteRule extends ToolCallRule {
  readonly id = RuleId.of('AG-B003');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.BLOCK;
  readonly title = 'Tool call writes agent configuration';
  readonly remediation =
    'Hooks and MCP servers written here run on the next session start. Change agent settings ' +
    'yourself, in your editor.';

  appliesTo(call: ToolCall): boolean {
    return call.access === 'write' || call.isShell;
  }

  inspect(call: ToolCall): readonly Finding[] {
    return call
      .paths()
      .filter((path) => AGENT_CONFIG.test(path.value))
      .map((path) =>
        this.finding({
          title: this.title,
          detail: `${call.tool} would write ${display(path, call)}, which executes on the next start.`,
          subject: display(path, call),
          location: null,
        }),
      );
  }
}

/** AG-B004 — repointing git hooks, which turns every commit into execution. */
export class GitHooksPathRule extends ToolCallRule {
  readonly id = RuleId.of('AG-B004');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.BLOCK;
  readonly title = 'Tool call changes where git looks for hooks';
  readonly remediation =
    'core.hooksPath makes every git operation run code from a directory of the setter’s ' +
    'choosing. Set it yourself if you need it.';

  appliesTo(call: ToolCall): boolean {
    return call.isShell;
  }

  inspect(call: ToolCall): readonly Finding[] {
    const command = call.command();
    if (command === null) return this.none();

    const offending = command
      .invocationsOf('git')
      .filter((segment) => segment.tokens.includes('config'))
      .filter((segment) => segment.tokens.some((token) => token.includes('core.hooksPath')));

    return offending.map((segment) =>
      this.finding({
        title: this.title,
        detail: `The command sets core.hooksPath: ${segment.toString()}`,
        subject: segment.toString(),
        location: null,
      }),
    );
  }
}

/** AG-B005 — self-protection: an agent that edits its own allowlist has none. */
export class SelfProtectionRule extends ToolCallRule {
  readonly id = RuleId.of('AG-B005');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.BLOCK;
  readonly title = 'Tool call modifies agentkeeper itself';
  readonly remediation =
    'Grants are added by editing ~/.agentkeeper/allowlist.json yourself. That gap between asking ' +
    'and receiving is the whole permission model; a tool call cannot close it.';

  appliesTo(call: ToolCall): boolean {
    return true;
  }

  inspect(call: ToolCall): readonly Finding[] {
    const stateDir = call.context.home.join('.agentkeeper');
    const paths = call.paths().filter((path) => stateDir.contains(path));

    const findings = paths.map((path) =>
      this.finding({
        title: this.title,
        detail: `${call.tool} would modify ${display(path, call)}.`,
        subject: display(path, call),
        location: null,
      }),
    );

    const command = call.command();
    if (command !== null && /agentkeeper\s+(grants|uninstall|pause)/.test(command.raw)) {
      findings.push(
        this.finding({
          title: this.title,
          detail: `The command would reconfigure agentkeeper: ${command.raw}`,
          subject: command.raw,
          location: null,
        }),
      );
    }
    return findings;
  }
}

/** AG-B006 — relaunching the agent with isolation turned off. */
export class BypassEnvironmentRule extends ToolCallRule {
  readonly id = RuleId.of('AG-B006');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.BLOCK;
  readonly title = 'Tool call tries to start a command with isolation disabled';
  readonly remediation =
    'AGENTKEEPER_BYPASS exists so *you* can skip the wrapper from your own shell. Reaching it ' +
    'from inside the agent would make the wrapper optional, which is the same as absent.';

  appliesTo(call: ToolCall): boolean {
    return call.isShell;
  }

  inspect(call: ToolCall): readonly Finding[] {
    const command = call.command();
    if (command === null) return this.none();

    const assignments = command.assignments();
    const viaEnvironment = Object.keys(assignments).some((name) => name === 'AGENTKEEPER_BYPASS');
    const viaText = /AGENTKEEPER_BYPASS/.test(command.raw);
    if (!viaEnvironment && !viaText) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `The command sets AGENTKEEPER_BYPASS: ${command.raw}`,
        subject: command.raw,
        location: null,
      }),
    ];
  }
}

function isEnvFile(path: AbsolutePath): boolean {
  return path.basename === '.env' || path.basename.startsWith('.env.');
}

function display(path: AbsolutePath, call: ToolCall): string {
  return path.toDisplay(call.context.home);
}
