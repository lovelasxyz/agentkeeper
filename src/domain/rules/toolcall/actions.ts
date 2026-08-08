import { ToolCallRule } from './blocking.js';
import { AbsolutePath } from '../../value-objects/AbsolutePath.js';
import { Disposition } from '../../value-objects/Disposition.js';
import { RuleId } from '../../value-objects/RuleId.js';
import { Severity } from '../../value-objects/Severity.js';
import type { Finding } from '../../entities/Finding.js';
import type { ToolCall } from '../../entities/ToolCall.js';
import type { ShellSegment } from '../../value-objects/ShellCommand.js';

/**
 * Family A — irreversible actions (spec §6.7).
 *
 * Off by default, and the reason is stated rather than hidden: switching these
 * on for an actively working developer costs several interruptions a day, which
 * is a direct conflict with the budget in §1.5. They are for people running an
 * agent unattended, who are making a different trade knowingly.
 */
abstract class ShellActionRule extends ToolCallRule {
  appliesTo(call: ToolCall): boolean {
    return call.isShell && call.command() !== null;
  }

  inspect(call: ToolCall): readonly Finding[] {
    const command = call.command();
    if (command === null) return this.none();

    return command.segments
      .filter((segment) => this.matches(segment, call))
      .map((segment) =>
        this.finding({
          title: this.title,
          detail: this.describe(segment),
          subject: segment.toString(),
          location: null,
        }),
      );
  }

  protected abstract matches(segment: ShellSegment, call: ToolCall): boolean;
  protected abstract describe(segment: ShellSegment): string;
}

const PROTECTED_BRANCHES = ['main', 'master', 'release', 'production'];

export class ForcePushRule extends ShellActionRule {
  readonly id = RuleId.of('AG-A001');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Force push to a protected branch';
  readonly remediation = 'A force push discards commits on the remote. Confirm the branch and the remote first.';

  protected matches(segment: ShellSegment): boolean {
    if (!isProgram(segment, 'git') || segment.subcommand !== 'push') return false;
    if (!segment.hasFlag('--force', '-f', '--force-with-lease')) return false;
    return segment.args.some((arg) => PROTECTED_BRANCHES.some((branch) => arg.includes(branch)));
  }

  protected describe(segment: ShellSegment): string {
    return `The command force-pushes to a protected branch: ${segment.toString()}`;
  }
}

const PUBLISH: readonly { program: string; subcommand: string }[] = [
  { program: 'npm', subcommand: 'publish' },
  { program: 'pnpm', subcommand: 'publish' },
  { program: 'yarn', subcommand: 'publish' },
  { program: 'cargo', subcommand: 'publish' },
  { program: 'twine', subcommand: 'upload' },
  { program: 'gem', subcommand: 'push' },
];

export class PublishRule extends ShellActionRule {
  readonly id = RuleId.of('AG-A002');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Package publication';
  readonly remediation =
    'Publishing puts code under your name onto a registry other people install from. It cannot ' +
    'be undone.';

  protected matches(segment: ShellSegment): boolean {
    return PUBLISH.some(
      (entry) => isProgram(segment, entry.program) && segment.subcommand === entry.subcommand,
    );
  }

  protected describe(segment: ShellSegment): string {
    return `The command publishes a package: ${segment.toString()}`;
  }
}

export class RecursiveDeleteRule extends ShellActionRule {
  readonly id = RuleId.of('AG-A003');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Recursive delete outside the workspace';
  readonly remediation = 'Check the path. Inside the workspace this is routine; outside it is not.';

  protected matches(segment: ShellSegment, call: ToolCall): boolean {
    if (!isProgram(segment, 'rm')) return false;
    if (!segment.args.some((arg) => /^-[a-z]*r/i.test(arg))) return false;

    return segment.args
      .filter((arg) => !arg.startsWith('-'))
      .some((arg) => {
        const target = resolve(arg, call);
        return target === null || !call.context.workspace.contains(target);
      });
  }

  protected describe(segment: ShellSegment): string {
    return `The command deletes recursively outside the workspace: ${segment.toString()}`;
  }
}

const INFRASTRUCTURE: readonly { program: string; verbs: readonly string[] }[] = [
  { program: 'aws', verbs: ['delete', 'terminate', 'put', 'create', 'update', 'modify'] },
  { program: 'gcloud', verbs: ['delete', 'create', 'update', 'deploy'] },
  { program: 'kubectl', verbs: ['delete', 'apply', 'patch', 'scale', 'drain'] },
  { program: 'terraform', verbs: ['apply', 'destroy'] },
  { program: 'pulumi', verbs: ['up', 'destroy'] },
];

export class InfrastructureMutationRule extends ShellActionRule {
  readonly id = RuleId.of('AG-A004');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Infrastructure change';
  readonly remediation = 'This command changes live infrastructure. Confirm the account and the target.';

  protected matches(segment: ShellSegment): boolean {
    const entry = INFRASTRUCTURE.find((candidate) => isProgram(segment, candidate.program));
    if (entry === undefined) return false;
    return segment.args.some((arg) => entry.verbs.includes(arg));
  }

  protected describe(segment: ShellSegment): string {
    return `The command changes infrastructure: ${segment.toString()}`;
  }
}

export class DockerEscapeRule extends ShellActionRule {
  readonly id = RuleId.of('AG-A005');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Container mounts the host filesystem or the Docker socket';
  readonly remediation =
    'Mounting / or docker.sock hands the container everything this machine has, including the ' +
    'files the sandbox is keeping out of reach.';

  protected matches(segment: ShellSegment): boolean {
    if (!isProgram(segment, 'docker') && !isProgram(segment, 'podman')) return false;
    return segment.args.some(
      (arg) =>
        arg.includes('docker.sock') ||
        /^\/:/.test(arg) ||
        /^(-v|--volume)?=?\/:\//.test(arg) ||
        arg === '--privileged',
    );
  }

  protected describe(segment: ShellSegment): string {
    return `The command gives a container host-level access: ${segment.toString()}`;
  }
}

export class WorkflowEditRule extends ToolCallRule {
  readonly id = RuleId.of('AG-A006');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'CI workflow modified';
  readonly remediation =
    'A workflow change runs on the next push, with whatever secrets the job holds. Read the diff.';

  appliesTo(call: ToolCall): boolean {
    return call.access === 'write';
  }

  inspect(call: ToolCall): readonly Finding[] {
    return call
      .paths()
      .filter((path) => path.value.includes('/.github/workflows/'))
      .map((path) =>
        this.finding({
          title: this.title,
          detail: `${call.tool} would modify ${path.toDisplay(call.context.home)}.`,
          subject: path.toDisplay(call.context.home),
          location: null,
        }),
      );
  }
}

const OUTBOUND_MCP = /(send|post|create|publish|notify|email|message|comment|tweet|upload)/i;

export class OutboundMessageRule extends ToolCallRule {
  readonly id = RuleId.of('AG-A007');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Outbound message through an MCP server';
  readonly remediation =
    'This sends something out of your machine under your identity. Read what is being sent and ' +
    'to whom.';

  appliesTo(call: ToolCall): boolean {
    return call.isMcp;
  }

  inspect(call: ToolCall): readonly Finding[] {
    if (!OUTBOUND_MCP.test(call.tool)) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${call.tool} sends data out of this machine.`,
        subject: call.tool,
        location: null,
      }),
    ];
  }
}

function isProgram(segment: ShellSegment, name: string): boolean {
  const program = segment.program;
  return program === name || program?.endsWith(`/${name}`) === true;
}

function resolve(arg: string, call: ToolCall): AbsolutePath | null {
  try {
    if (arg.startsWith('~')) return AbsolutePath.fromUserPath(arg, call.context.home);
    if (arg.startsWith('/')) return AbsolutePath.of(arg);
    if (arg.includes('*')) return null; // a glob has no single target to resolve
    return call.context.workspace.join(arg);
  } catch {
    return null;
  }
}
