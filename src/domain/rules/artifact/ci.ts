import { ArtifactRule } from './ArtifactRule.js';
import { Disposition } from '../../value-objects/Disposition.js';
import { RuleId } from '../../value-objects/RuleId.js';
import { Severity } from '../../value-objects/Severity.js';
import { SourceLocation } from '../../value-objects/SourceLocation.js';
import type { Artifact } from '../../entities/Artifact.js';
import type { Finding } from '../../entities/Finding.js';

const WORKFLOWS = ['.github/workflows/*.yml', '.github/workflows/*.yaml'];

/**
 * Actions that hand a repository's content to an agent.
 *
 * These rules read the workflow as text rather than as parsed YAML. That is a
 * deliberate limit, not an oversight: `zizmor` already does structural workflow
 * analysis well, and duplicating it would mean shipping a YAML parser to
 * re-derive conclusions somebody else derives better. What is added here is
 * only the agent-specific delta (spec §6.8).
 */
const AGENT_ACTIONS = [
  'anthropics/claude-code-action',
  'google-github-actions/run-gemini-cli',
  'openai/codex-action',
  'github/copilot-cli-action',
];

const AGENT_COMMANDS = /\b(claude|gemini|codex|aider|cursor-agent)\b/;

function isAgentWorkflow(content: string): boolean {
  return AGENT_ACTIONS.some((action) => content.includes(action)) || AGENT_COMMANDS.test(content);
}

/** Known-vulnerable CLI versions, from the incidents in spec §2.1. */
const VULNERABLE: readonly { name: string; pattern: RegExp; fixedIn: string; cve: string }[] = [
  {
    name: 'run-gemini-cli',
    pattern: /google-github-actions\/run-gemini-cli@v?(\d+\.\d+\.\d+)/g,
    fixedIn: '0.1.22',
    cve: 'CVE-2026-12537',
  },
  {
    name: 'gemini-cli',
    // The boundary matters: without it this also matches `run-gemini-cli`,
    // whose version numbering is unrelated, and a fixed action gets reported
    // as vulnerable.
    pattern: /(?<![\w-])gemini-cli@v?(\d+\.\d+\.\d+)/g,
    fixedIn: '0.39.1',
    cve: 'CVE-2026-12537',
  },
  {
    name: 'claude-code',
    pattern: /@anthropic-ai\/claude-code@v?(\d+\.\d+\.\d+)/g,
    fixedIn: '2.1.163',
    cve: 'CVE-2026-54316',
  },
];

export class VulnerableCliVersionRule extends ArtifactRule {
  readonly id = RuleId.of('AG-C001');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.BLOCK;
  readonly title = 'Workflow pins a known-vulnerable agent CLI';
  readonly remediation = 'Upgrade to the fixed version listed in the finding, then re-run.';

  protected readonly paths = WORKFLOWS;

  inspect(artifact: Artifact): readonly Finding[] {
    const findings: Finding[] = [];

    for (const entry of VULNERABLE) {
      for (const match of artifact.content.matchAll(entry.pattern)) {
        const version = match[1] as string;
        if (compareVersions(version, entry.fixedIn) >= 0) continue;

        findings.push(
          this.finding({
            title: this.title,
            detail: `${entry.name} ${version} is affected by ${entry.cve}; fixed in ${entry.fixedIn}.`,
            subject: artifact.relativePath,
            contentHash: artifact.hash,
            location: SourceLocation.firstMatch(artifact.content, match[0]),
          }),
        );
      }
    }
    return findings;
  }
}

const YOLO_FLAGS = ['--yolo', '--dangerously-skip-permissions', '--approval-mode=yolo', '--full-auto'];

export class PermissionSkipFlagRule extends ArtifactRule {
  readonly id = RuleId.of('AG-C002');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Workflow disables the agent permission prompt';
  readonly remediation =
    'In CI nobody is there to answer a prompt, so this flag means every tool call is approved. ' +
    'Pair it with a narrow token and a job that holds no other secrets.';

  protected readonly paths = WORKFLOWS;

  inspect(artifact: Artifact): readonly Finding[] {
    const hit = YOLO_FLAGS.find((flag) => artifact.content.includes(flag));
    if (hit === undefined) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} passes ${hit}.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: SourceLocation.firstMatch(artifact.content, hit),
      }),
    ];
  }
}

export class AgentStepNotLastRule extends ArtifactRule {
  readonly id = RuleId.of('AG-C003');
  readonly severity = Severity.MEDIUM;
  readonly defaultDisposition = Disposition.OBSERVE;
  readonly title = 'Steps run after the agent step';
  readonly remediation =
    'Anything the agent wrote is consumed by the steps that follow it. Put the agent last, or ' +
    'treat everything after it as untrusted input.';

  protected readonly paths = WORKFLOWS;

  inspect(artifact: Artifact): readonly Finding[] {
    if (!isAgentWorkflow(artifact.content)) return this.none();

    const lines = artifact.lines();
    const agentIndex = lines.findIndex((line) => isAgentStep(line));
    if (agentIndex === -1) return this.none();

    const following = lines.slice(agentIndex + 1).some((line) => /^\s*-\s+(uses|run):/.test(line));
    if (!following) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} runs further steps after the agent step.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: SourceLocation.atLine(agentIndex + 1, lines[agentIndex] ?? null),
      }),
    ];
  }
}

export class DoublePassRule extends ArtifactRule {
  readonly id = RuleId.of('AG-C004');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Two agent passes share one checkout';
  readonly remediation =
    'The first pass can write an instruction file that the second one loads as trusted input. ' +
    'Check out again between passes, or run them in separate jobs.';

  protected readonly paths = WORKFLOWS;

  inspect(artifact: Artifact): readonly Finding[] {
    const lines = artifact.lines();
    const checkouts = lines.filter((line) => line.includes('actions/checkout@')).length;
    const passes = lines.filter((line) => isAgentStep(line)).length;

    if (passes < 2 || checkouts > passes - 1) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} runs ${passes} agent steps over ${checkouts} checkout(s).`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: SourceLocation.firstMatch(artifact.content, /uses:.*(codex|claude|gemini)/i),
      }),
    ];
  }
}

const UNTRUSTED_TRIGGERS = ['issue_comment', 'pull_request_target', 'issues', 'discussion', 'discussion_comment'];

export class UntrustedTriggerRule extends ArtifactRule {
  readonly id = RuleId.of('AG-C005');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Agent job reachable by an untrusted trigger holds secrets';
  readonly remediation =
    'Anyone who can open an issue can put text into this prompt, and the job has credentials. ' +
    'Gate it behind a label or an author check, or move the secrets out of the job.';

  protected readonly paths = WORKFLOWS;

  inspect(artifact: Artifact): readonly Finding[] {
    if (!isAgentWorkflow(artifact.content)) return this.none();

    const trigger = UNTRUSTED_TRIGGERS.find((name) =>
      new RegExp(`^\\s{0,4}${name}:|^on:\\s*${name}\\b|\\[.*\\b${name}\\b.*\\]`, 'm').test(
        artifact.content,
      ),
    );
    if (trigger === undefined) return this.none();
    if (!/\$\{\{\s*secrets\./.test(artifact.content)) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} is triggered by ${trigger} and passes a secret to the agent.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: SourceLocation.firstMatch(artifact.content, trigger),
      }),
    ];
  }
}

function isAgentStep(line: string): boolean {
  if (!/^\s*-\s+(uses|run):/.test(line)) return false;
  return AGENT_ACTIONS.some((action) => line.includes(action)) || AGENT_COMMANDS.test(line);
}

function compareVersions(left: string, right: string): number {
  const a = left.split('.').map(Number);
  const b = right.split('.').map(Number);
  for (let index = 0; index < 3; index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}
