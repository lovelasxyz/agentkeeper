import { ArtifactRule } from './ArtifactRule.js';
import { Disposition } from '../../value-objects/Disposition.js';
import { RuleId } from '../../value-objects/RuleId.js';
import { Severity } from '../../value-objects/Severity.js';
import { SourceLocation } from '../../value-objects/SourceLocation.js';
import type { Artifact } from '../../entities/Artifact.js';
import type { Finding } from '../../entities/Finding.js';

/** Files the agent reads as trusted input (vector V3). */
const INSTRUCTION_FILES = [
  'CLAUDE.md',
  'CLAUDE.local.md',
  'AGENTS.md',
  'GEMINI.md',
  '.cursorrules',
  '.cursor/rules/**',
  '.github/copilot-instructions.md',
  '.windsurfrules',
  '**/CLAUDE.md',
  '**/AGENTS.md',
];

/**
 * Execution imperatives. Each pattern describes fetch-then-run, which is the
 * shape that turns a document into a payload — not merely a mention of `curl`.
 */
const EXECUTION_PATTERNS: readonly { pattern: RegExp; what: string }[] = [
  { pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|d|k)?sh\b/i, what: 'download piped into a shell' },
  { pattern: /\bbase64\b[^\n|]*(?:-d|--decode)[^\n|]*\|\s*(?:ba|z)?sh\b/i, what: 'base64 payload piped into a shell' },
  { pattern: /\beval\s*["'`]?\$\(\s*(?:curl|wget)/i, what: 'eval of downloaded content' },
  { pattern: /\bpython3?\s+-c\s+["'][^"']*(?:urllib|requests)[^"']*exec/i, what: 'python one-liner that fetches and executes' },
  { pattern: /\|\s*(?:sudo\s+)?(?:ba|z)?sh\s+-[a-z]*c\b/i, what: 'pipe into an inline shell' },
];

/** V3 — an instruction file telling the agent to fetch and run something. */
export class ExecutionImperativeRule extends ArtifactRule {
  readonly id = RuleId.of('AG-I001');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Instruction file tells the agent to execute remote content';
  readonly remediation =
    'The agent treats this file as trusted input. Read the command it is being told to run; if ' +
    'you did not write this line, treat the repository as hostile.';

  protected readonly paths = INSTRUCTION_FILES;

  inspect(artifact: Artifact): readonly Finding[] {
    return EXECUTION_PATTERNS.filter(({ pattern }) => pattern.test(artifact.content)).map(
      ({ pattern, what }) =>
        this.finding({
          title: this.title,
          detail: `${artifact.relativePath} contains a ${what}.`,
          subject: artifact.relativePath,
          contentHash: artifact.hash,
          location: SourceLocation.firstMatch(artifact.content, pattern),
        }),
    );
  }
}

/** Characters that carry text a reviewer cannot see. */
const INVISIBLE = /[​-‏‪-‮⁠-⁤﻿­]/;
/** Tags Block: an entire alphabet that renders as nothing at all. */
const TAG_CHARACTERS = /[\u{e0000}-\u{e007f}]/u;

/** V3 — instructions hidden from the human who reviewed the file. */
export class HiddenInstructionRule extends ArtifactRule {
  readonly id = RuleId.of('AG-I002');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Instruction file contains text you cannot see';
  readonly remediation =
    'The agent reads this; your editor does not show it. Text that hides from the reviewer and ' +
    'not from the model has exactly one purpose.';

  protected readonly paths = INSTRUCTION_FILES;

  inspect(artifact: Artifact): readonly Finding[] {
    const findings: Finding[] = [];

    if (INVISIBLE.test(artifact.content)) {
      findings.push(
        this.finding({
          title: this.title,
          detail: `${artifact.relativePath} contains zero-width or bidirectional control characters.`,
          subject: artifact.relativePath,
          contentHash: artifact.hash,
          location: SourceLocation.firstMatch(artifact.content, INVISIBLE),
        }),
      );
    }

    if (TAG_CHARACTERS.test(artifact.content)) {
      findings.push(
        this.finding({
          title: this.title,
          detail: `${artifact.relativePath} contains Unicode tag characters, which render as nothing.`,
          subject: artifact.relativePath,
          contentHash: artifact.hash,
          location: SourceLocation.firstMatch(artifact.content, TAG_CHARACTERS),
        }),
      );
    }

    const comment = findInstructionalComment(artifact.content);
    if (comment !== null) {
      findings.push(
        this.finding({
          title: this.title,
          detail: `${artifact.relativePath} hides an instruction inside an HTML comment.`,
          subject: artifact.relativePath,
          contentHash: artifact.hash,
          location: SourceLocation.firstMatch(artifact.content, '<!--'),
        }),
      );
    }
    return findings;
  }
}

/** V7 — the file was approved once and has changed since. */
export class InstructionDriftRule extends ArtifactRule {
  readonly id = RuleId.of('AG-I003');
  readonly severity = Severity.MEDIUM;
  readonly defaultDisposition = Disposition.OBSERVE;
  readonly title = 'Instruction file changed since the last run';
  readonly remediation =
    'A file you already read can change under a `git pull`. Review the diff before the next ' +
    'session rather than after it.';

  protected readonly paths = INSTRUCTION_FILES;

  override appliesTo(artifact: Artifact): boolean {
    return super.appliesTo(artifact) && artifact.previousHash !== null;
  }

  inspect(artifact: Artifact): readonly Finding[] {
    if (artifact.previousHash === null || artifact.previousHash.equals(artifact.hash)) {
      return this.none();
    }
    return [
      this.finding({
        title: this.title,
        detail:
          `${artifact.relativePath} changed from ${artifact.previousHash.short} to ` +
          `${artifact.hash.short} since the last scan.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: null,
      }),
    ];
  }
}

/**
 * An HTML comment is only interesting when it reads like an order.
 *
 * A bare `<!-- TODO -->` is noise; the false-positive budget of spec §1.5 is
 * spent on things that are worth a question.
 */
const IMPERATIVE = /\b(ignore|disregard|instead|system|assistant|must|always|never|secret|exfiltrat|send|upload|token|credential)\b/i;

function findInstructionalComment(content: string): string | null {
  const comments = content.match(/<!--[\s\S]*?-->/g) ?? [];
  return comments.find((comment) => comment.length > 40 && IMPERATIVE.test(comment)) ?? null;
}
