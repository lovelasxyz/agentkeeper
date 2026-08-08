import type { Finding } from '../../domain/entities/Finding.js';
import type { PlannedChange } from '../../application/ports/Integration.js';

/**
 * All user-facing text lives here (spec §14): one tone, testable, and ready for
 * localisation later. Interface language is English — the project is aimed at
 * an international open-source audience.
 */

const COLOURS = {
  reset: '[0m',
  dim: '[2m',
  bold: '[1m',
  red: '[31m',
  yellow: '[33m',
  green: '[32m',
  blue: '[34m',
} as const;

export class Palette {
  constructor(private readonly enabled: boolean) {}

  static forStream(stream: NodeJS.WriteStream): Palette {
    return new Palette(stream.isTTY === true && process.env['NO_COLOR'] === undefined);
  }

  private wrap(colour: keyof typeof COLOURS, text: string): string {
    return this.enabled ? `${COLOURS[colour]}${text}${COLOURS.reset}` : text;
  }

  dim(text: string): string {
    return this.wrap('dim', text);
  }
  bold(text: string): string {
    return this.wrap('bold', text);
  }
  red(text: string): string {
    return this.wrap('red', text);
  }
  yellow(text: string): string {
    return this.wrap('yellow', text);
  }
  green(text: string): string {
    return this.wrap('green', text);
  }
  blue(text: string): string {
    return this.wrap('blue', text);
  }
}

/** Spec §14: what was found, where, why it matters, one action. Five lines at most. */
export function renderFinding(finding: Finding, palette: Palette): string {
  const badge = severityBadge(finding, palette);
  const where = finding.location === null ? '' : palette.dim(` (${finding.location.toString()})`);

  return [
    `${badge} ${palette.bold(finding.title)}`,
    `  ${finding.subject}${where}`,
    `  ${finding.detail}`,
    `  ${palette.dim(finding.remediation)}`,
    palette.dim(`  ${finding.ruleId.toString()}`),
  ].join('\n');
}

function severityBadge(finding: Finding, palette: Palette): string {
  const label = finding.severity.name.toUpperCase().padEnd(8);
  if (finding.severity.name === 'critical') return palette.red(label);
  if (finding.severity.name === 'high') return palette.yellow(label);
  return palette.dim(label);
}

/** Unified-style diff, so `init` can show exactly what it is about to write. */
export function renderDiff(change: PlannedChange, palette: Palette): string {
  const before = (change.before ?? '').split('\n');
  const after = (change.after ?? '').split('\n');
  const lines: string[] = [
    palette.bold(change.path.value),
    palette.dim(`  ${change.summary}`),
  ];

  if (change.after === null) {
    lines.push(palette.red('  - (file removed)'));
    return lines.join('\n');
  }

  // Both files are small and generated; a common-prefix/suffix diff is enough
  // to show a human what changed without pulling in a diff library.
  let head = 0;
  while (head < before.length && head < after.length && before[head] === after[head]) head += 1;

  let tail = 0;
  while (
    tail < before.length - head &&
    tail < after.length - head &&
    before[before.length - 1 - tail] === after[after.length - 1 - tail]
  ) {
    tail += 1;
  }

  for (const line of before.slice(head, before.length - tail)) {
    lines.push(palette.red(`  - ${line}`));
  }
  for (const line of after.slice(head, after.length - tail)) {
    lines.push(palette.green(`  + ${line}`));
  }
  return lines.join('\n');
}

export const MESSAGES = {
  noMechanism:
    'No isolation mechanism is available on this platform. agent-guard is NOT protecting you ' +
    'beyond its rule layer — see `agent-guard status`.',

  grantTakesEffectNextRun:
    'Granted. It takes effect on the next run: both sandbox mechanisms fix the profile when the ' +
    'process starts, so a running agent keeps the world it was given.',

  tierTwoRefused:
    'This category is not configurable while the agent is running. Edit ' +
    '~/.agent-guard/allowlist.json in your editor if you genuinely need it.',

  scanClean: 'Nothing to report.',

  shellIrony:
    'Note: writing to your shell startup file is the same technique this tool watches for ' +
    '(vector V9). That is why it is one line pointing at a separate file, shown above in full, ' +
    'and removed exactly by `agent-guard uninstall`.',
} as const;
