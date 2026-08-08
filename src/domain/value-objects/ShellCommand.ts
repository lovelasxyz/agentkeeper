/**
 * A shell command line, split into the pieces a rule needs to reason about.
 *
 * Not a shell parser and not trying to be one: it exists to answer "which
 * programs does this line invoke, with which arguments", well enough that a
 * rule is not written against a raw string with a regex. Anything relying on
 * this for a *security boundary* would be wrong — that is the sandbox's job.
 * These rules observe and warn inside a boundary that already holds.
 */
export class ShellCommand {
  private constructor(
    readonly raw: string,
    readonly segments: readonly ShellSegment[],
  ) {
    Object.freeze(this);
  }

  static parse(raw: string): ShellCommand {
    return new ShellCommand(
      raw,
      splitSegments(raw)
        .map((segment) => ShellSegment.of(segment))
        .filter((segment) => segment.tokens.length > 0),
    );
  }

  /** Every program name invoked anywhere in the line, `env`/`sudo` seen through. */
  programs(): readonly string[] {
    return this.segments.map((segment) => segment.program).filter((name): name is string => name !== null);
  }

  invokes(program: string): boolean {
    return this.programs().some((name) => name === program || name.endsWith(`/${program}`));
  }

  /** Segments that invoke the given program, so arguments can be inspected. */
  invocationsOf(program: string): readonly ShellSegment[] {
    return this.segments.filter(
      (segment) =>
        segment.program === program || segment.program?.endsWith(`/${program}`) === true,
    );
  }

  /** Environment assignments written as a prefix, e.g. `FOO=1 claude`. */
  assignments(): Readonly<Record<string, string>> {
    const result: Record<string, string> = {};
    for (const segment of this.segments) {
      Object.assign(result, segment.assignments);
    }
    return result;
  }
}

/** One command in a pipeline or list. */
export class ShellSegment {
  private constructor(
    readonly tokens: readonly string[],
    readonly assignments: Readonly<Record<string, string>>,
  ) {
    Object.freeze(this);
  }

  static of(raw: string): ShellSegment {
    const tokens = tokenize(raw);
    const assignments: Record<string, string> = {};
    let index = 0;

    while (index < tokens.length) {
      const token = tokens[index] as string;
      const assignment = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(token);
      if (assignment) {
        assignments[assignment[1] as string] = assignment[2] as string;
        index += 1;
        continue;
      }
      // `env` and `sudo` wrap the real command; look through them.
      if (token === 'env' || token === 'sudo' || token === '/usr/bin/env') {
        index += 1;
        continue;
      }
      break;
    }
    return new ShellSegment(tokens.slice(index), assignments);
  }

  get program(): string | null {
    return this.tokens[0] ?? null;
  }

  get args(): readonly string[] {
    return this.tokens.slice(1);
  }

  /** Sub-command of a tool like `git push` or `npm publish`. */
  get subcommand(): string | null {
    return this.args.find((arg) => !arg.startsWith('-')) ?? null;
  }

  hasFlag(...flags: readonly string[]): boolean {
    return this.args.some((arg) => flags.includes(arg));
  }

  toString(): string {
    return this.tokens.join(' ');
  }
}

/**
 * Splits on unquoted separators only.
 *
 * A plain `String.split` cuts `git commit -m "a; b"` in half and hands the
 * rules two commands that were never there — so the walk has to know about
 * quoting before it knows about separators.
 */
function splitSegments(raw: string): string[] {
  const segments: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index] as string;

    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === '\\' && quote !== "'") {
      current += char;
      escaped = true;
      continue;
    }
    if (quote !== null) {
      current += char;
      if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      current += char;
      quote = char;
      continue;
    }
    if (char === ';' || char === '\n' || char === '|' || char === '&') {
      segments.push(current);
      current = '';
      // `&&` and `||` are two characters; consume the second.
      if (raw[index + 1] === char) index += 1;
      continue;
    }
    current += char;
  }
  segments.push(current);
  return segments.filter((segment) => segment.trim().length > 0);
}

function tokenize(raw: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (const char of raw.trim()) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === '\\' && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote !== null) {
      if (char === quote) quote = null;
      else current += char;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current.length > 0) tokens.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  if (current.length > 0) tokens.push(current);
  return tokens;
}
