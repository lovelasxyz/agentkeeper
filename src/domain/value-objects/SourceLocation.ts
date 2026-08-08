/** Where inside an artifact a finding sits, so the user can jump straight to it. */
export class SourceLocation {
  private constructor(
    readonly line: number,
    readonly excerpt: string | null,
  ) {
    Object.freeze(this);
  }

  static atLine(line: number, excerpt: string | null = null): SourceLocation {
    if (!Number.isInteger(line) || line < 1) {
      throw new Error(`Line numbers start at 1, got ${JSON.stringify(line)}`);
    }
    return new SourceLocation(line, excerpt === null ? null : truncate(excerpt.trim()));
  }

  /** Finds the first line matching a needle. Rules use it to point at real text. */
  static firstMatch(content: string, needle: string | RegExp): SourceLocation | null {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] as string;
      const hit = typeof needle === 'string' ? line.includes(needle) : needle.test(line);
      if (hit) return SourceLocation.atLine(index + 1, line);
    }
    return null;
  }

  toString(): string {
    return this.excerpt === null ? `line ${this.line}` : `line ${this.line}: ${this.excerpt}`;
  }
}

function truncate(text: string): string {
  return text.length <= 120 ? text : `${text.slice(0, 117)}...`;
}
