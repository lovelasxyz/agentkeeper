/** One CLI verb. Kept tiny so the router stays a lookup, not a switch. */
export interface Command {
  readonly name: string;
  readonly usage: string;
  readonly summary: string;
  execute(args: readonly string[]): Promise<number>;
}

/** Minimal flag parsing: `--flag`, `--key value`, `--key=value`, and positionals. */
export class Flags {
  private constructor(
    private readonly values: ReadonlyMap<string, string | true>,
    readonly positional: readonly string[],
  ) {}

  static parse(args: readonly string[]): Flags {
    const values = new Map<string, string | true>();
    const positional: string[] = [];

    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index] as string;
      if (!arg.startsWith('--')) {
        positional.push(arg);
        continue;
      }

      const [name, inline] = splitOnce(arg.slice(2), '=');
      if (inline !== null) {
        values.set(name, inline);
        continue;
      }
      const next = args[index + 1];
      if (next !== undefined && !next.startsWith('--')) {
        values.set(name, next);
        index += 1;
        continue;
      }
      values.set(name, true);
    }
    return new Flags(values, positional);
  }

  has(name: string): boolean {
    return this.values.has(name);
  }

  value(name: string): string | null {
    const found = this.values.get(name);
    return typeof found === 'string' ? found : null;
  }
}

function splitOnce(text: string, separator: string): [string, string | null] {
  const index = text.indexOf(separator);
  return index === -1 ? [text, null] : [text.slice(0, index), text.slice(index + 1)];
}
