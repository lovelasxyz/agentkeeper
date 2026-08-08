import { createInterface } from 'node:readline/promises';
import { spawn } from 'node:child_process';
import { homedir, tmpdir } from 'node:os';
import { AbsolutePath } from '../domain/value-objects/AbsolutePath.js';
import { isPlatform, type Platform } from '../domain/value-objects/Platform.js';
import type { Finding } from '../domain/entities/Finding.js';
import type {
  AnswerChoice,
  Clock,
  Environment,
  Logger,
  Notifier,
  Prompter,
} from '../application/ports/index.js';

export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }
}

/**
 * Everything read from the process environment, in one place.
 *
 * A single object rather than scattered `process.env` reads: a test can supply
 * a different home without touching global state, and there is exactly one
 * place to look when something resolves surprisingly.
 */
export class ProcessEnvironment implements Environment {
  readonly home: AbsolutePath;
  readonly cwd: AbsolutePath;
  readonly platform: Platform;
  readonly tempDir: AbsolutePath;
  readonly variables: Readonly<Record<string, string>>;

  constructor(env: NodeJS.ProcessEnv = process.env, cwd: string = process.cwd()) {
    this.home = AbsolutePath.of(env['HOME'] ?? homedir());
    this.cwd = AbsolutePath.of(cwd);
    this.platform = isPlatform(process.platform) ? process.platform : 'linux';
    this.tempDir = AbsolutePath.of(env['TMPDIR'] ?? tmpdir());
    this.variables = Object.freeze(
      Object.fromEntries(
        Object.entries(env).filter((entry): entry is [string, string] => entry[1] !== undefined),
      ),
    );
  }

  /**
   * Where the toolchain lives. Version managers put node under the home
   * directory, which the sandbox closes by default — without these the agent
   * cannot start the very runtime it is written in.
   */
  toolchainRoots(): readonly AbsolutePath[] {
    const candidates = [
      '.nvm',
      '.volta',
      '.fnm',
      '.asdf',
      '.local/share/mise',
      '.bun',
      '.deno',
      '.cargo',
      '.rustup',
      '.pyenv',
      '.rbenv',
      '.local/share/pnpm',
      '.npm',
      'Library/pnpm',
    ];
    const roots = candidates.map((relative) => this.home.join(relative));
    // The running interpreter itself, wherever it came from.
    roots.push(AbsolutePath.of(process.execPath).parent.parent);
    return roots;
  }
}

export class ConsoleLogger implements Logger {
  constructor(private readonly stream: NodeJS.WriteStream = process.stderr) {}

  info(message: string): void {
    this.stream.write(`${message}\n`);
  }

  warn(message: string): void {
    this.stream.write(`agent-guard: ${message}\n`);
  }

  error(message: string): void {
    this.stream.write(`agent-guard: ${message}\n`);
  }
}

/** Null Object for hooks and CI, where writing to stderr would corrupt output. */
export class SilentLogger implements Logger {
  info(): void {}
  warn(): void {}
  error(): void {}
}

/**
 * Asks on the terminal.
 *
 * Returns `null` whenever nobody can answer — no TTY, or a CI runner. A
 * question nobody sees must not become an implicit yes, so the caller treats
 * `null` as "not approved".
 */
export class TerminalPrompter implements Prompter {
  constructor(
    private readonly input: NodeJS.ReadStream = process.stdin,
    private readonly output: NodeJS.WriteStream = process.stderr,
  ) {}

  private get interactive(): boolean {
    return this.input.isTTY === true && process.env['CI'] === undefined;
  }

  async ask(finding: Finding): Promise<AnswerChoice | null> {
    if (!this.interactive) return null;

    this.output.write(
      `\n${finding.severity.name.toUpperCase()} ${finding.ruleId.toString()} — ${finding.title}\n` +
        `  ${finding.detail}\n` +
        `  ${finding.remediation}\n`,
    );

    const answer = await this.question('  [a]llow once  [f]orever  [d]eny  [D]eny forever > ');
    switch (answer.trim()) {
      case 'a':
        return 'allow-once';
      case 'f':
        return 'allow-forever';
      case 'D':
        return 'deny-forever';
      default:
        return 'deny';
    }
  }

  async confirm(question: string): Promise<boolean> {
    if (!this.interactive) return false;
    const answer = await this.question(`${question} [y/N] `);
    return /^y(es)?$/i.test(answer.trim());
  }

  private async question(prompt: string): Promise<string> {
    const rl = createInterface({ input: this.input, output: this.output });
    try {
      return await rl.question(prompt);
    } finally {
      rl.close();
    }
  }
}

/** Never approves anything. Used in CI and by the daemon. */
export class SilentPrompter implements Prompter {
  async ask(): Promise<AnswerChoice | null> {
    return null;
  }

  async confirm(): Promise<boolean> {
    return false;
  }
}

/**
 * Desktop notification, best effort.
 *
 * Failure is ignored on purpose: a notifier that cannot reach the desktop must
 * not take down the process that was trying to warn the user.
 */
export class DesktopNotifier implements Notifier {
  constructor(
    private readonly platform: Platform,
    private readonly fallback: Logger,
  ) {}

  async notify(finding: Finding): Promise<void> {
    const title = `agent-guard: ${finding.title}`;
    const body = finding.detail;
    this.fallback.warn(`${finding.ruleId.toString()} ${finding.subject} — ${body}`);

    try {
      if (this.platform === 'darwin') {
        await this.run('/usr/bin/osascript', [
          '-e',
          `display notification ${quote(body)} with title ${quote(title)}`,
        ]);
        return;
      }
      if (this.platform === 'linux') {
        await this.run('notify-send', [title, body]);
      }
    } catch {
      // The log line above already carried the message.
    }
  }

  private run(executable: string, args: readonly string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      const child = spawn(executable, [...args], { stdio: 'ignore' });
      child.once('error', reject);
      child.once('exit', () => resolve());
    });
  }
}

/** AppleScript string literal. Refuses rather than escapes, as with sandbox paths. */
function quote(text: string): string {
  return `"${text.replace(/[\\"]/g, '').replace(/[\n\r]+/g, ' ')}"`;
}
