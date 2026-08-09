import { AbsolutePath } from '../../src/domain/value-objects/AbsolutePath.js';
import type {
  AnswerChoice,
  AuditEntry,
  AuditLog,
  Clock,
  Decision,
  DecisionStore,
  Environment,
  FileStat,
  FileSystem,
  ListOptions,
  Logger,
  Notifier,
  Prompter,
} from '../../src/application/ports/index.js';
import type { Finding } from '../../src/domain/entities/Finding.js';
import type { Platform } from '../../src/domain/value-objects/Platform.js';

/**
 * In-memory adapters.
 *
 * The use cases talk to ports, so their tests need no temporary directories, no
 * mocking library and no cleanup — which is the practical payoff of the layer
 * boundary rather than a claim about it.
 */
export class InMemoryFileSystem implements FileSystem {
  readonly files = new Map<string, string>();
  private readonly directories = new Set<string>(['/']);
  private temporarySequence = 0;

  async read(path: AbsolutePath): Promise<string | null> {
    return this.files.get(path.value) ?? null;
  }

  async write(path: AbsolutePath, content: string): Promise<void> {
    this.files.set(path.value, content);
    for (let dir = path.parent; dir.value !== '/'; dir = dir.parent) {
      this.directories.add(dir.value);
    }
  }

  async append(path: AbsolutePath, content: string): Promise<void> {
    this.files.set(path.value, `${this.files.get(path.value) ?? ''}${content}`);
  }

  async move(source: AbsolutePath, destination: AbsolutePath): Promise<void> {
    const content = this.files.get(source.value);
    if (content === undefined) throw new Error(`Missing source: ${source.value}`);
    await this.write(destination, content);
    this.files.delete(source.value);
  }

  async exists(path: AbsolutePath): Promise<boolean> {
    return this.files.has(path.value) || this.directories.has(path.value);
  }

  async stat(path: AbsolutePath): Promise<FileStat | null> {
    if (this.directories.has(path.value)) {
      return { isDirectory: true, size: 0, modifiedAt: new Date(0) };
    }
    const content = this.files.get(path.value);
    if (content === undefined) return null;
    return { isDirectory: false, size: content.length, modifiedAt: new Date(0) };
  }

  async makeDirectory(path: AbsolutePath): Promise<void> {
    this.directories.add(path.value);
  }

  async makeTemporaryDirectory(parent: AbsolutePath, prefix: string): Promise<AbsolutePath> {
    const path = parent.join(`${prefix}${++this.temporarySequence}`);
    this.directories.add(path.value);
    return path;
  }

  async remove(path: AbsolutePath): Promise<void> {
    this.files.delete(path.value);
    this.directories.delete(path.value);
    for (const key of [...this.files.keys()]) {
      if (key.startsWith(`${path.value}/`)) this.files.delete(key);
    }
  }

  async list(root: AbsolutePath, _options?: ListOptions): Promise<readonly AbsolutePath[]> {
    const found = [...this.files.keys()]
      .filter((key) => key.startsWith(`${root.value}/`))
      .map((key) => AbsolutePath.of(key))
      .filter((path) => _options?.includeFile?.(path) !== false);
    return _options?.maxEntries === undefined ? found : found.slice(0, _options.maxEntries);
  }

  realPath(path: AbsolutePath): AbsolutePath {
    return path;
  }
}

export class FixedClock implements Clock {
  constructor(private current = new Date('2026-08-08T10:00:00Z')) {}

  now(): Date {
    return this.current;
  }

  advance(milliseconds: number): void {
    this.current = new Date(this.current.getTime() + milliseconds);
  }
}

export class RecordingAudit implements AuditLog {
  readonly entries: AuditEntry[] = [];

  async append(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
  }

  async since(moment: Date): Promise<readonly AuditEntry[]> {
    return this.entries.filter((entry) => entry.at >= moment);
  }

  events(): string[] {
    return this.entries.map((entry) => entry.event);
  }
}

export class RecordingLogger implements Logger {
  readonly messages: string[] = [];

  info(message: string): void {
    this.messages.push(message);
  }
  warn(message: string): void {
    this.messages.push(message);
  }
  error(message: string): void {
    this.messages.push(message);
  }

  joined(): string {
    return this.messages.join('\n');
  }
}

export class RecordingNotifier implements Notifier {
  readonly findings: Finding[] = [];

  async notify(finding: Finding): Promise<void> {
    this.findings.push(finding);
  }
}

export class ScriptedPrompter implements Prompter {
  constructor(
    private readonly answer: AnswerChoice | null = null,
    private readonly confirmation = true,
  ) {}

  async ask(): Promise<AnswerChoice | null> {
    return this.answer;
  }

  async confirm(): Promise<boolean> {
    return this.confirmation;
  }
}

export class InMemoryDecisions implements DecisionStore {
  private readonly decisions = new Map<string, Decision>();

  async find(key: string): Promise<Decision | null> {
    return this.decisions.get(key) ?? null;
  }

  async record(decision: Decision): Promise<void> {
    this.decisions.set(decision.key, decision);
  }

  async recordMany(decisions: readonly Decision[]): Promise<void> {
    for (const decision of decisions) this.decisions.set(decision.key, decision);
  }

  async all(): Promise<readonly Decision[]> {
    return [...this.decisions.values()];
  }
}

export class FakeEnvironment implements Environment {
  constructor(
    readonly home: AbsolutePath,
    readonly cwd: AbsolutePath,
    readonly platform: Platform = 'darwin',
    readonly tempDir: AbsolutePath = AbsolutePath.of('/tmp'),
    readonly variables: Readonly<Record<string, string>> = {},
    readonly identityHome: AbsolutePath = home,
  ) {}

  toolchainRoots(): readonly AbsolutePath[] {
    return [this.identityHome.join('.nvm')];
  }
}
