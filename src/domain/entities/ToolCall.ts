import { AbsolutePath } from '../value-objects/AbsolutePath.js';
import { ShellCommand } from '../value-objects/ShellCommand.js';
import type { PathContext } from '../paths/PathContext.js';
import type { Access } from '../paths/SensitivePath.js';

export interface ToolCallProps {
  readonly tool: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly context: PathContext;
}

/** Keys agents use for the file a tool acts on. */
const PATH_KEYS = ['file_path', 'path', 'filePath', 'notebook_path', 'target_file'];
const READ_TOOLS = ['Read', 'Grep', 'Glob', 'NotebookRead', 'LS'];
const WRITE_TOOLS = ['Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'str_replace_editor'];

/**
 * A tool invocation the agent is about to make, as seen by the PreToolUse hook.
 *
 * Normalises the differences between agents and tools — `file_path` here,
 * `path` there, a shell string somewhere else — so a rule never has to know
 * which harness it is running under.
 */
export class ToolCall {
  readonly tool: string;
  readonly input: Readonly<Record<string, unknown>>;
  readonly context: PathContext;

  constructor(props: ToolCallProps) {
    this.tool = props.tool;
    this.input = props.input;
    this.context = props.context;
    Object.freeze(this);
  }

  get isShell(): boolean {
    return this.tool === 'Bash' || this.tool === 'Shell' || this.tool === 'run_terminal_cmd';
  }

  get isMcp(): boolean {
    return this.tool.startsWith('mcp__');
  }

  /** What the call does to the paths it names. Unknown tools are treated as writes. */
  get access(): Access {
    if (READ_TOOLS.includes(this.tool)) return 'read';
    if (WRITE_TOOLS.includes(this.tool)) return 'write';
    return 'write';
  }

  command(): ShellCommand | null {
    if (!this.isShell) return null;
    const raw = this.input['command'];
    return typeof raw === 'string' ? ShellCommand.parse(raw) : null;
  }

  /**
   * Every filesystem path this call names, resolved against the workspace.
   * Includes paths appearing as shell arguments, which is where most of the
   * interesting ones show up.
   */
  paths(): readonly AbsolutePath[] {
    const found = new Set<string>();

    for (const key of PATH_KEYS) {
      const value = this.input[key];
      if (typeof value === 'string') this.collect(value, found);
    }

    const command = this.command();
    if (command !== null) {
      for (const segment of command.segments) {
        for (const token of segment.tokens.slice(1)) {
          if (token.startsWith('-')) continue;
          if (!token.includes('/') && !token.startsWith('~')) continue;
          this.collect(token, found);
        }
      }
    }
    return [...found].map((value) => AbsolutePath.of(value));
  }

  private collect(raw: string, found: Set<string>): void {
    try {
      const expanded = raw.startsWith('~')
        ? AbsolutePath.fromUserPath(raw, this.context.home)
        : raw.startsWith('/')
          ? AbsolutePath.of(raw)
          : this.context.workspace.join(raw);
      found.add(expanded.value);
    } catch {
      // Not a usable path (a URL, a glob with no anchor). Nothing to check.
    }
  }

  toString(): string {
    const command = this.command();
    return command === null ? this.tool : `${this.tool}: ${command.raw}`;
  }
}
