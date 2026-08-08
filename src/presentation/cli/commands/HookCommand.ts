import { Container } from '../../../composition/Container.js';
import { ToolCall } from '../../../domain/entities/ToolCall.js';
import { AbsolutePath } from '../../../domain/value-objects/AbsolutePath.js';
import type { Command } from '../Command.js';

const READ_TIMEOUT_MS = 2_000;

/**
 * `agent-guard hook pretooluse` — entry point E3 (spec §5).
 *
 * Two properties matter more than features here.
 *
 * **Fail-open by default** (spec §12): a hook that breaks the agent when the
 * hook itself is broken gets uninstalled the same day, and then nothing is
 * watching at all. `strictMode` flips this for people who chose it.
 *
 * **Silence on stdout except the verdict**: the harness parses this stream.
 */
export class HookCommand implements Command {
  readonly name = 'hook';
  readonly usage = 'hook pretooluse';
  readonly summary = 'Internal: evaluate a tool call (registered by init)';

  async execute(args: readonly string[]): Promise<number> {
    if (args[0] !== 'pretooluse') {
      process.stderr.write('Usage: agent-guard hook pretooluse\n');
      return 1;
    }

    const container = new Container({ quiet: true, interactive: false });
    let strict = false;

    try {
      strict = (await container.config()).strictMode;

      const payload = parse(await readStdin());
      if (payload === null) return 0;

      const call = new ToolCall({
        tool: payload.tool_name,
        input: payload.tool_input,
        context: {
          home: container.files.realPath(container.environment.home),
          workspace: container.files.realPath(
            payload.cwd === undefined
              ? container.environment.cwd
              : AbsolutePath.of(payload.cwd),
          ),
          platform: container.environment.platform,
        },
      });

      const verdict = await (await container.evaluateToolCall()).execute(call);
      if (verdict.decision === 'allow') return 0;

      // `deny` and `ask` both stop the call here. There is no interactive
      // prompt in a hook — spec §4.5 is explicit that a refusal must not come
      // with an offer, and an unattended agent has nobody to ask anyway.
      process.stdout.write(
        `${JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason: verdict.reason,
          },
        })}\n`,
      );
      return 0;
    } catch (error) {
      if (strict) {
        process.stderr.write(`agent-guard: hook failed: ${(error as Error).message}\n`);
        return 1;
      }
      // Fail-open: an internal error must not become the agent's problem.
      return 0;
    }
  }
}

interface HookPayload {
  readonly tool_name: string;
  readonly tool_input: Readonly<Record<string, unknown>>;
  readonly cwd?: string;
}

function parse(raw: string): HookPayload | null {
  try {
    const parsed = JSON.parse(raw) as Partial<HookPayload>;
    if (typeof parsed.tool_name !== 'string') return null;
    return {
      tool_name: parsed.tool_name,
      tool_input:
        typeof parsed.tool_input === 'object' && parsed.tool_input !== null
          ? parsed.tool_input
          : {},
      ...(typeof parsed.cwd === 'string' ? { cwd: parsed.cwd } : {}),
    };
  } catch {
    // An unrecognised payload shape means a harness version we do not know.
    // Spec §17.5: degrade visibly rather than guess at the contract.
    return null;
  }
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => resolve(data), READ_TIMEOUT_MS);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.once('end', () => {
      clearTimeout(timer);
      resolve(data);
    });
    process.stdin.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}
