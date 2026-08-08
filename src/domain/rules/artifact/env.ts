import { ArtifactRule } from './ArtifactRule.js';
import { Disposition } from '../../value-objects/Disposition.js';
import { RuleId } from '../../value-objects/RuleId.js';
import { Severity } from '../../value-objects/Severity.js';
import { SourceLocation } from '../../value-objects/SourceLocation.js';
import type { Artifact } from '../../entities/Artifact.js';
import type { Finding } from '../../entities/Finding.js';

const MCP_FILES = ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json'];

/**
 * Endpoint overrides. Redirecting the base URL sends the conversation — and the
 * key with it — to somebody else's server (CVE-2026-21852).
 */
const ENDPOINT_VARIABLES = [
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_API_URL',
  'OPENAI_BASE_URL',
  'OPENAI_API_BASE',
  'GOOGLE_GEMINI_BASE_URL',
  'GEMINI_API_BASE',
  'AWS_ENDPOINT_URL_BEDROCK',
];

/** V4 — CVE-2026-12537: a prepared `.gemini/.env` led to OS command injection. */
export class GeminiEnvRule extends ArtifactRule {
  readonly id = RuleId.of('AG-E001');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Repository ships a .gemini/.env';
  readonly remediation =
    'CVE-2026-12537: Gemini CLI before 0.39.1 executed content from this file. Upgrade, and ' +
    'delete the committed file — an environment file belongs on your machine, not in a repo.';

  protected readonly paths = ['.gemini/.env', '.gemini/**/.env'];

  inspect(artifact: Artifact): readonly Finding[] {
    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} is loaded by Gemini CLI when it starts in this directory.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: null,
      }),
    ];
  }
}

/** V8 — an MCP server is an arbitrary command the agent launches at start-up. */
export class McpServerRule extends ArtifactRule {
  readonly id = RuleId.of('AG-E002');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Repository defines an MCP server';
  readonly remediation =
    'The agent launches this command when the session opens. Read the command and its arguments; ' +
    'the decision is remembered per file content, so an edited definition asks again.';

  protected readonly paths = MCP_FILES;

  inspect(artifact: Artifact): readonly Finding[] {
    const servers = ArtifactRule.at(artifact.json(), 'mcpServers');
    if (!ArtifactRule.isRecord(servers)) return this.none();

    return Object.entries(servers).map(([name, definition]) =>
      this.finding({
        title: this.title,
        detail:
          `${artifact.relativePath} launches "${name}": ` +
          `${String(ArtifactRule.at(definition, 'command') ?? 'unknown command')} ` +
          `${describeArgs(ArtifactRule.at(definition, 'args'))}`.trim(),
        subject: `${artifact.relativePath}#${name}`,
        contentHash: artifact.hash,
        location: SourceLocation.firstMatch(artifact.content, `"${name}"`),
      }),
    );
  }
}

/** V7 — an unpinned `npx`/`uvx` server is a rug-pull waiting for the next install. */
export class UnpinnedMcpServerRule extends ArtifactRule {
  readonly id = RuleId.of('AG-E003');
  readonly severity = Severity.MEDIUM;
  readonly defaultDisposition = Disposition.OBSERVE;
  readonly title = 'MCP server is fetched without a pinned version';
  readonly remediation =
    'Pin the version (`package@1.2.3`). Without a pin, the code that runs on your machine can ' +
    'change under you at any time, and the approval you gave once no longer means anything.';

  protected readonly paths = MCP_FILES;

  inspect(artifact: Artifact): readonly Finding[] {
    const servers = ArtifactRule.at(artifact.json(), 'mcpServers');
    if (!ArtifactRule.isRecord(servers)) return this.none();

    const findings: Finding[] = [];
    for (const [name, definition] of Object.entries(servers)) {
      const command = ArtifactRule.at(definition, 'command');
      if (command !== 'npx' && command !== 'uvx' && command !== 'pnpx') continue;

      const args = ArtifactRule.at(definition, 'args');
      // Only the first non-flag argument is the package specifier; everything
      // after it belongs to the server being launched. Treating those as
      // package names reports `npx -y server@1.0.0 ./data` as unpinned, which
      // is a question asked about a correctly pinned server.
      const specifier = (Array.isArray(args) ? args : []).find(
        (arg): arg is string => typeof arg === 'string' && !arg.startsWith('-'),
      );
      if (specifier === undefined || isPinned(specifier)) continue;

      findings.push(
        this.finding({
          title: this.title,
          detail: `"${name}" runs ${String(command)} ${specifier} with no version pin.`,
          subject: `${artifact.relativePath}#${name}`,
          contentHash: artifact.hash,
          location: SourceLocation.firstMatch(artifact.content, `"${name}"`),
        }),
      );
    }
    return findings;
  }
}

/** V4 — the endpoint override that leaks the key before trust is ever confirmed. */
export class EndpointOverrideRule extends ArtifactRule {
  readonly id = RuleId.of('AG-E004');
  readonly severity = Severity.CRITICAL;
  readonly defaultDisposition = Disposition.BLOCK;
  readonly title = 'Repository redirects the model endpoint';
  readonly remediation =
    'CVE-2026-21852: a repository that sets the base URL routes your traffic — and your API key — ' +
    'through a server it chose. There is no legitimate reason for a checked-in file to do this.';

  protected readonly paths = [
    '.env',
    '.env.*',
    '.envrc',
    '.gemini/.env',
    '.claude/settings.json',
    '.claude/settings.local.json',
    '.vscode/settings.json',
    '.cursor/environment.json',
    'mise.toml',
    '.tool-versions',
  ];

  inspect(artifact: Artifact): readonly Finding[] {
    const hit = ENDPOINT_VARIABLES.find((variable) => artifact.content.includes(variable));
    if (hit === undefined) return this.none();

    return [
      this.finding({
        title: this.title,
        detail: `${artifact.relativePath} sets ${hit}, redirecting where your requests and key go.`,
        subject: artifact.relativePath,
        contentHash: artifact.hash,
        location: SourceLocation.firstMatch(artifact.content, hit),
      }),
    ];
  }
}

const AUTO_APPROVE_KEYS = ['enableAllProjectMcpServers', 'enabledMcpjsonServers'];

/** V8 — repository-level flags that approve MCP servers on the user's behalf. */
export class McpAutoApprovalRule extends ArtifactRule {
  readonly id = RuleId.of('AG-E005');
  readonly severity = Severity.HIGH;
  readonly defaultDisposition = Disposition.ASK;
  readonly title = 'Repository pre-approves its own MCP servers';
  readonly remediation =
    'This flag removes the prompt that would otherwise let you see what the server runs. ' +
    'Approving servers is a decision for your user settings, not for a cloned repository.';

  protected readonly paths = ['.claude/settings.json', '.claude/settings.local.json'];

  inspect(artifact: Artifact): readonly Finding[] {
    const document = artifact.json();
    if (!ArtifactRule.isRecord(document)) return this.none();

    const findings: Finding[] = [];
    for (const key of AUTO_APPROVE_KEYS) {
      const value = document[key];
      const enabled = value === true || (Array.isArray(value) && value.length > 0);
      if (!enabled) continue;

      findings.push(
        this.finding({
          title: this.title,
          detail: `${artifact.relativePath} sets ${key}, approving MCP servers without asking.`,
          subject: artifact.relativePath,
          contentHash: artifact.hash,
          location: SourceLocation.firstMatch(artifact.content, key),
        }),
      );
    }
    return findings;
  }
}

function describeArgs(args: unknown): string {
  return Array.isArray(args) ? args.map(String).join(' ') : '';
}

/** `pkg@1.2.3` counts; `pkg`, `pkg@latest` and `@scope/pkg` do not. */
function isPinned(specifier: string): boolean {
  const at = specifier.lastIndexOf('@');
  if (at <= 0) return false;
  return /^\d/.test(specifier.slice(at + 1));
}
