/**
 * Provider credentials that a supported agent may genuinely need in order to
 * authenticate. They are deliberately enumerated: a suffix such as `_TOKEN`
 * or `_API_KEY` is not evidence that a secret is safe to hand to an agent.
 */
export const PROVIDER_API_KEYS = Object.freeze([
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'GEMINI_API_KEY',
  'GOOGLE_API_KEY',
  'OPENROUTER_API_KEY',
] as const);

export type ProviderApiKey = (typeof PROVIDER_API_KEYS)[number];

/**
 * Ambient variables with data, rather than authority, that interactive tools
 * need to behave normally. Everything else is denied by default.
 *
 * Names are normalised for Windows, whose environment is case-insensitive.
 * Values are intentionally not interpreted here: the launcher owns cwd and
 * filesystem/network enforcement still applies to every path in a value.
 */
const SAFE_VARIABLE_NAMES = Object.freeze([
  // Command lookup. Identity, cwd and temporary paths are launcher-owned and
  // therefore intentionally absent from this ambient allowlist.
  'PATH',
  'SHELL',
  // Terminal behaviour. No editor/pager variables: those can execute commands.
  'TERM',
  'COLORTERM',
  'TERM_PROGRAM',
  'TERM_PROGRAM_VERSION',
  'COLUMNS',
  'LINES',
  'NO_COLOR',
  'FORCE_COLOR',
  'CLICOLOR',
  'CLICOLOR_FORCE',
  // Locale and deterministic time handling.
  'LANG',
  'LANGUAGE',
  'LC_ALL',
  'LC_CTYPE',
  'LC_COLLATE',
  'LC_MESSAGES',
  'LC_MONETARY',
  'LC_NUMERIC',
  'LC_TIME',
  'LC_PAPER',
  'LC_NAME',
  'LC_ADDRESS',
  'LC_TELEPHONE',
  'LC_MEASUREMENT',
  'LC_IDENTIFICATION',
  'TZ',
  // Common non-secret execution mode flag.
  'CI',
  // Non-path Windows process metadata. Path-bearing Windows variables are
  // launcher-owned for the same reason as HOME and TMPDIR on POSIX.
  'OS',
  'PROCESSOR_ARCHITECTURE',
  'PROCESSOR_IDENTIFIER',
  'NUMBER_OF_PROCESSORS',
] as const);

const KNOWN_PROVIDER_KEYS: ReadonlySet<string> = new Set(PROVIDER_API_KEYS);

/**
 * Pure allowlist for the environment crossing into an agent process.
 *
 * The policy is command-scoped: Claude receives the Anthropic credential, not
 * every provider credential present in the user's shell. Multi-provider agents
 * are the only adapters that receive the complete explicit provider set.
 */
export class EnvironmentPolicy {
  readonly providerApiKeys: readonly ProviderApiKey[];

  private constructor(providerApiKeys: readonly ProviderApiKey[]) {
    this.providerApiKeys = Object.freeze([...new Set(providerApiKeys)].sort());
    Object.freeze(this);
  }

  static strict(providerApiKeys: readonly ProviderApiKey[] = []): EnvironmentPolicy {
    for (const name of providerApiKeys) {
      if (!KNOWN_PROVIDER_KEYS.has(name)) {
        throw new Error(`Unknown provider environment credential: ${JSON.stringify(name)}`);
      }
    }
    return new EnvironmentPolicy(providerApiKeys);
  }

  static forExecutable(executable: string): EnvironmentPolicy {
    switch (executableName(executable)) {
      case 'claude':
      case 'claude-code':
        return EnvironmentPolicy.strict(['ANTHROPIC_API_KEY']);
      case 'codex':
        return EnvironmentPolicy.strict(['OPENAI_API_KEY']);
      case 'gemini':
        return EnvironmentPolicy.strict(['GEMINI_API_KEY', 'GOOGLE_API_KEY']);
      case 'opencode':
      case 'aider':
        return EnvironmentPolicy.strict(PROVIDER_API_KEYS);
      default:
        return EnvironmentPolicy.strict();
    }
  }

  allows(name: string): boolean {
    const normalized = name.toUpperCase();

    // These are launcher-owned even if a future safe-name list grows broad.
    if (normalized.startsWith('AGENTKEEPER_')) return false;
    if (SAFE_VARIABLE_NAMES.includes(normalized as (typeof SAFE_VARIABLE_NAMES)[number])) {
      return true;
    }
    // Provider SDKs use the canonical uppercase spelling on POSIX. Requiring
    // it avoids preserving lookalike variables that no supported agent needs.
    return name === normalized && this.providerApiKeys.includes(name as ProviderApiKey);
  }
}

function executableName(executable: string): string {
  // String#split always returns at least one element, including for "".
  const basename = executable.replace(/\\/g, '/').split('/').at(-1)!.toLowerCase();
  return basename.replace(/\.(exe|cmd|bat|ps1)$/i, '');
}
