import { SensitivePath } from './SensitivePath.js';
import { POSIX_PLATFORMS, PLATFORMS } from '../value-objects/Platform.js';

const ALL = PLATFORMS;
const POSIX = POSIX_PLATFORMS;
const MAC = ['darwin'] as const;
const LINUX = ['linux'] as const;
const WINDOWS = ['win32'] as const;

/**
 * The single source of truth behind the B and P rule families and behind the
 * sandbox profile itself (spec §6.4). Rows, not code: adding a path must never
 * mean editing a rule.
 *
 * Every row carries a rationale because a registry nobody can audit is a
 * registry nobody trusts. Tier and disposition are implied by the category
 * constructors, so a weak credential row is unrepresentable rather than
 * merely tested against.
 */
export const SENSITIVE_PATHS: readonly SensitivePath[] = Object.freeze([

  SensitivePath.credential({
    id: 'ssh-keys',
    pattern: '~/.ssh/**',
    platforms: ALL,
    rationale:
      'Private keys grant access to every host and repository the user can reach.',
  }),

  SensitivePath.credential({
    id: 'aws-credentials',
    pattern: '~/.aws/**',
    platforms: ALL,
    rationale:
      'Long-lived cloud access keys; a leak is an account takeover.',
  }),

  SensitivePath.credential({
    id: 'gcloud-credentials',
    pattern: '~/.config/gcloud/**',
    platforms: POSIX,
    rationale:
      'Google Cloud refresh tokens and application default credentials.',
  }),

  SensitivePath.credential({
    id: 'kube-config',
    pattern: '~/.kube/**',
    platforms: ALL,
    rationale:
      'Cluster certificates and tokens, usually with administrative rights.',
  }),

  SensitivePath.credential({
    id: 'docker-config',
    pattern: '~/.docker/**',
    platforms: ALL,
    rationale:
      'Registry authentication tokens, and a daemon socket path on some setups.',
  }),

  SensitivePath.credential({
    id: 'netrc',
    pattern: '~/.netrc',
    platforms: POSIX,
    rationale:
      'Plaintext machine credentials used by curl, git and ftp clients.',
  }),

  SensitivePath.credential({
    id: 'npmrc',
    pattern: '~/.npmrc',
    platforms: ALL,
    rationale:
      'Publish tokens; also a registry override that redirects every install.',
  }),

  SensitivePath.credential({
    id: 'pypirc',
    pattern: '~/.pypirc',
    platforms: ALL,
    rationale:
      'PyPI upload tokens, enough to publish a package under the user name.',
  }),

  SensitivePath.credential({
    id: 'gh-hosts',
    pattern: '~/.config/gh/**',
    platforms: POSIX,
    rationale:
      'GitHub CLI OAuth tokens with repository and workflow scope.',
  }),

  SensitivePath.credential({
    id: 'rclone-config',
    pattern: '~/.config/rclone/**',
    platforms: POSIX,
    rationale:
      'Credentials for every configured remote storage backend.',
  }),

  SensitivePath.credential({
    id: 'macos-keychain',
    pattern: '~/Library/Keychains/**',
    platforms: MAC,
    rationale:
      "The user's credential store; everything they ever saved lives here.",
  }),

  SensitivePath.credential({
    // Outside the home directory, where the macOS profile still permits broad
    // reads. The file is world-readable by default, so nothing but this rule
    // keeps it from leaving with the agent.
    id: 'macos-system-keychain',
    pattern: '/Library/Keychains/**',
    platforms: MAC,
    rationale:
      'The machine-wide credential store: Wi-Fi and 802.1X secrets, and certificates whose private keys are guarded by a daemon that a stolen copy never has to ask.',
  }),

  SensitivePath.credential({
    id: 'macos-ssh-host-keys',
    pattern: '/private/etc/ssh/**',
    platforms: MAC,
    rationale:
      'Host private keys, present once Remote Login is enabled; they authenticate the machine itself.',
  }),

  SensitivePath.credential({
    id: 'macos-root-home',
    pattern: '/var/root/**',
    platforms: MAC,
    rationale:
      "The superuser's home: an agent running with elevation finds credentials and history there.",
  }),

  SensitivePath.credential({
    id: 'macos-local-account-db',
    pattern: '/private/var/db/dslocal/**',
    platforms: MAC,
    rationale:
      'The local account database; password hashes and account metadata for every user of the machine.',
  }),

  SensitivePath.credential({
    id: 'gnupg',
    pattern: '~/.gnupg/**',
    platforms: POSIX,
    rationale:
      'Signing and encryption private keys.',
  }),

  SensitivePath.credential({
    id: 'env-file-outside-workspace',
    pattern: '**/.env',
    platforms: ALL,
    outsideWorkspaceOnly: true,
    rationale:
      'Another project’s environment file is the fastest route to its secrets.',
  }),

  SensitivePath.credential({
    id: 'env-variant-outside-workspace',
    pattern: '**/.env.*',
    platforms: ALL,
    outsideWorkspaceOnly: true,
    rationale:
      'Environment overlays of neighbouring projects hold the same secrets.',
  }),

  SensitivePath.credential({
    id: 'chrome-profile-macos',
    pattern: '~/Library/Application Support/Google/Chrome/**',
    platforms: MAC,
    rationale:
      'Session cookies and saved passwords of every logged-in service.',
  }),

  SensitivePath.credential({
    id: 'chromium-profile-linux',
    pattern: '~/.config/google-chrome/**',
    platforms: LINUX,
    rationale:
      'Session cookies and saved passwords of every logged-in service.',
  }),

  SensitivePath.credential({
    id: 'safari-profile',
    pattern: '~/Library/Safari/**',
    platforms: MAC,
    rationale:
      'Browsing history and site data, including authenticated sessions.',
  }),

  SensitivePath.credential({
    id: 'firefox-profile',
    pattern: '~/.mozilla/firefox/**',
    platforms: POSIX,
    rationale:
      'logins.json and cookies.sqlite hold decryptable saved credentials.',
  }),

  SensitivePath.credential({
    id: 'chrome-profile-windows',
    pattern: '~/appdata/local/google/chrome/user data/**',
    platforms: WINDOWS,
    rationale:
      'Chrome cookies and saved sessions provide authenticated access to web services.',
  }),

  SensitivePath.credential({
    id: 'edge-profile-windows',
    pattern: '~/appdata/local/microsoft/edge/user data/**',
    platforms: WINDOWS,
    rationale:
      'Edge cookies and saved sessions provide authenticated access to web services.',
  }),

  SensitivePath.credential({
    id: 'firefox-profile-windows',
    pattern: '~/appdata/roaming/mozilla/firefox/**',
    platforms: WINDOWS,
    rationale:
      'Firefox profiles contain saved logins, cookies and authenticated sessions.',
  }),

  SensitivePath.persistence({
    id: 'zsh-env',
    pattern: '~/.zshenv',
    readTier: 2,
    onRead: 'block',
    platforms: POSIX,
    rationale:
      'Read by every zsh invocation including non-interactive ones: the best foothold on macOS.',
  }),

  SensitivePath.persistence({
    id: 'zsh-rc',
    pattern: '~/.zshrc',
    readTier: 2,
    onRead: 'block',
    platforms: POSIX,
    rationale:
      'Runs on every interactive shell; survives deletion of the repository.',
  }),

  SensitivePath.persistence({
    id: 'bash-rc',
    pattern: '~/.bashrc',
    readTier: 2,
    onRead: 'block',
    platforms: POSIX,
    rationale:
      'Runs on every interactive bash shell.',
  }),

  SensitivePath.persistence({
    id: 'bash-profile',
    pattern: '~/.bash_profile',
    readTier: 2,
    onRead: 'block',
    platforms: POSIX,
    rationale:
      'Runs on every bash login shell.',
  }),

  SensitivePath.persistence({
    id: 'sh-profile',
    pattern: '~/.profile',
    readTier: 2,
    onRead: 'block',
    platforms: POSIX,
    rationale:
      'Runs on login for every POSIX shell.',
  }),

  SensitivePath.persistence({
    id: 'fish-config',
    pattern: '~/.config/fish/**',
    readTier: 2,
    onRead: 'block',
    platforms: POSIX,
    rationale:
      'config.fish and conf.d run on every fish shell start.',
  }),

  SensitivePath.persistence({
    id: 'git-config',
    pattern: '~/.gitconfig',
    // Reading is what makes `git` usable at all — measured, not assumed: with
    // the file unreadable git refuses every command. Writing installs
    // core.hooksPath, which is vector V9, so it stays out of runtime reach.
    readTier: 1,
    onRead: 'observe',
    platforms: ALL,
    rationale:
      'core.hooksPath, credential.helper and shell aliases each execute code.',
  }),

  SensitivePath.persistence({
    id: 'git-config-xdg',
    pattern: '~/.config/git/**',
    readTier: 1,
    onRead: 'observe',
    platforms: POSIX,
    rationale:
      'XDG location of the same git configuration.',
  }),

  SensitivePath.persistence({
    id: 'ssh-authorized-keys',
    pattern: '~/.ssh/authorized_keys',
    readTier: 2,
    onRead: 'block',
    platforms: ALL,
    rationale:
      'Appending a key grants permanent remote access to the machine.',
  }),

  SensitivePath.persistence({
    id: 'ssh-client-config',
    pattern: '~/.ssh/config',
    readTier: 2,
    onRead: 'block',
    platforms: ALL,
    rationale:
      'ProxyCommand and LocalCommand execute on every outgoing connection.',
  }),

  SensitivePath.persistence({
    id: 'launch-agents',
    pattern: '~/Library/LaunchAgents/**',
    readTier: 2,
    onRead: 'block',
    platforms: MAC,
    rationale:
      'A plist here runs at every login without any further user action.',
  }),

  SensitivePath.persistence({
    id: 'systemd-user-units',
    pattern: '~/.config/systemd/user/**',
    readTier: 2,
    onRead: 'block',
    platforms: LINUX,
    rationale:
      'A user unit starts at login and restarts itself on failure.',
  }),

  SensitivePath.persistence({
    id: 'powershell-core-profile',
    pattern: '~/documents/powershell/**',
    readTier: 2,
    onRead: 'block',
    platforms: WINDOWS,
    rationale:
      'PowerShell profile scripts execute whenever a PowerShell session starts.',
  }),

  SensitivePath.persistence({
    id: 'windows-powershell-profile',
    pattern: '~/documents/windowspowershell/**',
    readTier: 2,
    onRead: 'block',
    platforms: WINDOWS,
    rationale:
      'Windows PowerShell profile scripts execute whenever a legacy session starts.',
  }),

  SensitivePath.persistence({
    id: 'windows-startup-folder',
    pattern: '~/appdata/roaming/microsoft/windows/start menu/programs/startup/**',
    readTier: 2,
    onRead: 'block',
    platforms: WINDOWS,
    rationale:
      'Programs placed in the per-user Startup folder execute at every login.',
  }),

  SensitivePath.persistence({
    id: 'crontab-macos',
    pattern: '/private/var/at/tabs/**',
    readTier: 2,
    onRead: 'block',
    platforms: MAC,
    rationale:
      'Scheduled execution that outlives the session.',
  }),

  SensitivePath.persistence({
    id: 'crontab-linux',
    pattern: '/var/spool/cron/**',
    readTier: 2,
    onRead: 'block',
    platforms: LINUX,
    rationale:
      'Scheduled execution that outlives the session.',
  }),

  SensitivePath.history({
    id: 'zsh-history',
    pattern: '~/.zsh_history',
    platforms: POSIX,
    rationale:
      'Command lines regularly contain tokens pasted as arguments.',
  }),

  SensitivePath.history({
    id: 'bash-history',
    pattern: '~/.bash_history',
    platforms: POSIX,
    rationale:
      'Command lines regularly contain tokens pasted as arguments.',
  }),

  SensitivePath.history({
    id: 'psql-history',
    pattern: '~/.psql_history',
    platforms: POSIX,
    rationale:
      'Database queries with embedded connection strings and data.',
  }),

  SensitivePath.history({
    id: 'node-repl-history',
    pattern: '~/.node_repl_history',
    platforms: ALL,
    rationale:
      'REPL sessions frequently contain pasted keys.',
  }),

  SensitivePath.persistence({
    id: 'claude-settings',
    pattern: '~/.claude/settings*.json',
    readTier: 1,
    onRead: 'observe',
    platforms: ALL,
    rationale:
      'SessionStart and PreToolUse hooks here run on the next agent start.',
  }),

  SensitivePath.persistence({
    id: 'claude-config',
    pattern: '~/.claude.json',
    readTier: 1,
    onRead: 'observe',
    platforms: ALL,
    rationale:
      'Global agent configuration, including approved MCP servers.',
  }),

  SensitivePath.persistence({
    id: 'gemini-settings',
    pattern: '~/.gemini/settings.json',
    readTier: 1,
    onRead: 'observe',
    platforms: ALL,
    rationale:
      'Global agent configuration, including tool and MCP permissions.',
  }),

  SensitivePath.persistence({
    id: 'cursor-mcp',
    pattern: '~/.cursor/mcp.json',
    readTier: 1,
    onRead: 'observe',
    platforms: ALL,
    rationale:
      'MCP server definitions execute an arbitrary command at session start.',
  }),

  SensitivePath.persistence({
    id: 'agentkeeper-state',
    pattern: '~/.agentkeeper/**',
    readTier: 1,
    onRead: 'observe',
    platforms: ALL,
    rationale:
      'Self-protection: an agent that can edit its own allowlist has none.',
  }),

  SensitivePath.configuration({
    id: 'xdg-tool-config',
    pattern: '~/.config/**',
    readTier: 1,
    writeTier: 1,
    onRead: 'observe',
    onWrite: 'observe',
    platforms: POSIX,
    rationale:
      'Editor and tool settings: useful to the agent, cheap to grant, no secrets by itself.',
  }),

]);
