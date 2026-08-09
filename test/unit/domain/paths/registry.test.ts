import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { SENSITIVE_PATHS } from '../../../../src/domain/paths/registry.js';
import { SensitivePathRegistry } from '../../../../src/domain/paths/SensitivePathRegistry.js';
import type { PathContext } from '../../../../src/domain/paths/PathContext.js';

const HOME = AbsolutePath.of('/Users/dev');
const WORKSPACE = AbsolutePath.of('/Users/dev/projects/app');
const WINDOWS_HOME = AbsolutePath.of(String.raw`C:\Users\Dev`);
const WINDOWS_WORKSPACE = AbsolutePath.of(String.raw`C:\Users\Dev\projects\app`);
const ctx = (platform: 'darwin' | 'linux' | 'win32' = 'darwin'): PathContext => ({
  home: HOME,
  workspace: WORKSPACE,
  platform,
});
const windowsCtx = (): PathContext => ({
  home: WINDOWS_HOME,
  workspace: WINDOWS_WORKSPACE,
  platform: 'win32',
});

const registry = SensitivePathRegistry.default();

describe('sensitive path registry (spec §6.4)', () => {
  it('is not empty', () => {
    expect(registry.all().length).toBeGreaterThan(20);
  });

  it('gives every entry a unique id', () => {
    const ids = registry.all().map((entry) => entry.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('gives every entry a rationale', () => {
    for (const entry of registry.all()) {
      expect(entry.rationale.length, `${entry.id} needs a rationale`).toBeGreaterThan(10);
    }
  });

  it('gives every entry at least one platform', () => {
    for (const entry of registry.all()) {
      expect(entry.platforms.length, `${entry.id} needs platforms`).toBeGreaterThan(0);
    }
  });

  it('exposes the raw data and the registry consistently', () => {
    expect(registry.all().length).toBe(SENSITIVE_PATHS.length);
  });

  it('covers every category', () => {
    const categories = new Set(registry.all().map((entry) => entry.category));
    expect([...categories].sort()).toEqual(['config', 'credential', 'history', 'persistence']);
  });

  it('makes every credential, persistence and history entry unwritable at runtime', () => {
    for (const entry of registry.all()) {
      if (entry.category === 'config') continue;
      expect(entry.writeTier.level, `${entry.id} must be tier 2 for writes`).toBe(2);
    }
  });

  it('makes every credential and history entry unreadable at runtime', () => {
    for (const entry of registry.all()) {
      if (entry.category !== 'credential' && entry.category !== 'history') continue;
      expect(entry.readTier.level, `${entry.id} must be tier 2 for reads`).toBe(2);
    }
  });

  it('keeps tier and disposition consistent: tier 2 always blocks', () => {
    for (const entry of registry.all()) {
      if (entry.readTier.level === 2) {
        expect(entry.onRead.name, `${entry.id} read`).toBe('block');
      }
      if (entry.writeTier.level === 2) {
        expect(entry.onWrite.name, `${entry.id} write`).toBe('block');
      }
    }
  });

  it('lets git work: ~/.gitconfig is readable at runtime but never writable', () => {
    const gitconfig = registry.byId('git-config');
    expect(gitconfig?.readTier.canBeGrantedAtRuntime).toBe(true);
    expect(gitconfig?.writeTier.canBeGrantedAtRuntime).toBe(false);
  });

  it('filters by platform', () => {
    const linux = registry.forPlatform('linux');
    expect(linux.length).toBeGreaterThan(0);
    expect(linux.every((entry) => entry.platforms.includes('linux'))).toBe(true);
    expect(linux.some((entry) => entry.id === 'macos-keychain')).toBe(false);
  });

  describe('coverage of the threat model', () => {
    it.each([
      ['~/.ssh/id_rsa', 'credential', 'darwin'],
      ['~/.ssh/authorized_keys', 'persistence', 'darwin'],
      ['~/.aws/credentials', 'credential', 'darwin'],
      ['~/.config/gcloud/credentials.db', 'credential', 'darwin'],
      ['~/.kube/config', 'credential', 'darwin'],
      ['~/.docker/config.json', 'credential', 'darwin'],
      ['~/.netrc', 'credential', 'darwin'],
      ['~/.npmrc', 'credential', 'darwin'],
      ['~/.pypirc', 'credential', 'darwin'],
      ['~/.config/gh/hosts.yml', 'credential', 'darwin'],
      ['~/Library/Keychains/login.keychain-db', 'credential', 'darwin'],
      ['~/.config/rclone/rclone.conf', 'credential', 'darwin'],
      ['~/.gnupg/private-keys-v1.d/key.key', 'credential', 'darwin'],
      ['~/.zshenv', 'persistence', 'darwin'],
      ['~/.zshrc', 'persistence', 'darwin'],
      ['~/.bashrc', 'persistence', 'darwin'],
      ['~/.profile', 'persistence', 'darwin'],
      ['~/.bash_profile', 'persistence', 'darwin'],
      ['~/.config/fish/config.fish', 'persistence', 'darwin'],
      ['~/.gitconfig', 'persistence', 'darwin'],
      ['~/Library/LaunchAgents/evil.plist', 'persistence', 'darwin'],
      ['~/.ssh/config', 'persistence', 'darwin'],
      ['~/.zsh_history', 'history', 'darwin'],
      ['~/.bash_history', 'history', 'darwin'],
      ['~/.psql_history', 'history', 'darwin'],
      ['~/.node_repl_history', 'history', 'darwin'],
      ['~/Library/Application Support/Google/Chrome/Default/Cookies', 'credential', 'darwin'],
      ['~/Library/Safari/History.db', 'credential', 'darwin'],
      ['~/.mozilla/firefox/x.default/logins.json', 'credential', 'darwin'],
      ['/private/var/at/tabs/dev', 'persistence', 'darwin'],
      // Linux-only surfaces have no macOS counterpart and must not be asserted there.
      ['~/.config/systemd/user/evil.service', 'persistence', 'linux'],
      ['~/.config/google-chrome/Default/Cookies', 'credential', 'linux'],
      ['/var/spool/cron/dev', 'persistence', 'linux'],
    ] as const)('classifies %s as %s on %s', (raw, category, platform) => {
      const path = AbsolutePath.fromUserPath(raw, HOME);
      const matches = registry.matching(path, ctx(platform));
      expect(matches.length, `${raw} is not covered by the registry`).toBeGreaterThan(0);
      expect(matches.map((entry) => entry.category)).toContain(category);
    });
  });

  describe('Windows home-relative coverage', () => {
    it.each([
      ['~/.ssh/id_ed25519', 'credential', 'ssh-keys'],
      [
        '~/AppData/Local/Google/Chrome/User Data/Default/Cookies',
        'credential',
        'chrome-profile-windows',
      ],
      [
        '~/AppData/Local/Microsoft/Edge/User Data/Default/Cookies',
        'credential',
        'edge-profile-windows',
      ],
      [
        '~/AppData/Roaming/Mozilla/Firefox/Profiles/default/logins.json',
        'credential',
        'firefox-profile-windows',
      ],
      [
        '~/Documents/PowerShell/Microsoft.PowerShell_profile.ps1',
        'persistence',
        'powershell-core-profile',
      ],
      [
        '~/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1',
        'persistence',
        'windows-powershell-profile',
      ],
      [
        '~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.cmd',
        'persistence',
        'windows-startup-folder',
      ],
      ['~/.agentkeeper/allowlist.json', 'persistence', 'agentkeeper-state'],
    ] as const)('classifies %s as %s', (raw, category, id) => {
      const path = AbsolutePath.fromUserPath(raw, WINDOWS_HOME);
      const matches = registry.matching(path, windowsCtx());
      expect(matches.map((entry) => entry.id), `${raw} is not covered`).toContain(id);
      expect(matches.map((entry) => entry.category)).toContain(category);
    });

    it('matches Windows home-relative paths case-insensitively', () => {
      const key = AbsolutePath.of(String.raw`c:\USERS\DEV\.SSH\ID_RSA`);
      expect(registry.matching(key, windowsCtx()).map((entry) => entry.id)).toContain('ssh-keys');
    });

    it('does not apply Windows-only browser paths on POSIX', () => {
      const chrome = AbsolutePath.of(
        '/Users/dev/AppData/Local/Google/Chrome/User Data/Default/Cookies',
      );
      expect(registry.matching(chrome, ctx('darwin'))).toEqual([]);
    });
  });

  describe('false positives on a normal workspace', () => {
    it.each([
      '/Users/dev/projects/app/src/index.ts',
      '/Users/dev/projects/app/package.json',
      '/Users/dev/projects/app/.env',
      '/Users/dev/projects/app/.env.local',
      '/Users/dev/projects/app/node_modules/left-pad/index.js',
      '/Users/dev/projects/app/.git/HEAD',
      '/Users/dev/projects/app/config/ssh/README.md',
      '/usr/local/bin/node',
      '/tmp/build-output.log',
    ])('does not flag %s', (raw) => {
      expect(registry.matching(AbsolutePath.of(raw), ctx())).toEqual([]);
    });
  });

  describe('.env outside the workspace', () => {
    it('is sensitive in another project', () => {
      const other = AbsolutePath.of('/Users/dev/projects/other/.env');
      expect(registry.matching(other, ctx()).length).toBeGreaterThan(0);
    });

    it('is not sensitive inside the current workspace', () => {
      const inside = AbsolutePath.of('/Users/dev/projects/app/.env');
      expect(registry.matching(inside, ctx())).toEqual([]);
    });
  });

  it('keeps macOS-only entries off Linux', () => {
    const keychain = AbsolutePath.fromUserPath('~/Library/Keychains/login.keychain-db', HOME);
    expect(registry.matching(keychain, ctx('darwin')).length).toBeGreaterThan(0);
    expect(registry.matching(keychain, ctx('linux'))).toEqual([]);
  });

  it('provides the shell startup files of every supported platform', () => {
    const ids = registry.all().map((entry) => entry.id);
    expect(ids).toContain('zsh-env');
    expect(ids).toContain('fish-config');
    expect(ids).toContain('systemd-user-units');
    expect(ids).toContain('launch-agents');
    expect(ids).toContain('powershell-core-profile');
    expect(ids).toContain('windows-powershell-profile');
  });
});
