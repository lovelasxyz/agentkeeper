import { posix, win32 } from 'node:path';

type PathFlavour = 'posix' | 'windows-drive' | 'windows-unc';

const WINDOWS_DRIVE_ABSOLUTE = /^[A-Za-z]:[\\/]/;
const WINDOWS_UNC = /^[\\/]{2}[^\\/]/;

/**
 * A normalised absolute filesystem path.
 *
 * Pure value object: it never touches the filesystem, so it can be reasoned
 * about — and tested — without any I/O. Every path that crosses a policy or
 * rule boundary is expressed with this type, which removes a whole class of
 * "was this string absolute, normalised, tilde-expanded?" defects.
 */
export class AbsolutePath {
  private constructor(
    readonly value: string,
    private readonly flavour: PathFlavour,
    private readonly root: string,
  ) {
    Object.freeze(this);
  }

  static of(raw: string): AbsolutePath {
    if (raw.includes('\0')) {
      throw new Error(`Path contains a NUL byte: ${JSON.stringify(raw)}`);
    }
    if (isWindowsDeviceNamespace(raw)) {
      throw new Error(`Windows device namespace paths are not supported: ${JSON.stringify(raw)}`);
    }
    if (WINDOWS_DRIVE_ABSOLUTE.test(raw)) {
      return AbsolutePath.fromWindows(raw, 'windows-drive');
    }
    if (WINDOWS_UNC.test(raw)) {
      return AbsolutePath.fromWindows(raw, 'windows-unc');
    }
    if (!raw.startsWith('/')) {
      throw new Error(`Path must be absolute: ${JSON.stringify(raw)}`);
    }
    return new AbsolutePath(posix.normalize(raw).replace(/\/+$/, '') || '/', 'posix', '/');
  }

  /**
   * Accepts what a human would type: `/etc/hosts`, `~`, `~/.ssh/id_rsa`.
   * A bare `~user` form is deliberately not supported — resolving another
   * account's home requires I/O and is outside this object's contract.
   */
  static fromUserPath(raw: string, home: AbsolutePath): AbsolutePath {
    if (raw === '~') return home;
    if (raw.startsWith('~/')) return home.join(raw.slice(2));
    if (home.isWindows && raw.startsWith('~\\')) return home.join(raw.slice(2));
    return AbsolutePath.of(raw);
  }

  get segments(): readonly string[] {
    if (this.value === this.root) return [];
    const offset = this.root.endsWith('/') ? this.root.length : this.root.length + 1;
    return this.value.slice(offset).split('/').filter(Boolean);
  }

  get basename(): string {
    return this.segments.at(-1) ?? '';
  }

  get parent(): AbsolutePath {
    const parentSegments = this.segments.slice(0, -1);
    if (parentSegments.length === 0) return AbsolutePath.of(this.root);
    const separator = this.root.endsWith('/') ? '' : '/';
    return AbsolutePath.of(`${this.root}${separator}${parentSegments.join('/')}`);
  }

  join(...parts: readonly string[]): AbsolutePath {
    if (this.isWindows) {
      const native = this.value.replace(/\//g, '\\');
      return AbsolutePath.of(win32.join(native, ...parts));
    }
    return AbsolutePath.of(posix.join(this.value, ...parts));
  }

  /** True when `other` is this path or lives underneath it. */
  contains(other: AbsolutePath): boolean {
    if (this.flavour !== other.flavour) return false;
    if (this.root !== other.root) return false;
    if (this.value === this.root) return true;
    return other.value === this.value || other.value.startsWith(`${this.value}/`);
  }

  equals(other: AbsolutePath): boolean {
    return this.flavour === other.flavour && this.value === other.value;
  }

  /** Renders the path back with `~` when it sits inside the given home. */
  toDisplay(home: AbsolutePath): string {
    if (this.equals(home)) return '~';
    return home.contains(this) ? `~${this.value.slice(home.value.length)}` : this.value;
  }

  toString(): string {
    return this.value;
  }

  toJSON(): string {
    return this.value;
  }

  private get isWindows(): boolean {
    return this.flavour !== 'posix';
  }

  private static fromWindows(
    raw: string,
    flavour: Exclude<PathFlavour, 'posix'>,
  ): AbsolutePath {
    const normalised = win32.normalize(raw);
    const nativeRoot = win32.parse(normalised).root;

    if (
      !win32.isAbsolute(normalised) ||
      (flavour === 'windows-unc' && !nativeRoot.startsWith('\\\\'))
    ) {
      throw new Error(`Path must be absolute: ${JSON.stringify(raw)}`);
    }

    const root = canonicalWindows(nativeRoot, flavour, true);
    const value = canonicalWindows(normalised, flavour, normalised === nativeRoot);
    return new AbsolutePath(value, flavour, root);
  }
}

/**
 * Windows paths are canonicalised to forward slashes and folded to lower case.
 * Windows' default filesystem semantics are case-insensitive; making that
 * property part of the value prevents policy matching from gaining a second,
 * case-sensitive interpretation. The drive letter stays upper-case for the
 * conventional `C:/...` display form.
 */
function canonicalWindows(
  raw: string,
  flavour: Exclude<PathFlavour, 'posix'>,
  isRoot: boolean,
): string {
  let value = raw.replace(/\\/g, '/').toLowerCase();
  if (!isRoot || flavour === 'windows-unc') value = value.replace(/\/+$/, '');
  if (flavour === 'windows-drive') value = `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
  return value;
}

function isWindowsDeviceNamespace(raw: string): boolean {
  const slash = raw.replace(/\\/g, '/');
  return /^\/\/[?.]\//.test(slash) || /^\/{1,2}\?\?\//.test(slash);
}
