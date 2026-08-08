/** Platforms the product reasons about. Matches Node's `process.platform` values. */
export type Platform = 'darwin' | 'linux' | 'win32';

export const PLATFORMS: readonly Platform[] = ['darwin', 'linux', 'win32'];

export const POSIX_PLATFORMS: readonly Platform[] = ['darwin', 'linux'];

export function isPlatform(value: string): value is Platform {
  return (PLATFORMS as readonly string[]).includes(value);
}
