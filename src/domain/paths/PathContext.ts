import type { AbsolutePath } from '../value-objects/AbsolutePath.js';
import type { Platform } from '../value-objects/Platform.js';

/**
 * Everything the domain needs to decide what a path *means*, supplied by the
 * caller rather than read from the environment. Keeps path reasoning pure and
 * lets a test place a fake home anywhere.
 */
export interface PathContext {
  readonly home: AbsolutePath;
  readonly workspace: AbsolutePath;
  readonly platform: Platform;
}
