import type { Clock, FileSystem } from '../../application/ports/index.js';
import type { PauseState, PauseStateReader } from '../../application/ports/PersistenceMonitor.js';
import type { AbsolutePath } from '../../domain/value-objects/AbsolutePath.js';

const MAX_PAUSE_BYTES = 4_096;

/** Strict reader for the notification-only pause lease written by `pause`. */
export class JsonPauseState implements PauseStateReader {
  private readonly path: AbsolutePath;

  constructor(
    private readonly files: FileSystem,
    stateDir: AbsolutePath,
    private readonly clock: Clock,
  ) {
    this.path = stateDir.join('pause.json');
  }

  async read(): Promise<PauseState> {
    const info = await this.files.stat(this.path);
    if (info !== null && (info.isDirectory || info.size > MAX_PAUSE_BYTES)) {
      return { status: 'invalid', until: null, reason: 'pause.json exceeds its bounded schema' };
    }
    const raw = await this.files.read(this.path);
    if (raw === null) return { status: 'inactive', until: null };

    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!isObject(parsed) || typeof parsed['until'] !== 'string') {
        return { status: 'invalid', until: null, reason: 'expected an ISO until timestamp' };
      }
      const until = new Date(parsed['until']);
      if (!Number.isFinite(until.getTime())) {
        return { status: 'invalid', until: null, reason: 'until is not a valid timestamp' };
      }
      return until > this.clock.now()
        ? { status: 'active', until }
        : { status: 'expired', until };
    } catch {
      // A corrupt file must not become an indefinite silence switch.
      return { status: 'invalid', until: null, reason: 'pause.json is not valid JSON' };
    }
  }
}

function isObject(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
