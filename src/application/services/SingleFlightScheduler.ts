export type ScheduledTask = () => Promise<void>;
export type ScheduledTaskErrorHandler = (error: Error) => Promise<void>;

/**
 * Serialises an event-driven job without dropping an event that arrives while
 * the job is running. A burst is represented by one dirty rerun: comparisons
 * never overlap, but the final filesystem state is always observed.
 */
export class SingleFlightScheduler {
  private dirty = false;
  private inFlight: Promise<void> | null = null;

  constructor(
    private readonly task: ScheduledTask,
    private readonly onError: ScheduledTaskErrorHandler = async () => {},
  ) {}

  request(): Promise<void> {
    this.dirty = true;
    this.inFlight ??= this.drain().finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  get active(): boolean {
    return this.inFlight !== null;
  }

  private async drain(): Promise<void> {
    while (this.dirty) {
      this.dirty = false;
      try {
        await this.task();
      } catch (cause) {
        const error = cause instanceof Error ? cause : new Error(String(cause));
        try {
          await this.onError(error);
        } catch {
          // A resident scheduler must never create an unhandled rejection from
          // a best-effort error sink. The next filesystem event remains usable.
        }
      }
    }
  }
}
