/**
 * Maps independent asynchronous work with a fixed-size worker pool.
 *
 * The promise array contains at most `concurrency` workers, never one promise
 * per workspace entry. Results retain input order even when operations finish
 * out of order.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  operation: (item: T, index: number) => Promise<R>,
): Promise<readonly R[]> {
  if (!Number.isSafeInteger(concurrency) || concurrency < 1) {
    throw new Error(`Concurrency must be a positive integer: ${String(concurrency)}`);
  }
  if (items.length === 0) return [];

  const results = new Array<R>(items.length);
  let cursor = 0;

  const worker = async (): Promise<void> => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await operation(items[index] as T, index);
    }
  };

  const workerCount = Math.min(concurrency, items.length);
  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}
