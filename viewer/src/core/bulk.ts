export interface BulkFailure<T> {
  item: T;
  message: string;
}

export interface BulkResult<T> {
  successes: T[];
  failures: BulkFailure<T>[];
}

export interface BulkProgress {
  done: number;
  total: number;
  pending: boolean;
  successes: string[];
  failures: Array<{ reff: string; label: string; message: string }>;
}

/** Run independent issue mutations with a small, measured concurrency ceiling. */
export async function runBounded<T>(
  items: readonly T[],
  task: (item: T) => Promise<unknown>,
  concurrency: number,
  onProgress?: (done: number, total: number) => void,
): Promise<BulkResult<T>> {
  const successes: Array<{ index: number; item: T }> = [];
  const failures: Array<{ index: number; item: T; message: string }> = [];
  let cursor = 0;
  let done = 0;

  const worker = async () => {
    while (cursor < items.length) {
      const index = cursor++;
      const item = items[index]!;
      try {
        await task(item);
        successes.push({ index, item });
      } catch (error) {
        failures.push({
          index,
          item,
          message: error instanceof Error ? error.message : String(error),
        });
      } finally {
        done += 1;
        onProgress?.(done, items.length);
      }
    }
  };

  const workers = Array.from(
    { length: Math.min(Math.max(1, concurrency), items.length) },
    () => worker(),
  );
  await Promise.all(workers);

  return {
    successes: successes.sort((a, b) => a.index - b.index).map(({ item }) => item),
    failures: failures
      .sort((a, b) => a.index - b.index)
      .map(({ item, message }) => ({ item, message })),
  };
}
