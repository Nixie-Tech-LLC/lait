/**
 * Collapse a burst of re-read requests into one in-flight run plus one trailing run.
 *
 * The doorbell rings per commit, not per user action: a sync burst lands ten frames
 * in a couple hundred milliseconds, and each one asked for a fresh `board` read. The
 * `boardSeq` guard in `App` already stops the *answers* from landing out of order,
 * but the requests were all still sent — ten concurrent reads at one daemon, nine of
 * whose replies are discarded on arrival.
 *
 * Two things this deliberately is *not*:
 *
 * - **Not "await the in-flight run".** A read that started before a ring may have
 *   been served before the commit that rang it, so its result can be older than the
 *   news. The trailing run is what makes the answer newer than the question; drop it
 *   and this becomes a correctness bug that only shows under load, which is the
 *   worst kind. Hence exactly one trailing run, never zero.
 * - **Not a leading-edge throttle.** Callers absorbed into the trailing run get a
 *   promise that resolves when *that* run finishes, not immediately. `App` sequences
 *   `loadBoard(id).then(() => overlay.clearDoc(...))` — re-read first, then retire
 *   the guesses — and resolving early would clear predictions before the fresh rows
 *   land, flashing the stale server value for a frame. That flash is the whole thing
 *   the optimism exists to prevent.
 *
 * Latest args win: the trailing run reads the newest request, and the older ones it
 * absorbed are satisfied by it. That is only sound because every caller here wants
 * the same thing — "the current truth" — rather than a specific answer to their own
 * question.
 *
 * `fn` must own its failures (return, don't throw). A rejection is swallowed rather
 * than left to wedge the queue or surface as an unhandled rejection — but its
 * waiters are still released, because a caller blocked forever is worse than one
 * told nothing.
 */
export function coalesce<A extends unknown[]>(
  fn: (...args: A) => Promise<void>,
): (...args: A) => Promise<void> {
  let running = false;
  let queued: A | null = null;
  let waiters: Array<() => void> = [];

  const drain = async (args: A): Promise<void> => {
    running = true;
    try {
      await fn(...args);
    } catch {
      // `fn` owns its errors; a throw is a bug in it, not news for the callers.
    } finally {
      running = false;
      if (queued) {
        const nextArgs = queued;
        const release = waiters;
        queued = null;
        waiters = [];
        // No `await` between clearing `running` and re-entering `drain`, so no
        // caller can slip in and start a second run.
        void drain(nextArgs).then(() => {
          for (const w of release) w();
        });
      }
    }
  };

  return (...args: A): Promise<void> => {
    if (!running) return drain(args);
    queued = args;
    return new Promise<void>((resolve) => waiters.push(resolve));
  };
}
