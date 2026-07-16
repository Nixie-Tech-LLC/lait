import { describe, expect, it } from "vitest";

import { coalesce } from "./coalesce";

/** A run we can finish on command, so the races are scripted rather than timed. */
function gate() {
  let open!: () => void;
  const p = new Promise<void>((r) => (open = r));
  return { p, open };
}

describe("coalesce", () => {
  it("collapses a burst into the in-flight run plus one trailing run", async () => {
    const calls: string[] = [];
    const g = gate();
    const run = coalesce(async (id: string) => {
      calls.push(id);
      if (calls.length === 1) await g.p;
    });

    void run("a"); // starts immediately
    void run("b");
    void run("c");
    void run("d"); // three rings while "a" is in flight
    expect(calls).toEqual(["a"]);

    g.open();
    await new Promise((r) => setTimeout(r, 0));
    // Not ["a","b","c","d"] — and not ["a"] either. Latest args win.
    expect(calls).toEqual(["a", "d"]);
  });

  it("resolves absorbed callers only once a run that postdates them finishes", async () => {
    // The `.then(() => overlay.clearDoc(...))` ordering depends on this: resolve an
    // absorbed caller early and it retires its predictions against a read that was
    // served before the news it is reacting to.
    const g = gate();
    let finished = false;
    const run = coalesce(async () => {
      await g.p;
      finished = true;
    });

    void run();
    let resolved = false;
    void run().then(() => (resolved = true));

    await new Promise((r) => setTimeout(r, 0));
    expect(resolved).toBe(false); // still waiting on the first run, correctly

    g.open();
    await new Promise((r) => setTimeout(r, 0));
    expect(finished).toBe(true);
    expect(resolved).toBe(true);
  });

  it("starts a fresh run once idle rather than staying latched", async () => {
    const calls: string[] = [];
    const run = coalesce(async (id: string) => {
      calls.push(id);
    });
    await run("a");
    await run("b");
    expect(calls).toEqual(["a", "b"]);
  });

  it("releases waiters even when a run throws", async () => {
    // `fn` is supposed to own its errors. If one ever doesn't, the queue must not
    // wedge — a caller blocked forever is worse than one told nothing.
    const g = gate();
    let first = true;
    const run = coalesce(async () => {
      if (first) {
        first = false;
        await g.p;
        throw new Error("boom");
      }
    });

    void run();
    let resolved = false;
    void run().then(() => (resolved = true));

    g.open();
    await new Promise((r) => setTimeout(r, 0));
    expect(resolved).toBe(true);
  });
});
