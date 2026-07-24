import { describe, expect, it } from "vitest";

import { runBounded } from "./bulk";

describe("bounded bulk mutations", () => {
  it("continues after partial failures and preserves input order in its report", async () => {
    const progress: number[] = [];
    const result = await runBounded(
      ["A", "B", "C", "D"],
      async (item) => {
        if (item === "B" || item === "D") throw new Error(`${item} refused`);
      },
      2,
      (done) => progress.push(done),
    );

    expect(result.successes).toEqual(["A", "C"]);
    expect(result.failures).toEqual([
      { item: "B", message: "B refused" },
      { item: "D", message: "D refused" },
    ]);
    expect(progress).toHaveLength(4);
    expect(progress.at(-1)).toBe(4);
  });

  it("never exceeds the requested concurrency", async () => {
    let active = 0;
    let peak = 0;
    await runBounded(
      [1, 2, 3, 4, 5, 6],
      async () => {
        active += 1;
        peak = Math.max(peak, active);
        await Promise.resolve();
        active -= 1;
      },
      3,
    );
    expect(peak).toBe(3);
  });
});
