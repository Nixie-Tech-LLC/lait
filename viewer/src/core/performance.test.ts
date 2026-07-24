import { describe, expect, it } from "vitest";

import { boundedTail, indexBy } from "./performance";

describe("large projection primitives", () => {
  it("indexes realistic large catalogs without losing canonical identity", () => {
    const rows = Array.from({ length: 10_000 }, (_, index) => ({
      reff: `iss_${index}`,
      title: `Issue ${index}`,
    }));
    const indexed = indexBy(rows, (row) => row.reff);

    expect(indexed.size).toBe(10_000);
    expect(indexed.get("iss_9999")).toBe(rows[9_999]);
  });

  it("mounts only the newest timeline window and expands deterministically", () => {
    const events = Array.from({ length: 1_000 }, (_, index) => index);

    expect(boundedTail(events, 40)).toEqual(events.slice(960));
    expect(boundedTail(events, 80)).toEqual(events.slice(920));
    expect(boundedTail(events, 2_000)).toEqual(events);
  });
});
