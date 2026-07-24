import { describe, expect, it, vi } from "vitest";
import { WorldViewStore } from "./worldViewStore";

const deferred = <T>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
};

describe("WorldViewStore", () => {
  it("deduplicates concurrent reads and keeps snapshots stable", async () => {
    const store = new WorldViewStore();
    const pending = deferred<number>();
    const loader = vi.fn(() => pending.promise);
    const one = store.ensure("thing", loader);
    const two = store.ensure("thing", loader);
    expect(one).toBe(two);
    expect(loader).toHaveBeenCalledTimes(1);
    expect(store.read("thing")).toBe(store.read("thing"));
    pending.resolve(7);
    await one;
    expect(store.read<number>("thing")).toMatchObject({ state: "ready", data: 7 });
  });

  it("rejects stale responses after invalidation", async () => {
    const store = new WorldViewStore();
    const old = deferred<string>();
    const fresh = deferred<string>();
    void store.ensure("thing", () => old.promise);
    store.invalidate("thing");
    void store.ensure("thing", () => fresh.promise);
    fresh.resolve("new");
    await fresh.promise;
    old.resolve("old");
    await old.promise;
    await Promise.resolve();
    expect(store.read<string>("thing").data).toBe("new");
  });

  it("retains prior data throughout refresh and failure", async () => {
    const store = new WorldViewStore();
    store.set("thing", "known");
    store.invalidate("thing");
    const pending = deferred<string>();
    const request = store.ensure("thing", () => pending.promise);
    expect(store.read("thing")).toMatchObject({ state: "refreshing", data: "known" });
    pending.reject(new Error("offline"));
    await expect(request).rejects.toThrow("offline");
    await Promise.resolve();
    expect(store.read("thing")).toMatchObject({ state: "error", data: "known", stale: true });
  });

  it("invalidates only the requested scope and reset does not clear data", () => {
    const store = new WorldViewStore();
    store.set("space:a/issue:1", 1);
    store.set("space:a/board:A", 2);
    store.set("space:b/issue:1", 3);
    store.invalidate((key) => key.startsWith("space:a/issue:"));
    expect(store.read("space:a/issue:1").state).toBe("partial");
    expect(store.read("space:a/board:A").state).toBe("ready");
    store.reset((key) => key.startsWith("space:a/"));
    expect(store.read("space:a/board:A")).toMatchObject({ state: "partial", data: 2 });
    expect(store.read("space:b/issue:1").state).toBe("ready");
  });

  it("bounds entries without evicting active or in-flight resources", () => {
    const store = new WorldViewStore();
    store.set("issue:old", 1);
    store.set("issue:active", 2);
    const unsubscribe = store.subscribe("issue:active", () => undefined);
    void store.ensure("issue:flight", () => new Promise(() => undefined));
    store.set("issue:new", 4);
    store.evict("issue:", 2);
    expect(store.read("issue:old").state).toBe("cold");
    expect(store.read("issue:active").data).toBe(2);
    expect(store.isInFlight("issue:flight")).toBe(true);
    unsubscribe();
  });
});
