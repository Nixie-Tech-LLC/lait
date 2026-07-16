/**
 * The seam's tests.
 *
 * Weighted toward the invariants that are expensive to relearn: overrides
 * replace rather than alias, a bad override warns rather than throws, a sequence
 * prefix is not pre-empted by a shorter match, and the core has no privileged
 * path into the registry. The last one is the whole argument — if it ever fails,
 * "extensible" has quietly become "forkable".
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import { fuzzyScore, rank } from "./fuzzy";
import { formatBinding, matchChord, parseBinding } from "./keys";
import { Registry, type Command, type Ctx } from "./registry";
import { resolve, shouldHandle } from "./resolve";

const ctx = (over: Partial<Ctx> = {}): Ctx => ({
  view: "list",
  spaceId: "s1",
  readOnly: false,
  selection: null,
  overlay: false,
  app: {} as Ctx["app"],
  ...over,
});

const key = (k: string, mods: Partial<KeyboardEvent> = {}) =>
  new KeyboardEvent("keydown", { key: k, ...mods });

const cmd = (over: Partial<Command> & { id: string }): Command => ({
  title: over.id,
  run: () => {},
  ...over,
});

describe("key notation", () => {
  it("round-trips: what the ? overlay shows, a user can paste back", () => {
    for (const s of ["ctrl+k", "X", "enter", "tab", "space", "f2", "alt+x", "?", "g i"]) {
      const parsed = parseBinding(s);
      expect(parsed, s).not.toBeNull();
      expect(parseBinding(formatBinding(parsed!))).toEqual(parsed);
    }
  });

  it("rejects what isn't a chord, rather than half-reading it", () => {
    expect(parseBinding("ctrl+")).toBeNull(); // bare modifier
    expect(parseBinding("f13")).toBeNull(); // out of range
    expect(parseBinding("ab")).toBeNull(); // two chars is not a key
    expect(parseBinding("")).toBeNull();
  });

  it("treats shift as part of the character, not a separate flag", () => {
    // The rule inherited from keymap.rs: `KeyboardEvent.key` is already "X" for
    // shift+x, so comparing shiftKey too would make "X" unmatchable.
    const upper = parseBinding("X")![0]!;
    expect(matchChord(key("X", { shiftKey: true }), upper)).toBe(true);
    expect(matchChord(key("x"), upper)).toBe(false);
  });

  it("compares modifiers exactly for named keys", () => {
    const tab = parseBinding("tab")![0]!;
    expect(matchChord(key("Tab"), tab)).toBe(true);
    expect(matchChord(key("Tab", { shiftKey: true }), tab)).toBe(false);
  });

  it("maps mod to one real modifier", () => {
    const mod = parseBinding("mod+k")![0]!;
    // Exactly one of ctrl/meta — never both, or it would match nothing.
    expect(mod.ctrl !== mod.meta).toBe(true);
    expect(matchChord(key("k", { ctrlKey: mod.ctrl, metaKey: mod.meta }), mod)).toBe(true);
    expect(matchChord(key("k"), mod)).toBe(false);
  });
});

describe("resolution", () => {
  const reg = () => new Registry();

  it("does not let a short match pre-empt a sequence that shares its prefix", () => {
    // The bug this prevents: `g` bound alone would make `g i` unreachable.
    const r = reg();
    r.contribute({
      commands: [cmd({ id: "seq", keys: ["g i"] }), cmd({ id: "solo", keys: ["g"] })],
    });
    const active = r.active(ctx());
    const first = resolve(active, [], key("g"));
    expect(first.kind).toBe("pending");

    const second = resolve(active, [key("g")], key("i"));
    expect(second.kind).toBe("run");
    expect(second.kind === "run" && second.command.id).toBe("seq");
  });

  it("fires a lone exact match immediately", () => {
    const r = reg();
    r.contribute({ commands: [cmd({ id: "solo", keys: ["c"] })] });
    const out = resolve(r.active(ctx()), [], key("c"));
    expect(out.kind).toBe("run");
  });

  it("returns none for an unbound key rather than guessing", () => {
    const r = reg();
    r.contribute({ commands: [cmd({ id: "solo", keys: ["c"] })] });
    expect(resolve(r.active(ctx()), [], key("z")).kind).toBe("none");
  });

  it("prefers the context-scoped command over the always-on one", () => {
    // The browser's version of keymap.rs's "context table first, then global".
    const r = reg();
    r.contribute({
      commands: [
        cmd({ id: "global", keys: ["x"] }),
        cmd({ id: "scoped", keys: ["x"], when: (c) => c.overlay }),
      ],
    });
    const inOverlay = resolve(r.active(ctx({ overlay: true })), [], key("x"));
    expect(inOverlay.kind === "run" && inOverlay.command.id).toBe("scoped");

    const outside = resolve(r.active(ctx({ overlay: false })), [], key("x"));
    expect(outside.kind === "run" && outside.command.id).toBe("global");
  });

  it("keeps bare keys out of a text field but lets you escape it", () => {
    expect(shouldHandle(key("c"), true)).toBe(false); // typing a c
    expect(shouldHandle(key("c"), false)).toBe(true);
    expect(shouldHandle(key("Escape"), true)).toBe(true); // always a way out
    expect(shouldHandle(key("k", { ctrlKey: true }), true)).toBe(true);
    expect(shouldHandle(key("Shift"), false)).toBe(false); // half a chord
  });
});

describe("the seam", () => {
  let r: Registry;
  beforeEach(() => {
    r = new Registry();
  });

  it("an added command is instantly in every projection", () => {
    r.contribute({ commands: [cmd({ id: "x.y", title: "Do it", keys: ["q"] })] });
    const active = r.active(ctx());
    expect(active.map((b) => b.command.id)).toContain("x.y");
    expect(active[0]!.chords).toEqual(["q"]);
  });

  it("an override REPLACES the key set — it does not add an alias", () => {
    // Inherited from keymap.rs and still deliberate: the alternative is bindings
    // you can never remove.
    r.contribute({ commands: [cmd({ id: "p", keys: ["mod+k", ":"] })] });
    r.contribute({ keys: { p: "ctrl+p" } });

    const bound = r.bound(r.get("p")!);
    expect(bound.chords).toEqual(["ctrl+p"]);
    expect(resolve(r.active(ctx()), [], key(":")).kind).toBe("none");
  });

  it("unbinds with null, leaving the command palette-reachable", () => {
    r.contribute({ commands: [cmd({ id: "p", keys: ["c"] })] });
    r.contribute({ keys: { p: null } });
    expect(r.bound(r.get("p")!).chords).toEqual([]);
    expect(resolve(r.active(ctx()), [], key("c")).kind).toBe("none");
    // Still listed: a command without a key is not a command without a use.
    expect(r.active(ctx()).map((b) => b.command.id)).toContain("p");
  });

  it("warns and carries on when an override is nonsense", () => {
    // Never gate: a typo in config must not take the app down, or you'd have no
    // working app in which to fix the typo.
    r.contribute({ commands: [cmd({ id: "p", keys: ["c"] })] });
    r.contribute({ keys: { p: "ctrl+", nope: "x" } });
    r.bound(r.get("p")!);
    r.validate();

    expect(r.warnings.some((w) => w.includes("not a key"))).toBe(true);
    expect(r.warnings.some((w) => w.includes("nope"))).toBe(true);
    expect(() => r.active(ctx())).not.toThrow();
  });

  it("patches a command's behaviour without touching its declaration", () => {
    const original = vi.fn();
    const replacement = vi.fn();
    r.contribute({ commands: [cmd({ id: "p", keys: ["c"], run: original })] });
    r.contribute({ overrides: { p: { run: replacement, title: "Renamed" } } });

    const out = resolve(r.active(ctx()), [], key("c"));
    expect(out.kind === "run" && out.command.title).toBe("Renamed");
    if (out.kind === "run") out.command.run(ctx());
    expect(replacement).toHaveBeenCalled();
    expect(original).not.toHaveBeenCalled();
  });

  it("dispose undoes exactly one contribution", () => {
    r.contribute({ commands: [cmd({ id: "keep", keys: ["a"] })] });
    const ext = r.contribute({ commands: [cmd({ id: "temp", keys: ["b"] })] });
    expect(r.all().map((c) => c.id).sort()).toEqual(["keep", "temp"]);
    ext.dispose();
    expect(r.all().map((c) => c.id)).toEqual(["keep"]);
  });

  it("respects `when` so a read-only space offers no writes", () => {
    r.contribute({
      commands: [cmd({ id: "issue.create", keys: ["c"], when: (c) => !c.readOnly })],
    });
    expect(r.active(ctx({ readOnly: true }))).toHaveLength(0);
    expect(resolve(r.active(ctx({ readOnly: true })), [], key("c")).kind).toBe("none");
  });
});

describe("the core's g-sequences", () => {
  it("navigates on g+key without g meaning anything alone", async () => {
    const { registry } = await import("./registry");
    await import("../commands");

    const active = registry.active(ctx());
    const go = active.filter((b) => b.command.id.startsWith("go."));
    expect(go.map((b) => b.command.id).sort()).toEqual([
      "go.activity",
      "go.board",
      "go.inbox",
      "go.list",
      "go.members",
    ]);
    // Every one is a two-chord sequence, not a bare letter — otherwise `g` and
    // `i` would each fire something on their own.
    for (const b of go) expect(b.bindings[0]).toHaveLength(2);

    // `g` alone pends rather than running.
    expect(resolve(active, [], key("g")).kind).toBe("pending");
    const done = resolve(active, [key("g")], key("i"));
    expect(done.kind === "run" && done.command.id).toBe("go.inbox");
  });
});

describe("the core has no privileged path", () => {
  it("registers every built-in through the public seam", async () => {
    // The load-bearing claim. If the core ever reaches past `contribute()`, an
    // extension stops being able to do what the core does — and this fails.
    const { registry } = await import("./registry");
    await import("../commands");

    const ids = registry.all().map((c) => c.id);
    expect(ids).toContain("palette.open");
    expect(ids).toContain("issue.create");

    // And a third party can override a core command, which is the same claim
    // seen from the other side.
    registry.contribute({ keys: { "issue.create": "n" } });
    expect(registry.bound(registry.get("issue.create")!).chords).toEqual(["n"]);
  });
});

describe("the palette's cmdk filter bridge", () => {
  // `score` adapts our scorer to cmdk's contract, and the two disagree in a way
  // that fails silently: ours returns null-for-no-match over an unbounded range,
  // cmdk reads 0 as "hide". A legitimate match CAN score <= 0 (the length
  // penalty), so without the shift a real hit vanishes from the palette.
  it("never returns 0 for a real match, however long the title", () => {
    const long = "Configure the extremely verbose thing with a very long name indeed";
    expect(fuzzyScore("c", long)).toBeLessThanOrEqual(0); // the trap
    expect(paletteScore(long, "c")).toBeGreaterThan(0); // the fix
  });

  it("returns 0 only for an actual non-match", () => {
    expect(paletteScore("New issue", "zzz")).toBe(0);
  });

  it("shows everything for an empty query", () => {
    expect(paletteScore("anything", "")).toBeGreaterThan(0);
    expect(paletteScore("anything", "   ")).toBeGreaterThan(0);
  });

  it("ranks a better match higher, so cmdk sorts the way we do", () => {
    expect(paletteScore("New issue", "ni")).toBeGreaterThan(paletteScore("Toggle sidebar", "ni"));
  });

  it("matches on the command id via keywords", () => {
    expect(paletteScore("New issue", "issue.cr", ["issue.create"])).toBeGreaterThan(0);
  });
});

/** Mirror of `ui/Palette.tsx`'s `score` — kept here so the contract is pinned
 *  without dragging React into a unit test. */
function paletteScore(value: string, search: string, keywords?: string[]): number {
  if (!search.trim()) return 1;
  let best: number | null = null;
  for (const hay of [value, ...(keywords ?? [])]) {
    const s = fuzzyScore(search, hay);
    if (s !== null && (best === null || s > best)) best = s;
  }
  return best === null ? 0 : Math.max(best + 100, 1);
}

describe("fuzzy ranking", () => {
  it("prefers prefixes and word boundaries over scattered hits", () => {
    expect(fuzzyScore("sta", "start")!).toBeGreaterThan(fuzzyScore("sta", "instant")!);
    expect(fuzzyScore("xyz", "start")).toBeNull();
    expect(fuzzyScore("ni", "New issue")).not.toBeNull();
  });

  it("ranks the obvious answer first", () => {
    const items = [{ t: "Delete issue" }, { t: "New issue" }, { t: "Open command palette" }];
    expect(rank(items, "ni", (i) => [i.t])[0]!.t).toBe("New issue");
  });

  it("returns everything for an empty query, in registration order", () => {
    const items = [{ t: "a" }, { t: "b" }];
    expect(rank(items, "", (i) => [i.t])).toHaveLength(2);
  });
});
