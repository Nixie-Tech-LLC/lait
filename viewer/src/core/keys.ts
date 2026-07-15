/**
 * Key notation: parse, match, format.
 *
 * Ported from the TUI's `keymap.rs`, which had the model right and is worth
 * stating again: **a binding is data, and its notation is a closed loop** — what
 * the help overlay shows, a user can paste back into an override. Everything here
 * exists to keep `parse(format(parse(s))) === parse(s)` true.
 *
 * Three deliberate departures from the terminal original:
 *
 * - **`mod`** is Cmd on macOS and Ctrl elsewhere. The TUI could not have this
 *   idea (a terminal has no Cmd) and its parser rejected `meta+` outright, which
 *   would be exactly wrong in a browser where Cmd is the primary modifier.
 * - **Sequences** (`g i`) are first-class. Linear's navigation is built on them
 *   and a chord-only table cannot express it.
 * - **Shift-as-char survives.** The TUI's rule — "char patterns ignore SHIFT, the
 *   char itself already encodes case" — is true of `KeyboardEvent.key` too: shift+x
 *   arrives as `"X"`. So `X` *is* the binding for shift+x, and named keys
 *   (`enter`, `tab`) compare modifiers exactly.
 */

export interface Chord {
  /** `KeyboardEvent.key`, verbatim for printable keys; lowercased name otherwise. */
  key: string;
  ctrl: boolean;
  alt: boolean;
  shift: boolean;
  meta: boolean;
}

/** One binding: a sequence of chords. Length 1 is the common case. */
export type Binding = Chord[];

/** macOS gets Cmd; everyone else gets Ctrl. */
export const IS_MAC: boolean =
  typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform ?? "");

/** How long a half-finished sequence waits for its next key. Linear's feel. */
export const SEQUENCE_TIMEOUT_MS = 1000;

/** Named keys we accept in notation, mapped to their `KeyboardEvent.key`. */
const NAMED: Record<string, string> = {
  enter: "Enter",
  esc: "Escape",
  escape: "Escape",
  tab: "Tab",
  space: " ",
  up: "ArrowUp",
  down: "ArrowDown",
  left: "ArrowLeft",
  right: "ArrowRight",
  pgup: "PageUp",
  pgdn: "PageDown",
  pgdown: "PageDown",
  home: "Home",
  end: "End",
  backspace: "Backspace",
  delete: "Delete",
};

const NAMED_INVERSE: Record<string, string> = {
  Enter: "enter",
  Escape: "esc",
  Tab: "tab",
  " ": "space",
  ArrowUp: "up",
  ArrowDown: "down",
  ArrowLeft: "left",
  ArrowRight: "right",
  PageUp: "pgup",
  PageDown: "pgdn",
  Home: "home",
  End: "end",
  Backspace: "backspace",
  Delete: "delete",
};

/** Pretty glyphs for the help overlay. Display-only — `parse` never sees these. */
const GLYPH: Record<string, string> = {
  Enter: "↵",
  Escape: "Esc",
  Tab: "⇥",
  " ": "Space",
  ArrowUp: "↑",
  ArrowDown: "↓",
  ArrowLeft: "←",
  ArrowRight: "→",
};

function parseChord(text: string): Chord | null {
  let rest = text.trim();
  if (!rest) return null;

  const chord: Chord = { key: "", ctrl: false, alt: false, shift: false, meta: false };
  // Modifiers are a prefix loop, so `ctrl+alt+x` works and order doesn't matter.
  for (;;) {
    const m = /^(mod|cmd|meta|ctrl|control|alt|opt|option|shift)\+/i.exec(rest);
    if (!m?.[1]) break;
    switch (m[1].toLowerCase()) {
      case "mod":
        if (IS_MAC) chord.meta = true;
        else chord.ctrl = true;
        break;
      case "cmd":
      case "meta":
        chord.meta = true;
        break;
      case "ctrl":
      case "control":
        chord.ctrl = true;
        break;
      case "alt":
      case "opt":
      case "option":
        chord.alt = true;
        break;
      case "shift":
        chord.shift = true;
        break;
    }
    rest = rest.slice(m[0].length);
  }
  if (!rest) return null; // a bare modifier ("ctrl+") is not a chord

  const named = NAMED[rest.toLowerCase()];
  if (named) {
    chord.key = named;
    return chord;
  }
  const fn = /^f([1-9]|1[0-2])$/i.exec(rest);
  if (fn) {
    chord.key = `F${fn[1]}`;
    return chord;
  }
  // A single printable character. Case is meaningful and carries shift itself.
  if ([...rest].length !== 1) return null;
  chord.key = rest;
  return chord;
}

/**
 * Parse a binding: chords joined by `+`, sequences separated by spaces.
 *
 * `"mod+k"` → one chord. `"g i"` → two. Returns `null` on anything unparseable
 * so the caller can *warn* rather than throw — an override that cannot be read
 * must never take the app down with it (the TUI's "warn, never gate").
 */
export function parseBinding(text: string): Binding | null {
  const parts = text.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return null;
  const chords: Chord[] = [];
  for (const p of parts) {
    const c = parseChord(p);
    if (!c) return null;
    chords.push(c);
  }
  return chords;
}

/** Render a binding back to notation the user could paste into an override. */
export function formatBinding(binding: Binding, opts: { glyphs?: boolean } = {}): string {
  return binding.map((c) => formatChord(c, opts)).join(" ");
}

function formatChord(c: Chord, { glyphs = false }: { glyphs?: boolean }): string {
  // Two audiences, two spellings. `glyphs` is for a human reading a key hint —
  // macOS renders modifiers as symbols that need no separator (⌘K), everything
  // else spells them out (Ctrl+K). Without `glyphs` this is the *notation*: the
  // exact lowercase string `parseBinding` accepts, so the loop stays closed and
  // what the `?` overlay documents is what an override can be written with.
  const mods: string[] = [];
  if (c.ctrl) mods.push(glyphs ? (IS_MAC ? "⌃" : "Ctrl") : "ctrl");
  if (c.alt) mods.push(glyphs ? (IS_MAC ? "⌥" : "Alt") : "alt");
  if (c.shift) mods.push(glyphs ? "⇧" : "shift");
  if (c.meta) mods.push(glyphs ? "⌘" : "cmd");
  const key = glyphs ? (GLYPH[c.key] ?? c.key.toUpperCase()) : (NAMED_INVERSE[c.key] ?? c.key);
  const sep = glyphs && IS_MAC ? "" : "+";
  return [...mods, key].join(sep);
}

/**
 * Does this event match this chord?
 *
 * The shift rule is the subtle one, inherited and re-justified: for a printable
 * key, `KeyboardEvent.key` already encodes case (`"X"` for shift+x), so comparing
 * `shiftKey` as well would double-count it and make `X` unmatchable. For named
 * keys there is no such encoding, so modifiers compare exactly.
 */
export function matchChord(ev: KeyboardEvent, c: Chord): boolean {
  if (ev.ctrlKey !== c.ctrl || ev.altKey !== c.alt || ev.metaKey !== c.meta) return false;
  const printable = [...c.key].length === 1 && c.key !== " ";
  if (printable) return ev.key === c.key;
  return ev.key === c.key && ev.shiftKey === c.shift;
}

/** Whether an event is "just typing" — the target owns the key, not the app. */
export function isTypingTarget(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null;
  if (!el || !el.tagName) return false;
  const tag = el.tagName.toLowerCase();
  return tag === "input" || tag === "textarea" || tag === "select" || el.isContentEditable;
}
