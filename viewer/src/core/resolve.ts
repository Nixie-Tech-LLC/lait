/**
 * Key → command resolution, including sequences.
 *
 * Kept as pure functions over an explicit pending buffer rather than hidden in the
 * hook, so the whole model — including the parts that only misbehave on the third
 * keystroke — is testable without a DOM.
 */

import { matchChord } from "./keys";
import type { Bound, Command, Ctx } from "./registry";

export type Outcome =
  /** Nothing wanted this key. Let the browser have it. */
  | { kind: "none" }
  /** A prefix of one or more sequences. Swallow the key and wait. */
  | { kind: "pending"; prefix: KeyboardEvent[]; candidates: Bound[] }
  /** Run this. */
  | { kind: "run"; command: Command };

/**
 * Resolve `prefix + ev` against the active commands.
 *
 * Specificity: a command with a `when` beats one without. This is the browser's
 * version of the TUI's "context table first, then global" rule — there, focus
 * chose the table; here, `when` is the context, so having one *is* being more
 * specific. Ties fall back to registration order, which is stable.
 */
export function resolve(active: Bound[], prefix: KeyboardEvent[], ev: KeyboardEvent): Outcome {
  const depth = prefix.length;
  const exact: Bound[] = [];
  const partial: Bound[] = [];

  for (const b of active) {
    for (const binding of b.bindings) {
      if (binding.length <= depth) continue;
      // Every chord so far must still match this binding.
      const ok = prefix.every((p, i) => {
        const c = binding[i];
        return c !== undefined && matchChord(p, c);
      });
      if (!ok) continue;
      const next = binding[depth];
      if (!next || !matchChord(ev, next)) continue;
      (binding.length === depth + 1 ? exact : partial).push(b);
      break;
    }
  }

  // A longer sequence in flight must not be pre-empted by a shorter exact match
  // that shares its prefix — otherwise `g` could never be the start of `g i`.
  // But a lone exact match should fire immediately rather than wait out the
  // timeout, which is what makes single-key actions feel instant.
  if (exact.length > 0 && partial.length === 0) {
    const first = pickMostSpecific(exact);
    return first ? { kind: "run", command: first.command } : { kind: "none" };
  }
  if (partial.length > 0) {
    return { kind: "pending", prefix: [...prefix, ev], candidates: [...partial, ...exact] };
  }
  return { kind: "none" };
}

function pickMostSpecific(bs: Bound[]): Bound | undefined {
  return [...bs].sort((a, b) => Number(!!b.command.when) - Number(!!a.command.when))[0];
}

/**
 * Should this event reach the keymap at all?
 *
 * While typing, bare keys belong to the field — `c` in a title box must type a
 * `c`, not file an issue. Modified chords (`mod+enter`) and `Escape` still get
 * through, because those are how you *leave* a field, and a text box that traps
 * you is worse than one that ignores a shortcut.
 */
export function shouldHandle(ev: KeyboardEvent, typing: boolean): boolean {
  // A modifier press on its own is never a binding; it's half of one.
  if (["Control", "Alt", "Shift", "Meta"].includes(ev.key)) return false;
  if (ev.isComposing) return false; // mid-IME: the key belongs to the composition
  if (!typing) return true;
  return ev.key === "Escape" || ev.ctrlKey || ev.metaKey;
}

/** Commands that apply, for a projection (palette, shortcuts overlay). */
export function forCtx(active: Bound[], ctx: Ctx): Bound[] {
  return active.filter((b) => (b.command.when ? b.command.when(ctx) : true));
}
