/**
 * Catalog colours → theme tokens.
 *
 * `WorkflowState.color`, `ProjectDto.color`, and `LabelDto.color` are *names*
 * ("gray", "blue"), not hex — they come from the shared catalog and have to mean
 * something to a terminal as much as a browser. Handing them straight to CSS
 * technically works, and that is the trap: `color: blue` is #0000FF, which is not
 * in our palette, does not respond to the theme, and looks exactly as wrong as it
 * sounds next to a designed set of tokens.
 *
 * So they resolve through here. Unknown names fall back to a muted token rather
 * than to whatever CSS happens to recognise, because a colour we did not design is
 * a colour we cannot promise contrast for.
 */

const NAMED: Record<string, string> = {
  gray: "var(--color-mute)",
  grey: "var(--color-mute)",
  blue: "var(--color-accent)",
  green: "var(--color-ok)",
  yellow: "var(--color-warn)",
  orange: "var(--color-high)",
  red: "var(--color-danger)",
  purple: "light-dark(#7c3aed, #a78bfa)",
  pink: "light-dark(#db2777, #f472b6)",
  teal: "light-dark(#0d9488, #2dd4bf)",
};

/** A CSS colour for a catalog colour name. Accepts a literal hex passthrough,
 *  since nothing stops a catalog from carrying one. */
export function catalogColor(name: string): string {
  const key = name.trim().toLowerCase();
  if (/^#[0-9a-f]{3,8}$/i.test(key)) return key;
  return NAMED[key] ?? "var(--color-mute)";
}

/**
 * Member avatars: a **designed** set, indexed by key — never a computed hue.
 *
 * The obvious move is `hsl(hash % 360, …)`, and it is the wrong one for the same
 * reason `color: blue` is wrong above: a hue we did not choose is a hue we cannot
 * promise contrast for, and at 20px with white text on top, "mostly fine" means
 * "illegible for two members in ten". These eight are picked to hold white text in
 * both themes and to stay distinguishable from each other — including for the most
 * common forms of colour blindness, which a rainbow of computed hues is not.
 *
 * Deliberately *not* light-dark(): an avatar is a solid chip carrying white text,
 * so it wants the same ink in both themes. The surrounding ring adapts; the fill
 * does not need to.
 */
const AVATAR: readonly string[] = [
  "#4f46e5", // indigo
  "#0891b2", // cyan
  "#059669", // emerald
  "#b45309", // amber
  "#c026d3", // fuchsia
  "#dc2626", // red
  "#7c3aed", // violet
  "#0d9488", // teal
];

/**
 * A stable colour for a member key.
 *
 * FNV-1a over the whole key rather than `parseInt(key.slice(0, 2), 16)`: a prefix
 * is exactly what member keys are *displayed* by (and approved by), so two members
 * a human is being asked to tell apart are the two most likely to share a prefix —
 * and would have drawn the same colour. Hashing the full key puts the collision
 * somewhere it does not correlate with what the eye is comparing.
 */
export function avatarColor(deviceKey: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < deviceKey.length; i++) {
    h ^= deviceKey.charCodeAt(i);
    // `Math.imul` keeps this a 32-bit multiply; `h * 16777619` loses the low bits
    // to float precision and collapses the distribution.
    h = Math.imul(h, 0x01000193);
  }
  return AVATAR[Math.abs(h) % AVATAR.length] ?? AVATAR[0]!;
}
