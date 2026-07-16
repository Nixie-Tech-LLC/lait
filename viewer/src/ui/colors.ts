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
