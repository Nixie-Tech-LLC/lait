/**
 * Fuzzy ranking, ported from the TUI's `palette.rs`.
 *
 * Its own justification still holds: "case-insensitive subsequence score; prefix
 * and word-boundary hits score above scattered subsequences — enough ranking for
 * the palette's tiny candidate sets, no dependency."
 *
 * Greedy and left-to-right, so it can miss a better alignment further along. That
 * was an accepted simplification for a handful of commands and remains one here;
 * if the candidate set ever stops being tiny, replace this rather than tune it.
 */

const BONUS_MATCH = 1;
const BONUS_PREFIX = 4;
const BONUS_BOUNDARY = 3;
const BONUS_ADJACENT = 2;

/** `null` = no match. Higher is better. */
export function fuzzyScore(needle: string, haystack: string): number | null {
  if (!needle) return 0;
  const n = needle.toLowerCase();
  const h = haystack.toLowerCase();

  let score = 0;
  let hi = 0;
  let last = -2;

  for (const ch of n) {
    let found = -1;
    for (let i = hi; i < h.length; i++) {
      if (h[i] === ch) {
        found = i;
        break;
      }
    }
    if (found < 0) return null; // the full needle must be consumed

    score += BONUS_MATCH;
    if (found === 0) score += BONUS_PREFIX;
    else {
      const prev = h[found - 1];
      if (prev === " " || prev === "-" || prev === "_" || prev === ".") score += BONUS_BOUNDARY;
    }
    if (found === last + 1) score += BONUS_ADJACENT;

    last = found;
    hi = found + 1;
  }

  // Shorter haystacks win ties.
  return score - Math.floor(h.length / 8);
}

/** Rank items by their best-scoring searchable text; drop non-matches. */
export function rank<T>(items: readonly T[], needle: string, text: (t: T) => string[]): T[] {
  if (!needle.trim()) return [...items];
  const scored: Array<{ item: T; score: number }> = [];
  for (const item of items) {
    let best: number | null = null;
    for (const t of text(item)) {
      const s = fuzzyScore(needle, t);
      if (s !== null && (best === null || s > best)) best = s;
    }
    if (best !== null) scored.push({ item, score: best });
  }
  // Stable sort: registration order breaks ties, as in the TUI.
  return scored.sort((a, b) => b.score - a.score).map((s) => s.item);
}
