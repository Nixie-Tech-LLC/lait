import { tsToDate } from "../types";

/**
 * Relative time from a unix-**seconds** stamp.
 *
 * One implementation, because the units are the trap: every timestamp in the Layer-B
 * DTOs is seconds, and the previous viewer fed them straight to `new Date(ms)` and
 * rendered every issue as January 1970. `tsToDate` is the only conversion, and this
 * is the only formatter — a second copy is where the bug comes back.
 *
 * Coarse on purpose. "3d" is what a row wants; the exact stamp is one hover away
 * via `<time dateTime>`.
 */
export function when(ts: number): string {
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return tsToDate(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** Keys are 64 hex chars; nobody reads more than the head of one. */
export const short = (key: string) => key.slice(0, 8);
