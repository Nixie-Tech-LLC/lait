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

/**
 * A due date's urgency, Linear's traffic-light reading: `overdue` (red) at or
 * past the deadline, `soon` (orange) within a week, `later` (muted) beyond.
 * One implementation so the list rows and the detail pane can never disagree
 * about what counts as overdue.
 */
export function dueTone(ts: number): "overdue" | "soon" | "later" {
  const now = Math.floor(Date.now() / 1000);
  if (ts <= now) return "overdue";
  if (ts - now <= 7 * 86_400) return "soon";
  return "later";
}

/**
 * A due date as a short calendar label (`Jul 30`, with year when not this year).
 *
 * Formatted in **UTC**, deliberately: the engine stores a due date as UTC
 * midnight of the day the user named, so a local-time rendering would show
 * "Jul 24" for a deadline typed as the 25th to everyone west of Greenwich —
 * the label must agree with the date input beside it.
 */
export function dueLabel(ts: number): string {
  const d = tsToDate(ts);
  const sameYear = d.getUTCFullYear() === new Date().getUTCFullYear();
  return d.toLocaleDateString(undefined, {
    timeZone: "UTC",
    month: "short",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

/** Unix seconds → the `YYYY-MM-DD` a date input (and the engine) speaks, UTC. */
export function dueToInput(ts: number): string {
  return tsToDate(ts).toISOString().slice(0, 10);
}
