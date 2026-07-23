import type { DisplayState } from "./display";
import { EMPTY_FILTER, type FilterState } from "./filter";
import type { WorkView } from "./registry";

const KEY = "lait.saved-views";

export interface SavedView {
  id: string;
  name: string;
  filter: FilterState;
  display: DisplayState;
  /** The render mode to restore (list/board/calendar/timeline). Absent on views
   *  saved before the switcher existed — those just keep the current view. */
  view?: WorkView;
}

/** A view saved before a filter axis existed lacks that field; fold it over the
 *  empty filter so `.length` reads never touch `undefined`. */
function normalize(view: SavedView): SavedView {
  return { ...view, filter: { ...EMPTY_FILTER, ...view.filter } };
}

export function loadSavedViews(space: string, project: string): SavedView[] {
  try {
    const all = JSON.parse(localStorage.getItem(KEY) ?? "{}") as Record<string, SavedView[]>;
    return (all[scope(space, project)] ?? []).map(normalize);
  } catch {
    return [];
  }
}

export function saveView(space: string, project: string, view: SavedView): SavedView[] {
  const all = readAll();
  const scoped = all[scope(space, project)] ?? [];
  const next = [view, ...scoped.filter((item) => item.id !== view.id)];
  all[scope(space, project)] = next;
  writeAll(all);
  return next;
}

export function removeView(space: string, project: string, id: string): SavedView[] {
  const all = readAll();
  const next = (all[scope(space, project)] ?? []).filter((view) => view.id !== id);
  all[scope(space, project)] = next;
  writeAll(all);
  return next;
}

function scope(space: string, project: string): string {
  return `${space}:${project}`;
}

function readAll(): Record<string, SavedView[]> {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? "{}") as Record<string, SavedView[]>;
  } catch {
    return {};
  }
}

function writeAll(all: Record<string, SavedView[]>): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(all));
  } catch {
    // Views remain usable for the session even when persistence is unavailable.
  }
}
