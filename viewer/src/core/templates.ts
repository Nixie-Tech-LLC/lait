import type { Priority } from "../types";

/**
 * Issue templates — a stored default field-set the composer merges on create.
 *
 * Local-first and per-device by design (localStorage, keyed by canonical space):
 * lait has no template concept in the engine, and a personal "bug report" or
 * "spike" scaffold is a convenience, not shared truth. If templates ever need to
 * be team-standard, the home is a catalog `templates` map mirroring `labels` —
 * this store is deliberately the small first slice, not that.
 *
 * A template carries only the merge-able fields: title/body/priority/status and
 * label names + assignee keys. Due date is intentionally omitted (a fixed
 * calendar date ages badly), and sub-issues are out of scope for this slice.
 */
export interface IssueTemplate {
  id: string;
  name: string;
  title: string;
  body: string;
  priority: Priority;
  /** Workflow state id, or "" to keep the composer's current status. */
  status: string;
  labels: string[];
  assignees: string[];
}

const KEY = "lait.issue-templates";

export function loadTemplates(space: string): IssueTemplate[] {
  try {
    const all = JSON.parse(localStorage.getItem(KEY) ?? "{}") as Record<string, IssueTemplate[]>;
    return all[space] ?? [];
  } catch {
    return [];
  }
}

export function saveTemplate(space: string, template: IssueTemplate): IssueTemplate[] {
  const all = readAll();
  const scoped = all[space] ?? [];
  all[space] = [template, ...scoped.filter((t) => t.id !== template.id)];
  writeAll(all);
  return all[space];
}

export function removeTemplate(space: string, id: string): IssueTemplate[] {
  const all = readAll();
  all[space] = (all[space] ?? []).filter((t) => t.id !== id);
  writeAll(all);
  return all[space];
}

function readAll(): Record<string, IssueTemplate[]> {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? "{}") as Record<string, IssueTemplate[]>;
  } catch {
    return {};
  }
}

function writeAll(all: Record<string, IssueTemplate[]>): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(all));
  } catch {
    // Templates are a convenience; a full quota just means none persist.
  }
}
