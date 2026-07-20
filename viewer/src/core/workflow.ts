import type { StatusCategory, WorkflowState } from "../types";

/**
 * Where the work-state verbs land.
 *
 * `issue_start`/`_done`/`_stop` do not name a status — they name a **category**, and
 * the daemon resolves it as *the first state in workflow-list order whose category
 * matches* (`replica.rs::first_state_in`). So `start` on the default workflow means
 * `in_progress`, and on a workflow whose first Active state is `triage` it means
 * `triage`.
 *
 * This is a deliberate second copy of a daemon rule, which the client otherwise
 * refuses to make (see `core/filter.ts` on why `mine` is never guessed at). The
 * difference is what the copy is *for*: this one only ever feeds
 * `Overlay.set(doc, "status", …)` — a prediction, which is marked as unconfirmed on
 * screen and which the next doorbell overwrites with server truth regardless of
 * whether we guessed right. Being wrong here costs one frame of a wrong column, not
 * a wrong answer. Filtering has no such backstop: a mis-guessed `mine` silently
 * shows you someone else's issues and nothing ever corrects it.
 *
 * `states` must be in board order — `BoardView.columns` is, because the daemon
 * builds it by walking the workflow list.
 */
export function firstStateIn(
  states: readonly WorkflowState[],
  category: StatusCategory,
): WorkflowState | null {
  return states.find((s) => s.category === category) ?? null;
}

/** The category each work verb targets. Mirrors `replica.rs:797-799`. */
export const WORK_CATEGORY = {
  start: "active",
  done: "done",
  stop: "backlog",
} as const satisfies Record<string, StatusCategory>;

/**
 * The status a work verb will land on, or `null` if this workflow has no state in
 * that category — in which case the daemon refuses with "this space's workflow has
 * no {cat}-category status" and there is nothing honest to predict.
 */
export function workTarget(
  states: readonly WorkflowState[],
  action: keyof typeof WORK_CATEGORY,
): WorkflowState | null {
  return firstStateIn(states, WORK_CATEGORY[action]);
}

/**
 * The neighbouring status, for `H`/`L` (UI.md §5.1).
 *
 * Clamps rather than wraps: `L` on the last column should stop, not teleport the
 * issue back to Backlog. A wrap would be indistinguishable from a mis-key.
 * Returns `null` when there is nowhere to go, so the caller can no-op silently.
 */
export function neighbourState(
  states: readonly WorkflowState[],
  current: string,
  delta: number,
): WorkflowState | null {
  const i = states.findIndex((s) => s.id === current);
  if (i < 0) return null;
  const next = i + delta;
  if (next < 0 || next >= states.length) return null;
  return states[next] ?? null;
}
