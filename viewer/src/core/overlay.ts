import type { BoardView, Priority, Row } from "../types";

/**
 * The optimistic overlay — a local prediction, keyed by `(doc_id, field)`.
 *
 * Ported from the TUI's, and the word that carries the whole design is
 * **correlation-free**: there are no request ids, no pending queue, no rollback
 * log, no version vectors. A prediction is one cell, and it dies when *any* server
 * news arrives for its doc.
 *
 * The doorbell is the spine. It says "doc D is dirty" and carries no state, so the
 * client re-reads the authoritative projection and drops every guess about D. The
 * arrival of truth invalidates the guess — there is nothing to match up, which is
 * exactly why nothing can leak: a prediction cannot outlive the fact it predicted.
 *
 * Three ways a prediction dies:
 *   1. **A doorbell for its doc** — the normal path (see `App`'s handler).
 *   2. **An immediate error** — the request was refused; roll the guess back now.
 *   3. **The TTL** — see below.
 *
 * The TTL is the one thing the terminal version did without, and deliberately so:
 * against a local daemon over a Unix socket, a request that neither errors nor
 * produces a doorbell is close to impossible. A browser is not that. A dropped
 * fetch, a suspended tab, a socket that quietly went away — and the prediction
 * sticks forever, showing a value that no longer exists anywhere. So predictions
 * expire, and the UI falls back to whatever the server last said.
 */

/** Fields a client is allowed to predict — the ones a row renders. */
export type Field = "title" | "status" | "priority";

interface Prediction {
  value: string;
  /** ms epoch — the TTL axis. */
  at: number;
}

/** How long a guess may outlive its request before we stop believing it. */
export const PREDICTION_TTL_MS = 10_000;

export class Overlay {
  private byDoc = new Map<string, Map<Field, Prediction>>();

  set(doc: string, field: Field, value: string, now: number = Date.now()): void {
    const fields = this.byDoc.get(doc) ?? new Map<Field, Prediction>();
    fields.set(field, { value, at: now });
    this.byDoc.set(doc, fields);
  }

  get(doc: string, field: Field): string | undefined {
    return this.byDoc.get(doc)?.get(field)?.value;
  }

  /** Whether this doc carries any prediction — drives the "unconfirmed" mark. */
  has(doc: string): boolean {
    return (this.byDoc.get(doc)?.size ?? 0) > 0;
  }

  /** Every doc currently predicted. */
  docs(): string[] {
    return [...this.byDoc.keys()];
  }

  /** Drop every guess about this doc. The doorbell's whole job. */
  clearDoc(doc: string): boolean {
    return this.byDoc.delete(doc);
  }

  clear(): void {
    this.byDoc.clear();
  }

  /**
   * Expire stale predictions. Returns true if anything went, so the caller knows
   * whether a re-render is owed.
   */
  sweep(now: number = Date.now(), ttlMs: number = PREDICTION_TTL_MS): boolean {
    let changed = false;
    for (const [doc, fields] of this.byDoc) {
      for (const [field, p] of fields) {
        if (now - p.at >= ttlMs) {
          fields.delete(field);
          changed = true;
        }
      }
      if (fields.size === 0) this.byDoc.delete(doc);
    }
    return changed;
  }

  get size(): number {
    return this.byDoc.size;
  }
}

/**
 * Render a board through the overlay: predictions win over server data.
 *
 * A prediction is not a hint — it *is* the displayed value, or the write would not
 * feel instant. What keeps that honest is that every predicted row is visibly
 * marked (see the returned set), so the user is never told a guess is a fact.
 *
 * Status is the interesting one: predicting it has to **re-bucket** the row into
 * its new column, or the card sits still while claiming to have moved — worse than
 * no optimism at all. Rows are appended to the destination, because position is
 * `Catalog.boards[P]`'s to decide (A§9) and we do not know where the daemon will
 * put it; the doorbell will correct us in a moment.
 */
export function applyOverlay(
  board: BoardView,
  overlay: Overlay,
): { board: BoardView; optimistic: ReadonlySet<string> } {
  const marked = new Set(overlay.docs().filter((d) => overlay.has(d)));
  if (marked.size === 0) return { board, optimistic: marked };

  const predict = (r: Row): Row => {
    if (!overlay.has(r.doc_id)) return r;
    return {
      ...r,
      title: overlay.get(r.doc_id, "title") ?? r.title,
      status: overlay.get(r.doc_id, "status") ?? r.status,
      priority: (overlay.get(r.doc_id, "priority") as Priority | undefined) ?? r.priority,
    };
  };

  // Bucket in two passes so a mover cannot jump the queue: each column keeps its
  // own rows in their existing order (that order is `Catalog.boards[P]`'s answer,
  // A§9), and rows arriving from elsewhere are appended after them. We do not know
  // where the daemon will actually place a moved row, so the end is the honest
  // guess — and the doorbell corrects it in a moment either way.
  const all = board.columns.flatMap((c) => c.rows.map(predict));
  const stayed = new Map<string, string>(); // reff -> the column it came from
  for (const c of board.columns) for (const r of c.rows) stayed.set(r.reff, c.state.id);

  const seen = new Set<string>();
  const columns = board.columns.map((c) => {
    const home = all.filter((r) => r.status === c.state.id && stayed.get(r.reff) === c.state.id);
    const moved = all.filter((r) => r.status === c.state.id && stayed.get(r.reff) !== c.state.id);
    const rows = [...home, ...moved];
    rows.forEach((r) => seen.add(r.reff));
    return { ...c, rows };
  });

  // A status predicted to something with no column would vanish the row. Keep it
  // where it was: a wrong guess should be corrected by the doorbell, never
  // disappear the issue.
  const orphans = all.filter((r) => !seen.has(r.reff));
  if (orphans.length > 0 && columns[0]) {
    for (const o of orphans) {
      const home = board.columns.find((c) => c.rows.some((r) => r.reff === o.reff));
      const target = columns.find((c) => c.state.id === home?.state.id) ?? columns[0];
      target.rows = [...target.rows, { ...o, status: home?.state.id ?? o.status }];
    }
  }

  return { board: { ...board, columns }, optimistic: marked };
}
