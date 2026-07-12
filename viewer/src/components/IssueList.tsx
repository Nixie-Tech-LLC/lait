import type { Row } from "../types";
import { DEFAULT_WORKFLOW } from "../types";
import { PriorityBars, StatusDot, statusMeta } from "../ui";

// Group rows by workflow status, in canonical workflow order, so the flat list
// reads like Linear's grouped view.
function groupByStatus(rows: Row[]): [string, Row[]][] {
  const order = DEFAULT_WORKFLOW.map((s) => s.id);
  const byStatus = new Map<string, Row[]>();
  for (const r of rows) {
    const arr = byStatus.get(r.status) || [];
    arr.push(r);
    byStatus.set(r.status, arr);
  }
  const keys = [...byStatus.keys()].sort(
    (a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99),
  );
  return keys.map((k) => [k, byStatus.get(k)!]);
}

export function IssueList(props: {
  rows: Row[];
  loading: boolean;
  hasProjects: boolean;
  onOpen: (reff: string) => void;
  onCreateProject: () => void;
}) {
  const { rows, loading, hasProjects, onOpen, onCreateProject } = props;

  if (loading && rows.length === 0) return <div className="spin">Loading…</div>;

  if (rows.length === 0) {
    return (
      <div className="empty-state">
        {hasProjects ? (
          <>
            <div className="big">No issues yet</div>
            <div>Use “+ New issue” to create one.</div>
          </>
        ) : (
          <>
            <div className="big">Welcome to lait</div>
            <div>Create a project to start tracking issues.</div>
            <button
              className="btn"
              style={{ marginTop: 14 }}
              onClick={onCreateProject}
            >
              + New project
            </button>
          </>
        )}
      </div>
    );
  }

  const groups = groupByStatus(rows);

  return (
    <div className="list">
      {groups.map(([status, items]) => (
        <div key={status}>
          <div className="list-group-head">
            <StatusDot status={status} />
            {statusMeta(status).name}
            <span className="count">{items.length}</span>
          </div>
          {items.map((r) => (
            <button key={r.reff} className="row" onClick={() => onOpen(r.reff)}>
              <PriorityBars priority={r.priority} />
              <StatusDot status={r.status} />
              <span className="ref">{r.key_alias || r.reff}</span>
              <span className="title">
                {r.title || <em style={{ color: "var(--text-faint)" }}>untitled</em>}
              </span>
              {r.assignee_summary && (
                <span className="assignee">{r.assignee_summary}</span>
              )}
            </button>
          ))}
        </div>
      ))}
    </div>
  );
}
