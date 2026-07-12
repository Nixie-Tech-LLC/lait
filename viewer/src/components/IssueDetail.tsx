import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { IssueView, Priority } from "../types";
import { DEFAULT_WORKFLOW, PRIORITIES } from "../types";
import { StatusDot, fmtTime } from "../ui";

export function IssueDetail(props: {
  reff: string;
  onClose: () => void;
  onChanged: () => void; // notify parent to refresh lists/board
}) {
  const { reff, onClose, onChanged } = props;
  const [issue, setIssue] = useState<IssueView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api
      .issue(reff)
      .then((i) => {
        setIssue(i);
        setTitle(i.title);
        setError(null);
      })
      .catch((e) => setError(e.message));
  }, [reff]);

  useEffect(load, [load]);

  // Close on Escape.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const patch = async (p: { title?: string; status?: string; priority?: Priority }) => {
    setBusy(true);
    try {
      await api.editIssue(reff, p);
      onChanged();
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const saveTitle = () => {
    if (issue && title.trim() && title !== issue.title) patch({ title: title.trim() });
  };

  const addComment = async () => {
    if (!comment.trim()) return;
    setBusy(true);
    try {
      await api.comment(reff, comment.trim());
      setComment("");
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  const del = async () => {
    if (!confirm("Delete this issue?")) return;
    setBusy(true);
    try {
      await api.deleteIssue(reff);
      onChanged();
      onClose();
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  };

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <div className="drawer">
        <div className="drawer-head">
          <span className="ref">
            {issue?.key_alias || issue?.reff || reff}
          </span>
          {busy && <span style={{ color: "var(--text-faint)", fontSize: 11 }}>saving…</span>}
          <div style={{ flex: 1 }} />
          <button className="btn danger" onClick={del} disabled={busy}>
            Delete
          </button>
          <button className="icon-btn" onClick={onClose} title="Close (Esc)">
            ✕
          </button>
        </div>

        <div className="drawer-body">
          {error && <div className="banner" style={{ marginBottom: 12 }}>⚠ {error}</div>}
          {!issue ? (
            <div className="spin">Loading…</div>
          ) : (
            <>
              <textarea
                className="drawer-title"
                rows={1}
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                onBlur={saveTitle}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    (e.target as HTMLTextAreaElement).blur();
                  }
                }}
              />

              <div className="props">
                <span className="k">Status</span>
                <div className="row-flex">
                  <StatusDot status={issue.status} />
                  <select
                    className="inp"
                    value={issue.status}
                    onChange={(e) => patch({ status: e.target.value })}
                    style={{ maxWidth: 200 }}
                  >
                    {DEFAULT_WORKFLOW.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                    {/* keep a non-default status selectable if present */}
                    {!DEFAULT_WORKFLOW.some((s) => s.id === issue.status) && (
                      <option value={issue.status}>{issue.status}</option>
                    )}
                  </select>
                </div>

                <span className="k">Priority</span>
                <select
                  className="inp"
                  value={issue.priority}
                  onChange={(e) => patch({ priority: e.target.value as Priority })}
                  style={{ maxWidth: 200 }}
                >
                  {PRIORITIES.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>

                <span className="k">Project</span>
                <span>{issue.project_key || issue.project_id}</span>

                {issue.label_names.length > 0 && (
                  <>
                    <span className="k">Labels</span>
                    <span className="row-flex" style={{ flexWrap: "wrap" }}>
                      {issue.label_names.map((l) => (
                        <span className="label-tag" key={l}>
                          {l}
                        </span>
                      ))}
                    </span>
                  </>
                )}

                <span className="k">Created</span>
                <span title={new Date(issue.created_at).toLocaleString()}>
                  {fmtTime(issue.created_at)}
                </span>
              </div>

              <div className={"desc" + (issue.description ? "" : " empty")}>
                {issue.description || "No description."}
              </div>

              <div className="comments">
                <div style={{ color: "var(--text-dim)", fontSize: 12, marginBottom: 6 }}>
                  {issue.comments.length} comment
                  {issue.comments.length === 1 ? "" : "s"}
                </div>
                {issue.comments.map((c, i) => (
                  <div className="comment" key={i}>
                    <div>
                      <span className="who">{c.author_nick || c.author.slice(0, 8)}</span>
                      <span className="when">{fmtTime(c.ts)}</span>
                    </div>
                    <div className="body">{c.body}</div>
                  </div>
                ))}

                <div className="comment-box">
                  <textarea
                    className="inp"
                    rows={2}
                    placeholder="Add a comment…"
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                    onKeyDown={(e) => {
                      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") addComment();
                    }}
                  />
                  <div style={{ display: "flex", justifyContent: "flex-end" }}>
                    <button
                      className="btn"
                      onClick={addComment}
                      disabled={busy || !comment.trim()}
                    >
                      Comment
                    </button>
                  </div>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}
