import { useEffect, useState } from "react";
import { api } from "../api";
import type { BoardView } from "../types";
import { PriorityBars, StatusDot, colorOf } from "../ui";

export function Board(props: {
  project: string;
  onOpen: (reff: string) => void;
  nonce: number;
}) {
  const { project, onOpen, nonce } = props;
  const [board, setBoard] = useState<BoardView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .board(project)
      .then((b) => alive && (setBoard(b), setError(null)))
      .catch((e) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [project, nonce]);

  if (error) return <div className="banner">⚠ {error}</div>;
  if (!board) return <div className="spin">Loading board…</div>;

  return (
    <div className="board">
      {board.columns.map((col) => (
        <div className="board-col" key={col.state.id}>
          <div className="board-col-head">
            <span
              className="status-dot"
              style={{ color: colorOf(col.state.color) }}
            />
            {col.state.name}
            <span className="count">{col.rows.length}</span>
          </div>
          <div className="board-col-body">
            {col.rows
              .filter((r) => !r.tombstone)
              .map((r) => (
                <button
                  key={r.reff}
                  className="card"
                  onClick={() => onOpen(r.reff)}
                >
                  <div className="ref">{r.key_alias || r.reff}</div>
                  <div className="title">{r.title || "untitled"}</div>
                  <div className="meta">
                    <PriorityBars priority={r.priority} />
                    <StatusDot status={r.status} />
                    {r.assignee_summary && (
                      <span className="assignee" style={{ marginLeft: "auto" }}>
                        {r.assignee_summary}
                      </span>
                    )}
                  </div>
                </button>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
}
