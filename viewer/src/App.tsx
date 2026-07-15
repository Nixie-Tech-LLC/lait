import { useCallback, useEffect, useState } from "react";

import { ConfirmRequired, LaitError, rpc, spaces as fetchSpaces } from "./api";
import { useDoorbell } from "./doorbell";
import { isReadOnly, type BoardView, type SpaceRow } from "./types";
import "./app.css";

/**
 * The shell: spaces on the left, a board on the right.
 *
 * Deliberately thin for now — this is the foundation the keyboard layer (the
 * ported `Action`/keymap/palette vocabulary) and the rest of the surface grow
 * onto. What it does establish: the doorbell drives every refresh, selecting a
 * space is what attaches its daemon, and an agent's space renders read-only
 * because the engine will refuse writes there anyway.
 */
export function App() {
  const [spaces, setSpaces] = useState<SpaceRow[]>([]);
  const [current, setCurrent] = useState<string | null>(null);
  const [board, setBoard] = useState<BoardView | null>(null);
  const [error, setError] = useState<string | null>(null);

  const space = spaces.find((s) => s.id === current) ?? null;
  const readOnly = space ? isReadOnly(space) : false;

  const loadSpaces = useCallback(async () => {
    try {
      const { spaces } = await fetchSpaces();
      setSpaces(spaces);
      setError(null);
      // Selecting attaches a daemon, and attaching an agent brings that agent
      // *online*. So auto-select only our own single unambiguous space.
      setCurrent((cur) => {
        if (cur) return cur;
        const mine = spaces.filter((s) => !isReadOnly(s));
        return mine.length === 1 && mine[0] ? mine[0].id : null;
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const loadBoard = useCallback(async (id: string | null) => {
    if (!id) return setBoard(null);
    try {
      // `project: null` is legitimate — the daemon's choose-project chain picks
      // the view, so the picker needn't know a project to show a board.
      const r = await rpc(id, { cmd: "board", project: null });
      setBoard(r.kind === "board" ? r : null);
      setError(null);
    } catch (e) {
      setBoard(null);
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void loadSpaces();
  }, [loadSpaces]);
  useEffect(() => {
    void loadBoard(current);
  }, [current, loadBoard]);

  const liveness = useDoorbell(
    useCallback(
      (d) => {
        // A null frame is a `lagged`/undecodable ring: rebaseline everything.
        if (!d) {
          void loadSpaces();
          void loadBoard(current);
          return;
        }
        if (d.space !== current) return;
        void loadBoard(current);
        if (d.dirty_catalog.length) void loadSpaces();
      },
      [current, loadBoard, loadSpaces],
    ),
  );

  /** Writes never refetch: the daemon rings, and the doorbell reloads. */
  const write = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
      } catch (e) {
        if (e instanceof ConfirmRequired) return;
        setError(e instanceof LaitError ? e.message : String(e));
      }
    },
    [],
  );

  const create = () =>
    void write(async () => {
      const title = window.prompt("Issue title");
      if (!title || !current) return;
      await rpc(current, { cmd: "issue_new", title });
    });

  const remove = (reff: string) =>
    void write(async () => {
      if (!current) return;
      try {
        await rpc(current, { cmd: "issue_delete", reff });
      } catch (e) {
        // The engine hands back the CLI's own question rather than us inventing
        // one, so the modal and the terminal cannot disagree about the stakes.
        if (e instanceof ConfirmRequired) {
          if (window.confirm(e.question)) {
            await rpc(current, { cmd: "issue_delete", reff }, { confirm: true });
          }
          return;
        }
        throw e;
      }
    });

  const mine = spaces.filter((s) => !isReadOnly(s));
  const agents = spaces.filter(isReadOnly);

  return (
    <div className="app">
      <aside className="sidebar">
        <h2 className="eyebrow">Spaces</h2>
        <SpaceList rows={mine} current={current} onPick={setCurrent} />
        {agents.length > 0 && (
          <>
            <h2 className="eyebrow">Agents</h2>
            <SpaceList rows={agents} current={current} onPick={setCurrent} />
          </>
        )}
      </aside>

      <main className="main">
        <header className="topbar">
          <span className="title">
            {board ? board.project.name : "lait"}
            {readOnly && space?.identity.kind === "agent" && (
              <span className="badge" title="Writes here would be signed as this agent">
                {space.identity.name}’s space · read-only
              </span>
            )}
          </span>
          <span className={`live live--${liveness}`}>{liveness}</span>
          {!readOnly && current && (
            <button className="btn" onClick={create}>
              New issue
            </button>
          )}
        </header>

        {error && <p className="error">{error}</p>}

        {!current && <p className="empty">Pick a space.</p>}

        {board && (
          <div className="columns">
            {board.columns.map((c) => (
              <section className="column" key={c.state.id}>
                <h3 className="colhead">
                  <span className="dot" style={{ background: c.state.color }} />
                  {c.state.name}
                  <span className="count">{c.rows.length}</span>
                </h3>
                {c.rows
                  .filter((r) => !r.tombstone)
                  .map((r) => (
                    <article className="card" key={r.reff}>
                      <div className="card__title">{r.title}</div>
                      <div className="card__meta">
                        <span className="reff">{r.key_alias ?? r.reff}</span>
                        {!readOnly && (
                          <button className="link" onClick={() => remove(r.reff)}>
                            delete
                          </button>
                        )}
                      </div>
                    </article>
                  ))}
                {c.rows.length === 0 && <p className="empty empty--col">—</p>}
              </section>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}

function SpaceList({
  rows,
  current,
  onPick,
}: {
  rows: SpaceRow[];
  current: string | null;
  onPick: (id: string) => void;
}) {
  if (rows.length === 0) {
    return <p className="empty">Nothing yet.</p>;
  }
  return (
    <ul className="spacelist" role="listbox">
      {rows.map((s) => (
        <li key={s.id}>
          <button
            role="option"
            aria-selected={s.id === current}
            className="space"
            onClick={() => onPick(s.id)}
          >
            <span className="space__name">{s.name || s.workspace}</span>
            <span className="space__meta">
              <span className={`dot dot--${s.status}`} />
              {s.status}
              {s.identity.kind === "agent" && <span className="tag">{s.identity.name}</span>}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}
