import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ConfirmRequired, LaitError, rpc, spaces as fetchSpaces } from "./api";
import { useDoorbell } from "./doorbell";
import { registry, type AppApi, type Ctx } from "./core/registry";
import { useKeys } from "./core/useKeys";
import { Palette } from "./ui/Palette";
import { Shortcuts } from "./ui/Shortcuts";
import { isReadOnly, type BoardView, type Row, type SpaceRow } from "./types";
import "./commands";
import "./app.css";

type Overlay = "palette" | "shortcuts" | null;

/**
 * The shell.
 *
 * It owns state and supplies an [`AppApi`]; it does not own keys. Every gesture
 * — a shortcut, a palette entry, a button — resolves to a command id and runs it,
 * so there is exactly one place a behaviour is defined and exactly one place to
 * override it. Buttons call `registry.get(id)?.run(ctx)` rather than a handler
 * directly, which is what keeps "click" and "keypress" from drifting apart.
 */
export function App() {
  const [spaces, setSpaces] = useState<SpaceRow[]>([]);
  const [current, setCurrent] = useState<string | null>(null);
  const [board, setBoard] = useState<BoardView | null>(null);
  const [selection, setSelection] = useState<string | null>(null);
  const [overlay, setOverlay] = useState<Overlay>(null);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const space = spaces.find((s) => s.id === current) ?? null;
  const readOnly = space ? isReadOnly(space) : false;

  const rows: Row[] = useMemo(
    () => (board ? board.columns.flatMap((c) => c.rows.filter((r) => !r.tombstone)) : []),
    [board],
  );

  const loadSpaces = useCallback(async () => {
    try {
      const { spaces } = await fetchSpaces();
      setSpaces(spaces);
      setError(null);
      setCurrent((cur) => {
        if (cur) return cur;
        // Attaching an agent brings that agent *online*, so auto-select only our
        // own single unambiguous space — never an agent.
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

  // A selection that no longer exists (deleted, filtered away) must not linger.
  useEffect(() => {
    setSelection((s) => (s && rows.some((r) => r.reff === s) ? s : (rows[0]?.reff ?? null)));
  }, [rows]);

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(null), 2400);
    return () => window.clearTimeout(t);
  }, [toast]);

  const liveness = useDoorbell(
    useCallback(
      (d) => {
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

  const rowsRef = useRef(rows);
  rowsRef.current = rows;
  const selRef = useRef(selection);
  selRef.current = selection;

  /** Writes never refetch — the daemon rings and the doorbell reloads. */
  const guard = useCallback(async (fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch (e) {
      if (e instanceof ConfirmRequired) return;
      setError(e instanceof LaitError ? e.message : String(e));
    }
  }, []);

  const api: AppApi = useMemo(
    () => ({
      openPalette: () => setOverlay("palette"),
      closePalette: () => setOverlay(null),
      toggleShortcuts: () => setOverlay((o) => (o === "shortcuts" ? null : "shortcuts")),
      toast: (m) => setToast(m),
      refresh: () => {
        void loadSpaces();
        void loadBoard(current);
        setToast("Refreshed");
      },
      select: (reff) => setSelection(reff),
      pickSpace: (id) => setCurrent(id),
      moveSelection: (delta) => {
        const list = rowsRef.current;
        if (!list.length) return;
        const i = list.findIndex((r) => r.reff === selRef.current);
        const next = list[Math.max(0, Math.min(list.length - 1, (i < 0 ? 0 : i) + delta))];
        if (next) setSelection(next.reff);
      },
      createIssue: () =>
        void guard(async () => {
          const title = window.prompt("Issue title");
          if (!title || !current) return;
          await rpc(current, { cmd: "issue_new", title });
        }),
      deleteIssue: (reff) =>
        void guard(async () => {
          if (!current) return;
          try {
            await rpc(current, { cmd: "issue_delete", reff });
          } catch (e) {
            // The engine hands back the CLI's own question rather than us
            // inventing one, so modal and terminal cannot disagree on the stakes.
            if (e instanceof ConfirmRequired) {
              if (window.confirm(e.question)) {
                await rpc(current, { cmd: "issue_delete", reff }, { confirm: true });
              }
              return;
            }
            throw e;
          }
        }),
    }),
    [current, guard, loadBoard, loadSpaces],
  );

  const ctx: Ctx = useMemo(
    () => ({ spaceId: current, readOnly, selection, overlay: overlay !== null, app: api }),
    [current, readOnly, selection, overlay, api],
  );

  const pending = useKeys(ctx);

  // Overrides can only be validated once everything has contributed.
  useEffect(() => {
    registry.validate();
  }, []);

  /** Run a command by id — the one path a click takes, same as a keystroke. */
  const runCmd = (id: string) => void registry.get(id)?.run(ctx);

  const mine = spaces.filter((s) => !isReadOnly(s));
  const agents = spaces.filter(isReadOnly);

  return (
    <div className="app">
      <aside className="sidebar">
        <h2 className="eyebrow">Spaces</h2>
        <SpaceList rows={mine} current={current} onPick={api.pickSpace} />
        {agents.length > 0 && (
          <>
            <h2 className="eyebrow">Agents</h2>
            <SpaceList rows={agents} current={current} onPick={api.pickSpace} />
          </>
        )}
      </aside>

      <main className="main">
        <header className="topbar">
          <span className="title">
            {board ? board.project.name : "lait"}
            {readOnly && space?.identity.kind === "agent" && (
              <span className="badge" title="A write here would be signed as this agent">
                {space.identity.name}’s space · read-only
              </span>
            )}
          </span>
          <span className={`live live--${liveness}`}>{liveness}</span>
          {!readOnly && current && (
            <button className="btn" onClick={() => runCmd("issue.create")}>
              New issue
            </button>
          )}
          <button className="btn btn--ghost" onClick={() => runCmd("palette.open")}>
            <kbd>{navigator.platform.startsWith("Mac") ? "⌘K" : "Ctrl+K"}</kbd>
          </button>
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
                  <span className="count">{c.rows.filter((r) => !r.tombstone).length}</span>
                </h3>
                {c.rows
                  .filter((r) => !r.tombstone)
                  .map((r) => (
                    <article
                      key={r.reff}
                      className={`card${r.reff === selection ? " card--sel" : ""}${
                        r.provisional ? " card--provisional" : ""
                      }`}
                      onClick={() => api.select(r.reff)}
                    >
                      <div className="card__title">{r.title}</div>
                      <div className="card__meta">
                        <span className="reff">{r.key_alias ?? r.reff}</span>
                        {r.assignee_summary && <span className="who">{r.assignee_summary}</span>}
                      </div>
                    </article>
                  ))}
                {c.rows.filter((r) => !r.tombstone).length === 0 && (
                  <p className="empty empty--col">—</p>
                )}
              </section>
            ))}
          </div>
        )}
      </main>

      {overlay === "palette" && <Palette ctx={ctx} onClose={() => setOverlay(null)} />}
      {overlay === "shortcuts" && <Shortcuts ctx={ctx} onClose={() => setOverlay(null)} />}

      {/* A half-typed sequence must be visible, or `g` feels like a dropped key. */}
      {pending.length > 0 && <div className="pending">{pending.join(" ")} …</div>}
      {toast && <div className="toast">{toast}</div>}
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
  if (rows.length === 0) return <p className="empty">Nothing yet.</p>;
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
