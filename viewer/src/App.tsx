import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Group, Panel, Separator, useDefaultLayout, usePanelRef } from "react-resizable-panels";
import { Inbox as InboxIcon, LayoutGrid, List, PanelLeft, Plus } from "lucide-react";

import { ConfirmRequired, LaitError, rpc, spaces as fetchSpaces } from "./api";
import { useDoorbell } from "./doorbell";
import { contribute, registry, type AppApi, type Ctx, type View } from "./core/registry";
import { useKeys } from "./core/useKeys";
import { Activity } from "./ui/Activity";
import { Board } from "./ui/Board";
import { FilterBar } from "./ui/FilterBar";
import { Inbox } from "./ui/Inbox";
import { Members } from "./ui/Members";
import { IssueDetail } from "./ui/IssueDetail";
import { IssueList } from "./ui/IssueList";
import { Palette } from "./ui/Palette";
import { Shortcuts } from "./ui/Shortcuts";
import { Sidebar } from "./ui/Sidebar";
import { applyFilter, EMPTY_FILTER, needsServer, type FilterState } from "./core/filter";
import { isReadOnly, type BoardView, type LabelDto, type Row, type SpaceRow } from "./types";
import "./commands";

type Overlay = "palette" | "shortcuts" | null;

/**
 * The shell.
 *
 * It owns state and supplies an [`AppApi`]; it does not own keys. Every gesture —
 * a shortcut, a palette entry, a button — resolves to a command id and runs it, so
 * a behaviour is defined once and is overridable in one place. Buttons call
 * `registry.get(id)?.run(ctx)` rather than a local handler, which is what stops
 * "click" and "keypress" from drifting apart.
 */
export function App() {
  const [spaces, setSpaces] = useState<SpaceRow[]>([]);
  const [current, setCurrent] = useState<string | null>(null);
  const [board, setBoard] = useState<BoardView | null>(null);
  const [selection, setSelection] = useState<string | null>(null);
  const [overlay, setOverlay] = useState<Overlay>(null);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [detail, setDetail] = useState(true);
  const [view, setView] = useState<View>("list");
  const [unread, setUnread] = useState(0);
  const [filter, setFilter] = useState<FilterState>(EMPTY_FILTER);
  const [filterOpen, setFilterOpen] = useState(false);
  const [focusToken, setFocusToken] = useState(0);
  const [labels, setLabels] = useState<LabelDto[]>([]);
  /** Doc-ids the daemon says qualify. `null` = the daemon wasn't asked, which is
   *  not the same as "nothing qualifies" — see core/filter.ts. */
  const [allowed, setAllowed] = useState<ReadonlySet<string> | null>(null);
  // Bumped on every doorbell for this space: the detail pane re-reads off it.
  const [revision, setRevision] = useState(0);
  const sidebar = usePanelRef();

  const space = spaces.find((s) => s.id === current) ?? null;
  const readOnly = space ? isReadOnly(space) : false;

  const shown: BoardView | null = useMemo(
    () => (board ? applyFilter(board, filter, allowed) : null),
    [board, filter, allowed],
  );

  // Motion follows what is *visible*: j/k over rows a filter hid would look like
  // the selection teleporting.
  const rows: Row[] = useMemo(
    () => (shown ? shown.columns.flatMap((c) => c.rows.filter((r) => !r.tombstone)) : []),
    [shown],
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

  // Labels for the filter menu — the daemon's registry, not names we invented.
  useEffect(() => {
    if (!current) return setLabels([]);
    void (async () => {
      try {
        const r = await rpc(current, { cmd: "label_list" });
        if (r.kind === "labels") setLabels(r.labels);
      } catch {
        // A missing label registry is not worth an error banner over — the menu
        // just offers fewer options.
      }
    })();
  }, [current, revision]);

  // `mine`/`label` are server truth: ask `list`, keep the doc-ids, intersect.
  useEffect(() => {
    if (!current || !needsServer(filter)) return setAllowed(null);
    let alive = true;
    void (async () => {
      try {
        const r = await rpc(current, {
          cmd: "list",
          project: null,
          filter: { mine: filter.mine, label: filter.label, all: true },
        });
        if (alive && r.kind === "list") setAllowed(new Set(r.rows.map((x) => x.doc_id)));
      } catch (e) {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [current, filter, revision]);

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
          setRevision((r) => r + 1);
          return;
        }
        if (d.space !== current) return;
        void loadBoard(current);
        setRevision((r) => r + 1);
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
      toggleDetail: () => setDetail((d) => !d),
      goto: (v) => setView(v),
      openFilter: () => {
        setFilterOpen(true);
        setFocusToken((t) => t + 1);
      },
      toggleSidebar: () => {
        const p = sidebar.current;
        if (!p) return;
        if (p.isCollapsed()) p.expand();
        else p.collapse();
      },
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
    () => ({ view, spaceId: current, readOnly, selection, overlay: overlay !== null, app: api }),
    [view, current, readOnly, selection, overlay, api],
  );

  const pending = useKeys(ctx);
  // Width + collapsed state, persisted to localStorage by the library.
  const layout = useDefaultLayout({ id: "lait.layout", panelIds: ["sidebar", "main"] });

  useEffect(() => {
    registry.validate();
  }, []);

  const run = (id: string) => void registry.get(id)?.run(ctx);

  return (
    <Group
      orientation="horizontal"
      // Persisted per-user: a sidebar width you set once should survive a reload,
      // and the library already owns that — no state of ours to get wrong.
      {...layout}
      className="flex h-full"
    >
      <Panel
        id="sidebar"
        panelRef={sidebar}
        defaultSize="18%"
        minSize="140px"
        maxSize="32%"
        collapsible
        collapsedSize={0}
        className="bg-raised"
      >
        <Sidebar spaces={spaces} current={current} onPick={api.pickSpace} />
      </Panel>

      {/* A 1px seam with a 7px hit area: thin to look at, big enough to grab. */}
      <Separator className="bg-line data-[state=dragging]:bg-accent hover:bg-accent/60 relative w-px outline-none transition-colors">
        <span className="absolute inset-y-0 -left-[3px] w-[7px]" />
      </Separator>

      <Panel id="main" className="flex min-w-0 flex-col">
        <header className="border-line flex h-11 shrink-0 items-center gap-3 border-b px-3">
          <button
            onClick={() => run("view.sidebar")}
            className="text-mute hover:bg-hover hover:text-fg grid size-6 place-items-center rounded"
            title="Toggle sidebar"
            aria-label="Toggle sidebar"
          >
            <PanelLeft className="size-4" />
          </button>
          <h1 className="truncate font-semibold">{board?.project.name ?? "lait"}</h1>
          <span className="text-mute sr-only capitalize">{view}</span>
          <nav className="border-line ml-2 flex items-center gap-px rounded border p-px">
            {(
              [
                ["list", List, "Issues", "g l"],
                ["board", LayoutGrid, "Board", "g b"],
                ["inbox", InboxIcon, "Inbox", "g i"],
              ] as const
            ).map(([v, Icon, label, chord]) => (
              <button
                key={v}
                onClick={() => run(`go.${v}`)}
                aria-pressed={view === v}
                title={`${label} (${chord})`}
                aria-label={label}
                className={`relative grid size-6 place-items-center rounded-sm ${
                  view === v ? "bg-active text-fg" : "text-mute hover:bg-hover hover:text-fg"
                }`}
              >
                <Icon className="size-3.5" />
                {v === "inbox" && unread > 0 && (
                  <span className="bg-accent absolute -top-0.5 -right-0.5 size-1.5 rounded-full" />
                )}
              </button>
            ))}
          </nav>
          {readOnly && space?.identity.kind === "agent" && (
            <span
              className="border-line-strong text-dim rounded-sm border px-1.5 py-px text-2xs"
              title="A write here would be signed as this agent"
            >
              {space.identity.name}’s space · read-only
            </span>
          )}

          <span className="ml-auto flex items-center gap-3">
            <Liveness state={liveness} />
            {!readOnly && current && (
              <button
                onClick={() => run("issue.create")}
                className="border-line-strong bg-bg hover:bg-hover flex items-center gap-1.5 rounded border px-2 py-1 font-medium"
              >
                <Plus className="size-3.5" />
                New issue
              </button>
            )}
            <button
              onClick={() => run("palette.open")}
              className="border-line-strong text-mute hover:text-fg rounded border px-1.5 py-0.5 font-mono text-2xs"
              title="Command palette"
            >
              {navigator.platform.startsWith("Mac") ? "⌘K" : "Ctrl K"}
            </button>
          </span>
        </header>

        {error && (
          <p className="border-line text-danger border-b px-4 py-2 text-sm" role="alert">
            {error}
          </p>
        )}

        {filterOpen && (view === "list" || view === "board") && (
          <FilterBar
            filter={filter}
            labels={labels}
            focusToken={focusToken}
            onChange={setFilter}
            onClose={() => setFilterOpen(false)}
          />
        )}

        <div className="group/list flex min-h-0 flex-1 flex-col">
          {!current ? (
            <p className="text-mute p-8 text-center">Pick a space.</p>
          ) : view === "inbox" ? (
            <Inbox
              spaceId={current}
              revision={revision}
              onError={setError}
              onCountChange={setUnread}
              onOpen={(reff) => {
                api.select(reff);
                setView("list");
              }}
            />
          ) : view === "members" ? (
            <Members
              spaceId={current}
              revision={revision}
              readOnly={readOnly}
              onError={setError}
            />
          ) : view === "activity" ? (
            <Activity spaceId={current} revision={revision} onError={setError} onOpen={api.select} />
          ) : shown && view === "board" ? (
            <Board
              board={shown}
              selection={selection}
              onSelect={api.select}
              onCreate={() => run("issue.create")}
              readOnly={readOnly}
            />
          ) : shown && view === "list" ? (
            <IssueList
              board={shown}
              selection={selection}
              onSelect={api.select}
              onOpen={() => setDetail(true)}
              onCreate={() => run("issue.create")}
              readOnly={readOnly}
            />
          ) : (
            <p className="text-mute p-8 text-center">Not built yet.</p>
          )}
        </div>
      </Panel>

      {detail && selection && current && board && (view === "list" || view === "board") && (
        <>
          <Separator className="bg-line data-[state=dragging]:bg-accent hover:bg-accent/60 relative w-px outline-none transition-colors">
            <span className="absolute inset-y-0 -left-[3px] w-[7px]" />
          </Separator>
          <Panel id="detail" defaultSize="30%" minSize="260px" maxSize="50%">
            <IssueDetail
              // Remount on a different issue: a stale draft must not survive into
              // the next one, and `key` says that in one line.
              key={selection}
              spaceId={current}
              reff={selection}
              states={board.columns.map((c) => c.state)}
              readOnly={readOnly}
              revision={revision}
              onError={setError}
              onDelete={api.deleteIssue}
            />
          </Panel>
        </>
      )}

      {overlay === "palette" && <Palette ctx={ctx} onClose={() => setOverlay(null)} />}
      {overlay === "shortcuts" && <Shortcuts ctx={ctx} onClose={() => setOverlay(null)} />}

      {/* A half-typed sequence must be visible, or `g` reads as a dropped key. */}
      {pending.length > 0 && (
        <div className="border-line-strong bg-raised text-dim shadow-overlay fixed bottom-4 left-4 rounded border px-2 py-1 font-mono text-sm">
          {pending.join(" ")} …
        </div>
      )}
      {toast && (
        <div className="border-line-strong bg-raised shadow-overlay fixed bottom-4 left-1/2 -translate-x-1/2 rounded border px-3 py-1.5 text-sm">
          {toast}
        </div>
      )}
    </Group>
  );
}

function Liveness({ state }: { state: "connecting" | "live" | "retrying" }) {
  const dot = { live: "bg-ok", connecting: "bg-mute", retrying: "bg-warn" }[state];
  return (
    <span
      className={`flex items-center gap-1.5 text-sm ${state === "retrying" ? "text-warn" : "text-mute"}`}
      title={`Doorbell stream: ${state}`}
    >
      <span className={`size-1.5 rounded-full ${dot}`} />
      {state}
    </span>
  );
}

/**
 * The sidebar toggle is a command like everything else.
 *
 * Contributed here rather than in `commands/` because its `run` needs the panel
 * handle only this component holds — but it still goes through the same door, so
 * it lists in the palette, shows in `?`, and is rebindable. A component with a
 * private `keydown` would be a binding nobody could see or change.
 */
contribute({
  commands: [
    {
      id: "view.sidebar",
      title: "Toggle sidebar",
      group: "View",
      keys: ["mod+b"],
      run: (c) => c.app.toggleSidebar(),
    },
  ],
});
