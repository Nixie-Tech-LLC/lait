import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Group, Panel, Separator, useDefaultLayout, usePanelRef } from "react-resizable-panels";
import {
  Inbox as InboxIcon,
  LayoutGrid,
  List,
  ListFilter,
  PanelLeft,
  Plus,
  Search,
} from "lucide-react";

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
import { NewIssue } from "./ui/NewIssue";
import { Palette } from "./ui/Palette";
import { Shortcuts } from "./ui/Shortcuts";
import * as ask from "./ui/dialogs";
import { DialogHost } from "./ui/dialogs";
import { IconButton, TooltipProvider } from "./ui/primitives";
import { Sidebar } from "./ui/Sidebar";
import {
  applyFilter,
  EMPTY_FILTER,
  isActive,
  needsServer,
  type FilterState,
} from "./core/filter";
import { applyOverlay, Overlay, PREDICTION_TTL_MS, type Field } from "./core/overlay";
import { isReadOnly, type BoardView, type LabelDto, type Row, type SpaceRow } from "./types";
import "./commands";

type Modal = "palette" | "shortcuts" | null;

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
  const [modal, setModal] = useState<Modal>(null);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [detail, setDetail] = useState(true);
  const [view, setView] = useState<View>("list");
  const [unread, setUnread] = useState(0);
  /** The composer, and the column it was opened from (null = closed). */
  const [composing, setComposing] = useState<{ status?: string } | null>(null);
  const [filter, setFilter] = useState<FilterState>(EMPTY_FILTER);
  const [filterOpen, setFilterOpen] = useState(false);
  const [focusToken, setFocusToken] = useState(0);
  const [labels, setLabels] = useState<LabelDto[]>([]);
  /** Doc-ids the daemon says qualify. `null` = the daemon wasn't asked, which is
   *  not the same as "nothing qualifies" — see core/filter.ts. */
  const [allowed, setAllowed] = useState<ReadonlySet<string> | null>(null);
  /** Local predictions. A ref, not state: the doorbell handler mutates it and we
   *  re-render explicitly — putting it in state would make every `set` a new Map
   *  and every render a new overlay. */
  const overlay = useRef(new Overlay());
  const [predicted, setPredicted] = useState(0);
  // Bumped on every doorbell for this space: the detail pane re-reads off it.
  const [revision, setRevision] = useState(0);
  const sidebar = usePanelRef();

  const space = spaces.find((s) => s.id === current) ?? null;
  const readOnly = space ? isReadOnly(space) : false;

  // Overlay first, then filter: a predicted title should be findable by the text
  // you just typed into it, and a predicted status should filter as its new one.
  // `predicted` is the re-render trigger — the overlay itself is a mutable ref.
  const { shown, optimistic } = useMemo(() => {
    if (!board) return { shown: null, optimistic: new Set<string>() as ReadonlySet<string> };
    const o = applyOverlay(board, overlay.current);
    return { shown: applyFilter(o.board, filter, allowed), optimistic: o.optimistic };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [board, filter, allowed, predicted]);

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

  /**
   * Load the board, and keep trying.
   *
   * A failed load must not be terminal. The daemon this space talks to can
   * restart under us — someone runs `lait shutdown`, an update swaps the binary,
   * two processes race to respawn it — and the failure lasts milliseconds. But
   * nothing would re-trigger the load: doorbells arrive through the very
   * attachment that just broke, so a transient error froze the view and left a
   * stale banner over it until the user thought to press `r`. The error was
   * honest; its permanence was the bug.
   *
   * Backs off rather than hammering, and gives up after a few tries so a genuinely
   * dead space says so instead of spinning forever.
   */
  const loadBoard = useCallback(async (id: string | null, attempt = 0): Promise<void> => {
    if (!id) return setBoard(null);
    try {
      const r = await rpc(id, { cmd: "board", project: null });
      setBoard(r.kind === "board" ? r : null);
      setError(null);
    } catch (e) {
      if (attempt < 3) {
        await new Promise((r) => window.setTimeout(r, 400 * 2 ** attempt));
        return loadBoard(id, attempt + 1);
      }
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
          // We can't say which docs moved, so no prediction can be trusted.
          overlay.current.clear();
          setPredicted((n) => n + 1);
          void loadSpaces();
          void loadBoard(current);
          setRevision((r) => r + 1);
          return;
        }
        if (d.space !== current) return;
        // The doorbell is the spine of the optimism: it names the docs that
        // moved, and the arrival of truth about a doc is what kills every guess
        // about it — no ids to match, nothing to reconcile. Re-read FIRST, then
        // drop the predictions: clearing before the fresh rows land would flash
        // the old server value for a frame, which is the one thing the optimism
        // exists to prevent.
        void loadBoard(current).then(() => {
          const docs = Object.values(d.dirty_by_project).flat();
          let cleared = false;
          for (const doc of docs) cleared = overlay.current.clearDoc(doc) || cleared;
          // `reset` (or a daemon restart) means our whole view is suspect, so no
          // guess about it survives either.
          if (d.reset) {
            overlay.current.clear();
            cleared = true;
          }
          if (cleared) setPredicted((n) => n + 1);
        });
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

  /**
   * Predict, then send.
   *
   * The order is the point: the value is on screen before the request leaves, and
   * the doorbell — not a response — is what retires the guess. If the request is
   * refused we roll back immediately rather than wait for a doorbell that will
   * never come, because a refusal *is* the news.
   */
  const predict = useCallback(
    async (doc: string, field: Field, value: string, send: () => Promise<unknown>) => {
      overlay.current.set(doc, field, value);
      setPredicted((n) => n + 1);
      try {
        await send();
      } catch (e) {
        overlay.current.clearDoc(doc);
        setPredicted((n) => n + 1);
        if (!(e instanceof ConfirmRequired)) {
          setError(e instanceof LaitError ? e.message : String(e));
        }
      }
    },
    [],
  );

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
      openPalette: () => setModal("palette"),
      closePalette: () => setModal(null),
      toggleShortcuts: () => setModal((m) => (m === "shortcuts" ? null : "shortcuts")),
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
      predict: (doc, field, value, send) => void predict(doc, field, value, send),
      pickSpace: (id) => setCurrent(id),
      moveSelection: (delta) => {
        const list = rowsRef.current;
        if (!list.length) return;
        const i = list.findIndex((r) => r.reff === selRef.current);
        const next = list[Math.max(0, Math.min(list.length - 1, (i < 0 ? 0 : i) + delta))];
        if (next) setSelection(next.reff);
      },
      createIssue: () => setComposing({}),
      deleteIssue: (reff) =>
        void guard(async () => {
          if (!current) return;
          try {
            await rpc(current, { cmd: "issue_delete", reff });
          } catch (e) {
            // The engine hands back the CLI's own question rather than us
            // inventing one, so modal and terminal cannot disagree on the stakes.
            if (e instanceof ConfirmRequired) {
              // The engine's own words, in our dialog.
              if (await ask.confirm({ title: e.question, confirmText: "Delete", danger: true })) {
                await rpc(current, { cmd: "issue_delete", reff }, { confirm: true });
              }
              return;
            }
            throw e;
          }
        }),
    }),
    [current, guard, loadBoard, loadSpaces, predict],
  );

  const ctx: Ctx = useMemo(
    () => ({ view, spaceId: current, readOnly, selection, overlay: modal !== null, app: api }),
    [view, current, readOnly, selection, modal, api],
  );

  const pending = useKeys(ctx);
  // Width + collapsed state, persisted to localStorage by the library.
  const layout = useDefaultLayout({ id: "lait.layout", panelIds: ["sidebar", "main"] });

  useEffect(() => {
    registry.validate();
  }, []);

  // A prediction whose request neither errored nor rang is stuck: a dropped fetch,
  // a suspended tab. Sweep so the UI falls back to what the server last said
  // instead of showing a value that exists nowhere.
  useEffect(() => {
    if (!predicted) return;
    const t = window.setInterval(() => {
      if (overlay.current.sweep()) setPredicted((n) => n + 1);
    }, PREDICTION_TTL_MS / 2);
    return () => window.clearInterval(t);
  }, [predicted]);

  const run = (id: string) => void registry.get(id)?.run(ctx);

  return (
    <TooltipProvider>
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
        {/*
          Chrome recedes. Linear's header is a breadcrumb and a few ghost icons —
          no bordered CTA competing with the content, no permanently-lit status
          badge. Ours had a segmented control, a primary button, and a `Ctrl K`
          chip all shouting at once; the work is the content, not the toolbar.
        */}
        <header className="border-line flex h-11 shrink-0 items-center gap-1 border-b px-2">
          <IconButton label="Toggle sidebar" chord="⌘B" onClick={() => run("view.sidebar")}>
            <PanelLeft className="size-4" />
          </IconButton>

          <h1 className="ml-1 flex min-w-0 items-baseline gap-1.5">
            <span className="truncate font-semibold">{board?.project.name ?? "lait"}</span>
            <span className="text-mute shrink-0">/</span>
            <span className="text-dim shrink-0 capitalize">{view}</span>
          </h1>

          <span className="ml-auto flex items-center gap-1">
            {/* Only when it is worth saying. A permanently-lit "live" is noise;
                a silent failure is worse. So: nothing when healthy, a warning
                when not. */}
            {liveness !== "live" && (
              <span
                className="text-warn mr-1 flex items-center gap-1.5 text-xs"
                title={`Doorbell stream: ${liveness}`}
                role="status"
              >
                <span className="bg-warn size-1.5 animate-pulse rounded-full" />
                {liveness}
              </span>
            )}

            <IconButton label="Search commands" chord="⌘K" onClick={() => run("palette.open")}>
              <Search className="size-4" />
            </IconButton>

            {(view === "list" || view === "board") && (
              <IconButton
                label="Filter"
                chord="/"
                variant={isActive(filter) ? "active" : "ghost"}
                onClick={() => run("filter.open")}
              >
                <ListFilter className="size-4" />
              </IconButton>
            )}

            {/* A segmented group without a box around it: adjacency does the
                grouping, the active fill does the state. */}
            <span className="mx-1 flex items-center gap-0.5">
              {(
                [
                  ["list", List, "Issues", "G L"],
                  ["board", LayoutGrid, "Board", "G B"],
                  ["inbox", InboxIcon, "Inbox", "G I"],
                ] as const
              ).map(([v, Icon, label, chord]) => (
                <IconButton
                  key={v}
                  label={label}
                  chord={chord}
                  variant={view === v ? "active" : "ghost"}
                  aria-pressed={view === v}
                  onClick={() => run(`go.${v}`)}
                  className="relative"
                >
                  <Icon className="size-4" />
                  {v === "inbox" && unread > 0 && (
                    <span className="bg-accent absolute top-0.5 right-0.5 size-1.5 rounded-full" />
                  )}
                </IconButton>
              ))}
            </span>

            {!readOnly && current && (
              <IconButton label="New issue" chord="C" onClick={() => run("issue.create")}>
                <Plus className="size-4" />
              </IconButton>
            )}
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
              optimistic={optimistic}
              onSelect={api.select}
              onCreate={(status) => setComposing({ status })}
              readOnly={readOnly}
            />
          ) : shown && view === "list" ? (
            <IssueList
              board={shown}
              selection={selection}
              optimistic={optimistic}
              onSelect={api.select}
              onOpen={() => setDetail(true)}
              onCreate={(status) => setComposing({ status })}
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
              onPredict={api.predict}
            />
          </Panel>
        </>
      )}

      {composing && current && board && (
        <NewIssue
          spaceId={current}
          projectKey={board.project.key}
          states={board.columns.map((c) => c.state)}
          labels={labels}
          defaultStatus={composing.status}
          onClose={() => setComposing(null)}
          onError={setError}
        />
      )}
      <DialogHost />
      {modal === "palette" && <Palette ctx={ctx} onClose={() => setModal(null)} />}
      {modal === "shortcuts" && <Shortcuts ctx={ctx} onClose={() => setModal(null)} />}

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
    </TooltipProvider>
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
