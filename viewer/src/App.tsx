import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import type { ProjectDto, Row, StatusInfo } from "./types";
import { Sidebar } from "./components/Sidebar";
import { IssueList } from "./components/IssueList";
import { Board } from "./components/Board";
import { IssueDetail } from "./components/IssueDetail";
import { NewIssueModal } from "./components/NewIssueModal";
import { NewProjectModal } from "./components/NewProjectModal";
import { InvitePanel } from "./components/InvitePanel";

type View = "list" | "board";
type Modal = "new-issue" | "new-project" | "invite" | null;

export function App() {
  const [projects, setProjects] = useState<ProjectDto[]>([]);
  const [status, setStatus] = useState<StatusInfo | null>(null);
  const [selected, setSelected] = useState<string>("all"); // "all" | project key
  const [view, setView] = useState<View>("list");
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [openReff, setOpenReff] = useState<string | null>(null);
  const [modal, setModal] = useState<Modal>(null);
  const [nonce, setNonce] = useState(0); // bump to force a data reload

  const bump = useCallback(() => setNonce((n) => n + 1), []);

  // Load projects + status (catalog-level) on mount and after writes.
  const loadCatalog = useCallback(async () => {
    try {
      const [ps, st] = await Promise.all([api.projects(), api.status()]);
      setProjects(ps);
      setStatus(st);
      setError(null);
    } catch (e: any) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    loadCatalog();
  }, [loadCatalog, nonce]);

  // Load the issue rows for the current selection (list view drives this; the
  // board fetches its own columns).
  useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .issues({ project: selected })
      .then((r) => {
        if (!alive) return;
        setRows(r.filter((row) => !row.tombstone));
        setError(null);
      })
      .catch((e) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [selected, nonce]);

  const selectedProject = projects.find((p) => p.key === selected) || null;
  const title =
    selected === "all" ? "All issues" : selectedProject?.name || selected;

  // Board needs a concrete project; fall back to the first if "all" is active.
  const boardProject =
    selectedProject?.key || (view === "board" ? projects[0]?.key : undefined);

  return (
    <div className="app">
      <Sidebar
        projects={projects}
        status={status}
        selected={selected}
        onSelect={setSelected}
        onNewProject={() => setModal("new-project")}
        onInvite={() => setModal("invite")}
      />

      <div className="main">
        <div className="topbar">
          <h1>{title}</h1>
          <div className="seg">
            <button
              className={view === "list" ? "active" : ""}
              onClick={() => setView("list")}
            >
              List
            </button>
            <button
              className={view === "board" ? "active" : ""}
              onClick={() => setView("board")}
            >
              Board
            </button>
          </div>
          <div className="spacer" />
          <button
            className="btn"
            onClick={() => setModal("new-issue")}
            disabled={projects.length === 0}
            title={projects.length === 0 ? "Create a project first" : ""}
          >
            + New issue
          </button>
        </div>

        {error && <div className="banner">⚠ {error}</div>}

        <div className="content">
          {view === "list" ? (
            <IssueList
              rows={rows}
              loading={loading}
              onOpen={setOpenReff}
              hasProjects={projects.length > 0}
              onCreateProject={() => setModal("new-project")}
            />
          ) : boardProject ? (
            <Board key={boardProject} project={boardProject} onOpen={setOpenReff} nonce={nonce} />
          ) : (
            <div className="empty-state">
              <div className="big">No project to show a board for</div>
              <div>Create a project to use board view.</div>
            </div>
          )}
        </div>
      </div>

      {openReff && (
        <IssueDetail
          reff={openReff}
          onClose={() => setOpenReff(null)}
          onChanged={bump}
        />
      )}

      {modal === "new-issue" && (
        <NewIssueModal
          projects={projects}
          defaultProject={selectedProject?.key}
          onClose={() => setModal(null)}
          onCreated={(reff) => {
            setModal(null);
            bump();
            setOpenReff(reff);
          }}
        />
      )}
      {modal === "new-project" && (
        <NewProjectModal
          onClose={() => setModal(null)}
          onCreated={(key) => {
            setModal(null);
            setSelected(key);
            bump();
          }}
        />
      )}
      {modal === "invite" && (
        <InvitePanel
          room={status?.room || "workspace"}
          inviterNick={status?.nick || ""}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  );
}
