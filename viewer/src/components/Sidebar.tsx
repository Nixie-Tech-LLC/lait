import type { ProjectDto, StatusInfo } from "../types";
import { colorOf } from "../ui";

export function Sidebar(props: {
  projects: ProjectDto[];
  status: StatusInfo | null;
  selected: string;
  onSelect: (key: string) => void;
  onNewProject: () => void;
  onInvite: () => void;
}) {
  const { projects, status, selected, onSelect, onNewProject, onInvite } = props;
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="dot" />
        lait
        <small>{status?.room}</small>
      </div>

      <div className="nav-section">
        <button
          className={"nav-item" + (selected === "all" ? " active" : "")}
          onClick={() => onSelect("all")}
        >
          <span className="swatch" style={{ background: "var(--text-faint)" }} />
          All issues
          {status && <span className="count">{status.issues}</span>}
        </button>
      </div>

      <div className="nav-section">
        <div className="nav-label">
          Projects
          <button title="New project" onClick={onNewProject}>
            +
          </button>
        </div>
        {projects.length === 0 && (
          <div style={{ padding: "4px 8px", color: "var(--text-faint)", fontSize: 12 }}>
            No projects yet
          </div>
        )}
        {projects.map((p) => (
          <button
            key={p.id}
            className={"nav-item" + (selected === p.key ? " active" : "")}
            onClick={() => onSelect(p.key)}
            title={p.key}
          >
            <span className="swatch" style={{ background: colorOf(p.color) }} />
            {p.name}
            <span className="count">{p.key}</span>
          </button>
        ))}
      </div>

      <div className="nav-section" style={{ marginTop: 12 }}>
        <button className="nav-item" onClick={onInvite}>
          <span style={{ width: 9, textAlign: "center" }}>✉</span>
          Invite people
        </button>
      </div>

      <div className="sidebar-foot">
        {status ? (
          <>
            {status.nick} · {status.online_peers} peer
            {status.online_peers === 1 ? "" : "s"} online
          </>
        ) : (
          "connecting…"
        )}
      </div>
    </aside>
  );
}
