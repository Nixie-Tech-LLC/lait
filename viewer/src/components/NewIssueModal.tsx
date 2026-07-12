import { useState } from "react";
import { api } from "../api";
import type { Priority, ProjectDto } from "../types";
import { PRIORITIES } from "../types";

export function NewIssueModal(props: {
  projects: ProjectDto[];
  defaultProject?: string;
  onClose: () => void;
  onCreated: (reff: string) => void;
}) {
  const { projects, defaultProject, onClose, onCreated } = props;
  const [title, setTitle] = useState("");
  const [project, setProject] = useState(defaultProject || projects[0]?.key || "");
  const [priority, setPriority] = useState<Priority>("none");
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!title.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.createIssue({
        title: title.trim(),
        project: project || undefined,
        priority: priority === "none" ? undefined : priority,
        body: body.trim() || undefined,
      });
      onCreated(r.reff);
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>New issue</h2>
        {error && <div className="banner" style={{ marginBottom: 12 }}>⚠ {error}</div>}

        <div className="field">
          <label>Title</label>
          <input
            className="inp"
            autoFocus
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            placeholder="Issue title"
          />
        </div>

        <div className="field" style={{ display: "flex", gap: 12 }}>
          <div style={{ flex: 1 }}>
            <label>Project</label>
            <select
              className="inp"
              value={project}
              onChange={(e) => setProject(e.target.value)}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.key}>
                  {p.name} ({p.key})
                </option>
              ))}
            </select>
          </div>
          <div style={{ flex: 1 }}>
            <label>Priority</label>
            <select
              className="inp"
              value={priority}
              onChange={(e) => setPriority(e.target.value as Priority)}
            >
              {PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="field">
          <label>Description (optional)</label>
          <textarea
            className="inp"
            rows={4}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Add more detail…"
          />
        </div>

        <div className="modal-actions">
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn" onClick={submit} disabled={busy || !title.trim()}>
            {busy ? "Creating…" : "Create issue"}
          </button>
        </div>
      </div>
    </div>
  );
}
