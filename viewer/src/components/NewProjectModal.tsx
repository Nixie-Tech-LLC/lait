import { useState } from "react";
import { api } from "../api";

export function NewProjectModal(props: {
  onClose: () => void;
  onCreated: (key: string) => void;
}) {
  const { onClose, onCreated } = props;
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [keyTouched, setKeyTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-suggest a key from the name (uppercase, alnum, first ~4 chars) until
  // the user edits the key field themselves.
  const suggestKey = (n: string) =>
    n.replace(/[^a-zA-Z0-9]/g, "").toUpperCase().slice(0, 4);
  const effKey = keyTouched ? key : suggestKey(name);

  const submit = async () => {
    if (!name.trim() || !effKey.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.createProject(name.trim(), effKey.trim());
      onCreated(effKey.trim());
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>New project</h2>
        {error && <div className="banner" style={{ marginBottom: 12 }}>⚠ {error}</div>}

        <div className="field">
          <label>Name</label>
          <input
            className="inp"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Engineering"
          />
        </div>

        <div className="field">
          <label>Key (issue prefix, e.g. ENG)</label>
          <input
            className="inp"
            value={effKey}
            onChange={(e) => {
              setKeyTouched(true);
              setKey(e.target.value.toUpperCase());
            }}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            placeholder="ENG"
          />
        </div>

        <div className="modal-actions">
          <button className="btn ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button
            className="btn"
            onClick={submit}
            disabled={busy || !name.trim() || !effKey.trim()}
          >
            {busy ? "Creating…" : "Create project"}
          </button>
        </div>
      </div>
    </div>
  );
}
