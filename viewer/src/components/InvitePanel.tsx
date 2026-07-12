import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import type { InviteInfo, JoinRequest, MemberDto } from "../types";
import { fmtTime } from "../ui";

const INSTALL_UNIX =
  "curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.sh | sh";
const INSTALL_WIN =
  'powershell -c "irm https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.ps1 | iex"';

function CopyBtn({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="btn ghost"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        } catch {
          /* clipboard blocked — user can select manually */
        }
      }}
    >
      {done ? "✓ Copied" : label}
    </button>
  );
}

export function InvitePanel(props: {
  room: string;
  inviterNick: string;
  onClose: () => void;
}) {
  const { room, inviterNick, onClose } = props;
  const [invite, setInvite] = useState<InviteInfo | null>(null);
  const [requests, setRequests] = useState<JoinRequest[]>([]);
  const [members, setMembers] = useState<MemberDto[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const loadInvite = useCallback(() => {
    api.invite().then(setInvite).catch((e) => setError(e.message));
  }, []);

  const loadMembership = useCallback(() => {
    Promise.all([api.joinRequests(), api.members()])
      .then(([r, m]) => {
        setRequests(r);
        setMembers(m);
      })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(loadInvite, [loadInvite]);
  useEffect(() => {
    loadMembership();
    // Poll for new join requests while the panel is open.
    const t = setInterval(loadMembership, 5000);
    return () => clearInterval(t);
  }, [loadMembership]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const approve = async (req: JoinRequest) => {
    setBusyId(req.id);
    setError(null);
    try {
      await api.addMember(req.id);
      loadMembership();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusyId(null);
    }
  };

  const url = invite?.url || "";
  const connectCmd = `lait connect ${url}`;
  const emailBody = [
    `Hi,`,
    ``,
    `You're invited to the "${room}" workspace on lait${
      inviterNick ? ` by ${inviterNick}` : ""
    }.`,
    ``,
    `1. Install lait:`,
    `   macOS/Linux:  ${INSTALL_UNIX}`,
    `   Windows:      ${INSTALL_WIN}`,
    ``,
    `2. Join the workspace:`,
    `   ${connectCmd}`,
    ``,
    `That announces a join request; I'll approve you and your device gets the`,
    `workspace key automatically. lait is local-first and end-to-end encrypted.`,
  ].join("\n");
  const mailto = `mailto:?subject=${encodeURIComponent(
    `Invitation to the "${room}" lait workspace`,
  )}&body=${encodeURIComponent(emailBody)}`;

  return (
    <div className="modal-scrim" onClick={onClose}>
      <div
        className="modal invite-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="invite-head">
          <h2>Invite to “{room}”</h2>
          <button className="icon-btn" onClick={onClose} title="Close (Esc)">
            ✕
          </button>
        </div>

        {error && <div className="banner" style={{ marginBottom: 12 }}>⚠ {error}</div>}

        {/* ---- share ---- */}
        <div className="invite-share">
          <div
            className="qr"
            aria-label="Invite QR code"
            dangerouslySetInnerHTML={{ __html: invite?.qr || "" }}
          />
          <div className="invite-share-right">
            <label className="mini-label">Invite link</label>
            <div className="row-flex">
              <input className="inp" readOnly value={url} onFocus={(e) => e.currentTarget.select()} />
              <CopyBtn text={url} />
            </div>
            <div className="invite-actions">
              <a className="btn" href={mailto}>
                ✉ Email invite
              </a>
              <button className="btn ghost" onClick={loadInvite} title="Generate a fresh link">
                ↻ Regenerate
              </button>
            </div>
          </div>
        </div>

        {/* ---- recipient one-liner ---- */}
        <details className="invite-onboard">
          <summary>What the recipient does</summary>
          <label className="mini-label">1. Install lait</label>
          <div className="code-row">
            <code>{INSTALL_UNIX}</code>
            <CopyBtn text={INSTALL_UNIX} />
          </div>
          <div className="code-row">
            <code>{INSTALL_WIN}</code>
            <CopyBtn text={INSTALL_WIN} />
          </div>
          <label className="mini-label">2. Join (announces a request you approve below)</label>
          <div className="code-row">
            <code>{connectCmd}</code>
            <CopyBtn text={connectCmd} />
          </div>
        </details>

        {/* ---- join requests ---- */}
        <div className="invite-requests">
          <div className="mini-label">
            Join requests {requests.length > 0 && `(${requests.length})`}
          </div>
          {requests.length === 0 ? (
            <div className="muted">
              None pending. When someone runs <code>lait connect</code> with your
              link, they’ll appear here to approve.
            </div>
          ) : (
            requests.map((r) => (
              <div className="req-row" key={r.id}>
                <div className="req-who">
                  <span className="req-nick">{r.nick || "unknown"}</span>
                  <span className="req-id">{r.id.slice(0, 10)}…</span>
                  <span className="when">{fmtTime(r.ts * 1000)}</span>
                </div>
                <button
                  className="btn"
                  disabled={busyId === r.id}
                  onClick={() => approve(r)}
                >
                  {busyId === r.id ? "Approving…" : "Approve"}
                </button>
              </div>
            ))
          )}
        </div>

        {/* ---- members ---- */}
        <div className="invite-members">
          <div className="mini-label">Members ({members.length})</div>
          {members.map((m) => (
            <div className="member-row" key={m.key}>
              <span className="req-id">{m.key.slice(0, 10)}…</span>
              <span className="chip">{m.role}</span>
              {m.me && <span className="muted">you</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
