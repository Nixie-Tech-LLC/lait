import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import { Check, Copy, KeyRound, Link2, Pencil, ShieldCheck, UserPlus, X } from "lucide-react";

import { ConfirmRequired, rpc } from "../api";
import type { JoinRequestDto, MemberDto } from "../types";
import { when } from "./time";

/**
 * Members, join requests, and the invite link.
 *
 * The rule this screen exists to enforce, straight from the CLI: **the key is
 * authenticated; the nick is a self-asserted claim.** You approve by key, having
 * confirmed it out-of-band — so the key is what this shows first, in mono, at full
 * scannable width, and the nick is labelled as the claim it is. A UI that led with
 * the nick would be inviting exactly the mistake the ACL cannot catch.
 *
 * Roles come from the signed ACL graph — the only cryptographically-verified
 * identity in the system. Admin-only actions are hidden for non-admins rather than
 * offered and rejected.
 */
export function Members({
  spaceId,
  revision,
  readOnly,
  onError,
}: {
  spaceId: string;
  revision: number;
  readOnly: boolean;
  onError: (m: string) => void;
}) {
  const [members, setMembers] = useState<MemberDto[]>([]);
  const [requests, setRequests] = useState<JoinRequestDto[]>([]);
  const [ticket, setTicket] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const m = await rpc(spaceId, { cmd: "members" });
      if (m.kind === "members") setMembers(m.members);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
      return;
    }
    try {
      const r = await rpc(spaceId, { cmd: "member_requests" });
      if (r.kind === "join_requests") setRequests(r.requests);
    } catch {
      // A non-admin can't list requests, and that's not an error worth shouting
      // about — they simply don't get the section.
      setRequests([]);
    }
  }, [spaceId, onError]);

  useEffect(() => {
    void load();
  }, [load, revision]);

  const isAdmin = members.some((m) => m.me && m.role === "admin");

  const act = async (id: string, fn: () => Promise<unknown>) => {
    setBusy(id);
    try {
      await fn();
      await load();
    } catch (e) {
      // A destructive verb comes back as the CLI's own question; if the human
      // says no, that is an answer, not a failure.
      if (!(e instanceof ConfirmRequired)) {
        onError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto flex max-w-2xl flex-col gap-6 p-6">
        {requests.length > 0 && isAdmin && !readOnly && (
          <section>
            <h2 className="text-mute mb-1 text-2xs font-semibold tracking-wider uppercase">
              Pending · {requests.length}
            </h2>
            {/* The one sentence that keeps this screen honest. */}
            <p className="text-warn mb-2 text-sm">
              Approve by key — confirm it out-of-band. The nick is an unverified claim.
            </p>
            <ul className="border-line divide-line divide-y rounded border">
              {requests.map((r) => (
                <li key={r.key} className="flex items-center gap-3 p-3">
                  <span className="min-w-0 flex-1">
                    {/* Key first, full width, mono: it is the thing you verify. */}
                    <code className="block truncate text-xs">{r.key}</code>
                    <span className="text-mute text-xs">
                      claims to be “{r.nick || "—"}” · {when(r.ts)}
                    </span>
                  </span>
                  <button
                    disabled={busy === r.key}
                    onClick={() =>
                      void act(r.key, async () => {
                        const as = window.prompt(
                          `Approve ${r.key.slice(0, 12)}…\n\nOptional local name for this key (private to you):`,
                          r.nick,
                        );
                        // Cancel means cancel — an empty string is a deliberate
                        // "no petname", null is "I changed my mind".
                        if (as === null) return;
                        await rpc(spaceId, {
                          cmd: "member_approve",
                          who: r.key,
                          as_name: as.trim() || null,
                        });
                      })
                    }
                    className="border-line-strong hover:bg-hover flex shrink-0 items-center gap-1.5 rounded border px-2 py-1 text-sm font-medium disabled:opacity-50"
                  >
                    <Check className="size-3.5" />
                    Approve
                  </button>
                </li>
              ))}
            </ul>
          </section>
        )}

        <section>
          <h2 className="text-mute mb-2 text-2xs font-semibold tracking-wider uppercase">
            Members · {members.length}
          </h2>
          <ul className="border-line divide-line divide-y rounded border">
            {members.map((m) => (
              <li key={m.key} className="flex items-center gap-3 p-3">
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2">
                    <span className="font-medium">
                      {m.alias || <span className="text-mute italic">unnamed</span>}
                    </span>
                    {m.me && <span className="text-mute text-2xs">you</span>}
                    {m.role === "admin" && (
                      <span
                        className="text-accent flex items-center gap-1 text-2xs"
                        title="From the signed ACL graph"
                      >
                        <ShieldCheck className="size-3" />
                        admin
                      </span>
                    )}
                  </span>
                  <code className="text-mute block truncate text-xs">{m.key}</code>
                </span>
                {isAdmin && !readOnly && (
                  <span className="flex shrink-0 gap-1">
                    <IconButton
                      label="Set a local name"
                      onClick={() =>
                        void act(m.key, async () => {
                          const name = window.prompt(
                            "Local name for this key (private to you; empty clears):",
                            m.alias,
                          );
                          if (name === null) return;
                          await rpc(spaceId, { cmd: "member_alias", who: m.key, name: name.trim() });
                        })
                      }
                    >
                      <Pencil className="size-3.5" />
                    </IconButton>
                    {!m.me && (
                      <IconButton
                        label="Remove (rotates the space key)"
                        danger
                        onClick={() =>
                          void act(m.key, async () => {
                            try {
                              await rpc(spaceId, { cmd: "member_remove", who: m.key });
                            } catch (e) {
                              // The engine hands back its own question — removing
                              // rotates the space key, and it says so.
                              if (e instanceof ConfirmRequired) {
                                if (window.confirm(e.question)) {
                                  await rpc(
                                    spaceId,
                                    { cmd: "member_remove", who: m.key },
                                    { confirm: true },
                                  );
                                }
                                return;
                              }
                              throw e;
                            }
                          })
                        }
                      >
                        <X className="size-3.5" />
                      </IconButton>
                    )}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </section>

        {isAdmin && !readOnly && (
          <Invite spaceId={spaceId} ticket={ticket} setTicket={setTicket} onError={onError} />
        )}
      </div>
    </div>
  );
}

function IconButton({
  label,
  onClick,
  danger,
  children,
}: {
  label: string;
  onClick: () => void;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      aria-label={label}
      className={`grid size-6 place-items-center rounded ${
        danger ? "text-mute hover:text-danger" : "text-mute hover:text-fg"
      } hover:bg-hover`}
    >
      {children}
    </button>
  );
}

/**
 * The invite surface.
 *
 * `invite --json` returns the bare **ticket**; the `lait://join/…` link is derived
 * from it. The default pass auto-admits — the joiner runs `lait join <link>` and is
 * in, no approve step — so the copy says that rather than describing the old
 * approval-gated flow. `--require-approval` is the opt-in that makes the Pending
 * section above mean something.
 */
function Invite({
  spaceId,
  ticket,
  setTicket,
  onError,
}: {
  spaceId: string;
  ticket: string | null;
  setTicket: (t: string | null) => void;
  onError: (m: string) => void;
}) {
  const [qr, setQr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [approval, setApproval] = useState(false);

  const link = ticket ? `lait://join/${ticket}` : null;

  useEffect(() => {
    if (!link) return setQr(null);
    // Rendered locally. A remote QR service would mean handing an invite ticket —
    // which admits someone to an E2EE workspace — to a third party.
    void QRCode.toDataURL(link, { margin: 1, width: 220, errorCorrectionLevel: "L" })
      .then(setQr)
      .catch(() => setQr(null));
  }, [link]);

  const mint = async () => {
    try {
      const r = await rpc(spaceId, { cmd: "invite", require_approval: approval });
      if (r.kind === "text") setTicket(r.text.trim());
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section>
      <h2 className="text-mute mb-2 text-2xs font-semibold tracking-wider uppercase">Invite</h2>
      <div className="border-line flex flex-col gap-3 rounded border p-3">
        {!link ? (
          <>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={approval}
                onChange={(e) => setApproval(e.target.checked)}
              />
              Require my approval
              <span className="text-mute">
                — otherwise the link admits them automatically
              </span>
            </label>
            <button
              onClick={() => void mint()}
              className="border-line-strong hover:bg-hover flex w-fit items-center gap-1.5 rounded border px-2 py-1 font-medium"
            >
              <UserPlus className="size-3.5" />
              Create invite link
            </button>
          </>
        ) : (
          <>
            <div className="flex gap-4">
              {qr && (
                <img
                  src={qr}
                  alt="Invite link QR code"
                  className="size-[110px] shrink-0 rounded bg-white p-1"
                />
              )}
              <div className="flex min-w-0 flex-1 flex-col gap-2">
                <p className="text-dim text-sm">
                  {approval
                    ? "They’ll appear above as a pending request to approve."
                    : "They run this and they’re in — no approve step."}
                </p>
                <code className="bg-bg border-line block truncate rounded border p-2 text-xs">
                  lait join {link}
                </code>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      void navigator.clipboard.writeText(link).then(() => {
                        setCopied(true);
                        window.setTimeout(() => setCopied(false), 1500);
                      });
                    }}
                    className="border-line-strong hover:bg-hover flex items-center gap-1.5 rounded border px-2 py-1 text-sm"
                  >
                    {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
                    {copied ? "Copied" : "Copy link"}
                  </button>
                  <a
                    href={mailto(link)}
                    className="border-line-strong hover:bg-hover flex items-center gap-1.5 rounded border px-2 py-1 text-sm"
                  >
                    <Link2 className="size-3.5" />
                    Email it
                  </a>
                  <button
                    onClick={() => setTicket(null)}
                    className="text-mute hover:text-fg ml-auto flex items-center gap-1.5 text-sm"
                  >
                    <KeyRound className="size-3.5" />
                    New link
                  </button>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

/** A prefilled mail draft — no SMTP, no app password: it opens their mail client. */
function mailto(link: string): string {
  const body = [
    "You've been invited to a lait space.",
    "",
    "1. Install lait:  https://github.com/Nixie-Tech-LLC/lait",
    "2. Join:",
    `   lait join ${link}`,
    "",
    "That's it — it creates your store and syncs you in.",
  ].join("\n");
  return `mailto:?subject=${encodeURIComponent("Join my lait space")}&body=${encodeURIComponent(body)}`;
}
