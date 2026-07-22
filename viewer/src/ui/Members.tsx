import { useCallback, useEffect, useState } from "react";
import QRCode from "qrcode";
import {
  Check,
  Copy,
  KeyRound,
  Link2,
  Pencil,
  ShieldAlert,
  ShieldCheck,
  UserPlus,
  X,
} from "lucide-react";

import { ConfirmRequired, rpc } from "../api";
import type { MemberDto, MemberLogEntry } from "../types";
import { memberName } from "./Avatar";
import * as ask from "./dialogs";
import { Button, IconButton } from "./primitives";

/**
 * Members and the invite link. Admission needs no controls here: accepting an
 * invite IS the approval, and redemption is automatic on the next contact.
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
  const [log, setLog] = useState<MemberLogEntry[]>([]);
  const [ticket, setTicket] = useState<string | null>(null);
  const [, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const m = await rpc(spaceId, { cmd: "members" });
      if (m.kind === "members") setMembers(m.members);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
      return;
    }
    try {
      const l = await rpc(spaceId, { cmd: "member_log" });
      if (l.kind === "member_log") setLog(l.entries);
    } catch {
      // The audit log is a nicety, not load-bearing for the roster; a failure just
      // hides the section rather than breaking the page.
      setLog([]);
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
                          const name = await ask.prompt({
                            title: "Local name",
                            body: "Private to you, never synced. Empty clears it.",
                            label: "Name",
                            defaultValue: m.alias,
                            allowEmpty: true,
                          });
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
                        variant="danger"
                        onClick={() =>
                          void act(m.key, async () => {
                            try {
                              await rpc(spaceId, { cmd: "member_remove", who: m.key });
                            } catch (e) {
                              // The engine hands back its own question — removing
                              // rotates the space key, and it says so.
                              if (e instanceof ConfirmRequired) {
                                if (
                                  await ask.confirm({
                                    title: e.question,
                                    confirmText: "Remove",
                                    danger: true,
                                  })
                                ) {
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

        {log.length > 0 && <MemberLog entries={log} members={members} />}
      </div>
    </div>
  );
}

/**
 * The membership audit log.
 *
 * The one feed in lait whose author is **cryptographically verified**: `actor`
 * signed the op, and the signature covers it (unlike in-doc activity, which is
 * advisory). That is why it belongs here and not in the activity feed — it is the
 * record of who changed *access*, which is exactly the thing you want to be sure of.
 *
 * An `authorized: false` row is shown, not hidden. A rejected op is a real event —
 * someone tried something the ACL refused — and quietly dropping it would defeat the
 * point of having an audit trail at all.
 */
function MemberLog({ entries, members }: { entries: MemberLogEntry[]; members: MemberDto[] }) {
  const name = (key: string) => memberName(key, members.find((m) => m.key === key));
  const PHRASE: Record<string, string> = {
    add_member: "added",
    remove_member: "removed",
    set_role: "set the role of",
    add_agent: "sponsored agent",
    unknown: "(unrecognized op)",
  };

  return (
    <section>
      <h2 className="text-mute mb-2 text-2xs font-semibold tracking-wider uppercase">
        Access log · {entries.length}
      </h2>
      <ul className="border-line divide-line divide-y rounded border">
        {/* Newest first — an audit log answers "what just changed access". */}
        {[...entries].reverse().map((e) => (
          <li key={e.op} className="flex items-center gap-2 p-2.5 text-sm">
            <span className="min-w-0 flex-1">
              <span className="font-medium">{name(e.actor)}</span>{" "}
              <span className="text-dim">{PHRASE[e.kind] ?? e.kind}</span>
              {e.subject && <span className="font-medium"> {name(e.subject)}</span>}
              {e.role && <span className="text-mute"> as {e.role}</span>}
            </span>
            {!e.authorized && (
              <span
                className="text-danger flex items-center gap-1 text-2xs"
                title="Replay rejected this op as unauthorized or undecodable"
              >
                <ShieldAlert className="size-3" />
                rejected
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * The invite surface.
 *
 * `invite --json` returns the bare **link body**; the `lait://join/…` link is
 * derived from it. The capability always auto-admits — the joiner runs
 * `lait join <link>` and is in; accepting the invite is the approval.
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

  const link = ticket ? `lait://join/${ticket}` : null;

  useEffect(() => {
    if (!link) return setQr(null);
    // Rendered locally. A remote QR service would mean handing an invite ticket —
    // which admits someone to an E2EE space — to a third party.
    void QRCode.toDataURL(link, { margin: 1, width: 220, errorCorrectionLevel: "L" })
      .then(setQr)
      .catch(() => setQr(null));
  }, [link]);

  const mint = async () => {
    try {
      const r = await rpc(spaceId, { cmd: "invite" });
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
          <Button variant="outline" size="md" onClick={() => void mint()} className="w-fit">
            <UserPlus className="size-3.5" />
            Create invite link
          </Button>
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
                  They run this and they’re in — accepting the invite is the approval.
                </p>
                <code className="bg-bg border-line block truncate rounded border p-2 text-xs">
                  lait join {link}
                </code>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    onClick={() => {
                      void navigator.clipboard.writeText(link).then(() => {
                        setCopied(true);
                        window.setTimeout(() => setCopied(false), 1500);
                      });
                    }}
                  >
                    {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
                    {copied ? "Copied" : "Copy link"}
                  </Button>
                  <a
                    href={mailto(link)}
                    className="border-line-strong hover:bg-hover flex items-center gap-1.5 rounded border px-2 py-1 text-sm"
                  >
                    <Link2 className="size-3.5" />
                    Email it
                  </a>
                  <Button onClick={() => setTicket(null)} className="ml-auto">
                    <KeyRound className="size-3.5" />
                    New link
                  </Button>
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
