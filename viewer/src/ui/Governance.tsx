import { useEffect, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { AlertTriangle, ArrowRight, ShieldCheck, X } from "lucide-react";

import { rpc } from "../api";
import type { StatusCategory } from "../types";
import { catalogColor } from "./colors";
import { StatusIcon } from "./icons";
import { IconButton } from "./primitives";

/**
 * The governance viewers — a project's workflow and the space's roles, read-only.
 *
 * These answer the question the errors couldn't: a gated transition refuses with
 * "that change conflicts…" or a demand failure, and until now the browser had no
 * way to see *what the rule was*. `workflow_show` / `role_list` reply as
 * `Response::Text` carrying the same pretty JSON the CLI prints, so this parses
 * that — one source of truth, two renderings.
 *
 * Read-only on purpose. Editing a workflow or a role is a CAS ceremony
 * (`expect_heads` / `expect_revision`) whose conflict flow deserves its own
 * design pass; a half-built editor over signed policy would be worse than the
 * CLI it papers over.
 */

// ---- the wire shapes (defensively partial — parsed from pretty JSON) --------

interface WorkflowStateWire {
  state_id: string;
  name: string;
  category: string;
  color: string;
}

interface WorkflowTransitionWire {
  transition_id: string;
  source_state_ids: string[];
  destination_state_id: string;
  demand_template: DemandWire;
}

type DemandWire =
  | { op: "require"; capability: string; resource: { kind: string } }
  | { op: "all"; children: DemandWire[] }
  | { op: "any"; children: DemandWire[] };

interface WorkflowShowWire {
  project_id: string;
  revision: {
    revision_id: string;
    body: { name: string; states: WorkflowStateWire[]; transitions: WorkflowTransitionWire[] };
  } | null;
  conflict_heads: string[];
}

interface RoleWire {
  role_id: string;
  built_in: boolean;
  revision: {
    revision_id: string;
    body: {
      name: string;
      description: string;
      scope_kind: string;
      capabilities: string[];
    };
  } | null;
  conflict_heads: string[];
}

/** One sentence for a demand template: what the gate asks of the actor. */
function demandPhrase(d: DemandWire): string {
  switch (d.op) {
    case "require":
      return `${d.capability} @ ${d.resource.kind}`;
    case "all":
      return d.children.map(demandPhrase).join(" AND ");
    case "any":
      return d.children.map(demandPhrase).join(" OR ");
  }
}

function Shell({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="ui-overlay fixed inset-0 z-50 bg-black/45 backdrop-blur-[2px]" />
        <Dialog.Content
          aria-describedby={undefined}
          className="ui-surface border-line-strong bg-raised shadow-overlay fixed top-[10vh] left-1/2 z-50 flex max-h-[75vh] w-[min(560px,94vw)] -translate-x-1/2 flex-col overflow-hidden rounded-lg border"
        >
          <header className="border-line flex shrink-0 items-center gap-2 border-b px-4 py-3">
            <Dialog.Title className="font-semibold">{title}</Dialog.Title>
            <Dialog.Close asChild>
              <IconButton label="Close" chord="Esc" className="ml-auto">
                <X className="size-4" />
              </IconButton>
            </Dialog.Close>
          </header>
          <div className="flex flex-col gap-4 overflow-y-auto p-4">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Multiple heads = concurrent edits nobody has resolved; edits are blocked
 *  until `workflow set --expect-head` (or the role equivalent) picks one. */
function ConflictNote({ heads, fix }: { heads: string[]; fix: string }) {
  if (heads.length === 0) return null;
  return (
    <p className="text-warn border-warn/40 flex items-start gap-2 rounded border p-2 text-sm">
      <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
      <span>
        {heads.length} concurrent revisions are unresolved — ordinary edits are blocked until an
        admin runs <code className="font-mono text-xs">{fix}</code>.
      </span>
    </p>
  );
}

export function WorkflowDialog({
  spaceId,
  projectKey,
  onClose,
}: {
  spaceId: string;
  /** The board's project — the workflow shown is this project's. */
  projectKey: string;
  onClose: () => void;
}) {
  const [wf, setWf] = useState<WorkflowShowWire | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    void rpc(spaceId, { cmd: "workflow_show", project: projectKey })
      .then((r) => {
        if (!alive) return;
        if (r.kind === "text") setWf(JSON.parse(r.text) as WorkflowShowWire);
      })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      alive = false;
    };
  }, [spaceId, projectKey]);

  const nameOf = (id: string) =>
    wf?.revision?.body.states.find((s) => s.state_id === id)?.name ?? id;

  return (
    <Shell title={`Workflow — ${projectKey}`} onClose={onClose}>
      {error && <p className="text-danger text-sm">{error}</p>}
      {!wf && !error && <p className="text-mute text-sm">Loading…</p>}
      {wf && (
        <>
          <ConflictNote heads={wf.conflict_heads} fix="lait workflow set --expect-head …" />
          {wf.revision && (
            <>
              <section>
                <h3 className="text-mute mb-2 text-2xs font-semibold tracking-wider uppercase">
                  States
                </h3>
                <ul className="flex flex-col gap-1">
                  {wf.revision.body.states.map((s) => (
                    <li key={s.state_id} className="flex items-center gap-2 text-sm">
                      <StatusIcon
                        category={s.category as StatusCategory}
                        color={catalogColor(s.color)}
                      />
                      <span>{s.name}</span>
                      {s.name.trim().toLowerCase() !== s.category.replaceAll("_", " ") && (
                        <span className="text-mute text-2xs capitalize">
                          {s.category.replaceAll("_", " ")}
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              </section>
              <section>
                <h3 className="text-mute mb-2 text-2xs font-semibold tracking-wider uppercase">
                  Transitions & gates
                </h3>
                <ul className="flex flex-col gap-1.5">
                  {wf.revision.body.transitions.map((t) => (
                    <li key={t.transition_id} className="text-sm">
                      <span className="flex items-center gap-1.5">
                        <span>{t.source_state_ids.map(nameOf).join(", ")}</span>
                        <ArrowRight className="text-mute size-3 shrink-0" />
                        <span>{nameOf(t.destination_state_id)}</span>
                      </span>
                      <span className="text-mute font-mono text-2xs">
                        requires {demandPhrase(t.demand_template)}
                      </span>
                    </li>
                  ))}
                </ul>
              </section>
              <p className="text-mute text-xs">
                Revision <code className="font-mono">{wf.revision.revision_id.slice(0, 12)}…</code>{" "}
                — editable via <code className="font-mono">lait workflow set</code>.
              </p>
            </>
          )}
        </>
      )}
    </Shell>
  );
}

export function RolesDialog({ spaceId, onClose }: { spaceId: string; onClose: () => void }) {
  const [roles, setRoles] = useState<RoleWire[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    void rpc(spaceId, { cmd: "role_list" })
      .then((r) => {
        if (!alive) return;
        if (r.kind === "text") setRoles(JSON.parse(r.text) as RoleWire[]);
      })
      .catch((e) => {
        if (alive) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      alive = false;
    };
  }, [spaceId]);

  return (
    <Shell title="Roles" onClose={onClose}>
      {error && <p className="text-danger text-sm">{error}</p>}
      {!roles && !error && <p className="text-mute text-sm">Loading…</p>}
      {roles?.map((role) => (
        <section key={role.role_id} className="border-line rounded border p-3">
          <div className="flex items-center gap-2">
            <span className="font-medium">{role.revision?.body.name ?? role.role_id}</span>
            {role.built_in && (
              <span className="text-accent flex items-center gap-1 text-2xs" title="Immutable">
                <ShieldCheck className="size-3" />
                built-in
              </span>
            )}
            <span className="text-mute text-2xs capitalize">
              {role.revision?.body.scope_kind ?? ""}
            </span>
          </div>
          {role.revision?.body.description && (
            <p className="text-dim mt-1 text-sm">{role.revision.body.description}</p>
          )}
          <ConflictNote heads={role.conflict_heads} fix="lait role resolve …" />
          <ul className="mt-2 flex flex-wrap gap-1">
            {(role.revision?.body.capabilities ?? []).map((c) => (
              <li
                key={c}
                className="border-line-strong text-dim rounded-full border px-2 py-px font-mono text-2xs"
              >
                {c}
              </li>
            ))}
          </ul>
        </section>
      ))}
      {roles && (
        <p className="text-mute text-xs">
          Custom roles are managed via <code className="font-mono">lait role create/edit</code>.
        </p>
      )}
    </Shell>
  );
}
