import { RotateCcw, Trash2, X } from "lucide-react";

import type { BulkProgress } from "../core/bulk";
import type { LabelDto, MemberDto, WorkflowState } from "../types";
import { PRIORITY_ORDER } from "../types";
import { Avatar, memberName } from "./Avatar";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { Combobox } from "./Picker";
import { Button, IconButton, Kbd } from "./primitives";

/**
 * The bulk-action bar — appears while any issue carries a check (`x`), floats
 * over the list like Linear's, and vanishes with the last check.
 *
 * Every action here is N ordinary `Request`s, one per checked issue, with only a
 * few in flight at once. The engine's transaction unit remains one intent on one
 * issue, so "set 12 issues to Done" is still twelve honest commits. The bar reports
 * each outcome and retries only failures.
 */
export function BulkBar({
  count,
  progress,
  states,
  labels,
  members,
  onStatus,
  onPriority,
  onLabel,
  onAssign,
  onDelete,
  onRetryFailures,
  onClear,
}: {
  count: number;
  progress: BulkProgress | null;
  states: WorkflowState[];
  labels: LabelDto[];
  members: MemberDto[];
  onStatus: (id: string) => void;
  onPriority: (id: string) => void;
  onLabel: (name: string) => void;
  onAssign: (key: string) => void;
  onDelete: () => void;
  onRetryFailures: () => void;
  onClear: () => void;
}) {
  const pending = progress?.pending === true;
  return (
    <div className="border-line-strong bg-raised shadow-overlay fixed bottom-4 left-1/2 z-40 flex -translate-x-1/2 items-center gap-2 rounded-lg border px-3 py-1.5">
      <span className="text-sm font-medium tabular-nums">{count} selected</span>
      {progress && (
        <>
          <span
            className={progress.failures.length ? "text-danger text-xs" : "text-mute text-xs"}
            role="status"
            aria-live="polite"
            title={progress.failures
              .map((failure) => `${failure.label}: ${failure.message}`)
              .join("\n")}
          >
            {progress.pending
              ? `${progress.done}/${progress.total} complete`
              : progress.failures.length
                ? `${progress.successes.length} succeeded · ${progress.failures.length} failed`
                : `${progress.total} complete`}
          </span>
          {!progress.pending && progress.failures.length > 0 && (
            <Button variant="ghost" onClick={onRetryFailures}>
              <RotateCcw className="size-3" />
              Retry failed
            </Button>
          )}
        </>
      )}
      <span className="bg-line mx-1 h-4 w-px" />

      <Combobox
        label="Status"
        disabled={pending}
        value={null}
        placeholder="Status"
        options={states.map((s) => ({
          id: s.id,
          label: s.name,
          icon: <StatusIcon category={s.category} color={catalogColor(s.color)} />,
        }))}
        onPick={onStatus}
      />
      <Combobox
        label="Priority"
        disabled={pending}
        value={null}
        placeholder="Priority"
        className="capitalize"
        options={[...PRIORITY_ORDER].reverse().map((p) => ({
          id: p,
          label: p,
          icon: <PriorityIcon priority={p} />,
        }))}
        onPick={onPriority}
      />
      <Combobox
        label="Add label"
        disabled={pending}
        value={null}
        placeholder="Label"
        emptyText={labels.length ? "No matches" : "No labels yet"}
        options={labels.map((l) => ({
          id: l.name,
          label: l.name,
          swatch: catalogColor(l.color),
        }))}
        onPick={onLabel}
        onCreate={onLabel}
      />
      <Combobox
        label="Assign"
        disabled={pending}
        value={null}
        placeholder="Assign"
        emptyText={members.length ? "No matches" : "No members yet"}
        options={members.map((m) => ({
          id: m.key,
          label: memberName(m.key, m),
          icon: <Avatar deviceKey={m.key} alias={m.alias} me={m.me} size="sm" />,
          hint: m.key.slice(0, 6),
          keywords: [m.key, m.alias],
        }))}
        onPick={onAssign}
      />

      <IconButton label="Delete selected" variant="danger" disabled={pending} onClick={onDelete}>
        <Trash2 className="size-3.5" />
      </IconButton>

      <span className="bg-line mx-1 h-4 w-px" />
      <IconButton label="Clear selection" chord="Esc" onClick={onClear}>
        <X className="size-3.5" />
      </IconButton>
      <span className="text-mute flex items-center gap-1 text-2xs">
        <Kbd>x</Kbd> toggles
      </span>
    </div>
  );
}
