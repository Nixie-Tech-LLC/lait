import { Command } from "cmdk";
import { Clock3, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { rpc } from "../api";
import { cmdkFilter } from "../core/fuzzy";
import { loadRecentIssues, rememberRecentIssue } from "../core/personalNav";
import type { Row } from "../types";
import { PriorityIcon } from "./icons";
import { Kbd } from "./primitives";

export function rememberIssue(spaceId: string, reff: string): void {
  rememberRecentIssue(spaceId, reff);
}

export function IssueSearch({
  spaceId,
  rpcSpaceId,
  rows,
  onOpen,
  onClose,
}: {
  spaceId: string;
  rpcSpaceId: string;
  rows: Row[];
  onOpen: (row: Row) => void;
  onClose: () => void;
}) {
  const [available, setAvailable] = useState(rows);
  useEffect(() => {
    let alive = true;
    void rpc(rpcSpaceId, { cmd: "list", project: null, filter: { all: true } })
      .then((reply) => {
        if (alive && reply.kind === "list") {
          setAvailable(reply.rows.filter((row) => !row.tombstone));
        }
      })
      .catch(() => {
        // The active board remains a useful, honest subset when the broader
        // projection is unavailable.
      });
    return () => {
      alive = false;
    };
  }, [rpcSpaceId]);

  const recents = useMemo(() => {
    const byRef = new Map(available.map((row) => [row.reff, row]));
    return loadRecentIssues(spaceId).flatMap((reff) => {
      const row = byRef.get(reff);
      return row ? [row] : [];
    });
  }, [spaceId, available]);

  const choose = (reff: string) => {
    const row = available.find((candidate) => candidate.reff === reff);
    if (!row) return;
    rememberIssue(spaceId, reff);
    onClose();
    onOpen(row);
  };

  return (
    <div className="ui-overlay fixed inset-0 z-50 flex justify-center bg-black/45 pt-[10vh] backdrop-blur-[2px]" onMouseDown={onClose}>
      <Command
        label="Search issues"
        loop
        filter={cmdkFilter}
        onMouseDown={(event) => event.stopPropagation()}
        className="ui-surface border-line-strong bg-raised shadow-overlay flex h-fit max-h-[70vh] w-[min(680px,94vw)] flex-col overflow-hidden rounded-lg border"
      >
        <div className="border-line flex items-center gap-3 border-b px-4">
          <Search className="text-mute size-4" />
          <Command.Input autoFocus placeholder="Search issues by title or reference…" className="placeholder:text-mute min-w-0 flex-1 bg-transparent py-3 text-lg outline-none" />
          <Kbd>Esc</Kbd>
        </div>
        <Command.List className="overflow-y-auto p-2">
          <Command.Empty className="text-mute p-8 text-center">No issue matches this search.</Command.Empty>
          {recents.length > 0 && (
            <Command.Group heading="Recent" className="[&_[cmdk-group-heading]]:text-mute [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase">
              {recents.map((row) => <IssueResult key={`recent-${row.reff}`} row={row} recent onOpen={choose} />)}
            </Command.Group>
          )}
          <Command.Group heading="All issues" className="[&_[cmdk-group-heading]]:text-mute [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase">
            {available.map((row) => <IssueResult key={row.reff} row={row} onOpen={choose} />)}
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}

function IssueResult({ row, recent, onOpen }: { row: Row; recent?: boolean; onOpen: (reff: string) => void }) {
  return (
    <Command.Item
      value={row.reff}
      keywords={[row.title, row.key_alias ?? "", row.project_id]}
      onSelect={() => onOpen(row.reff)}
      className="data-[selected=true]:bg-hover flex cursor-default items-center gap-3 rounded px-2 py-1.5"
    >
      {recent ? <Clock3 className="text-mute size-3.5" /> : <PriorityIcon priority={row.priority} />}
      <span className="text-mute w-20 shrink-0 truncate font-mono text-xs">{row.key_alias ?? row.reff}</span>
      <span className="min-w-0 flex-1 truncate">{row.title}</span>
      {row.provisional && <span className="text-warn text-2xs">arriving</span>}
    </Command.Item>
  );
}
