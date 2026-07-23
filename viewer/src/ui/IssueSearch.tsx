import { Command } from "cmdk";
import { Clock3, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { rpc } from "../api";
import { cmdkFilter } from "../core/fuzzy";
import { loadRecentIssues, rememberRecentIssue } from "../core/personalNav";
import type { ProjectDto, Row, WorkflowState } from "../types";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { Kbd } from "./primitives";
import { useReturnFocus } from "./useReturnFocus";

export function rememberIssue(spaceId: string, reff: string): void {
  rememberRecentIssue(spaceId, reff);
}

export function IssueSearch({
  spaceId,
  rpcSpaceId,
  rows,
  projects,
  states,
  onOpen,
  onClose,
}: {
  spaceId: string;
  rpcSpaceId: string;
  rows: Row[];
  projects: ProjectDto[];
  states: WorkflowState[];
  onOpen: (row: Row) => void;
  onClose: () => void;
}) {
  useReturnFocus();
  const [available, setAvailable] = useState(rows);
  const [query, setQuery] = useState("");
  useEffect(() => {
    let alive = true;
    void Promise.allSettled(
      projects.map((project) =>
        rpc(rpcSpaceId, { cmd: "board", project: project.key }),
      ),
    ).then((replies) => {
      if (!alive) return;
      const merged = new Map<string, Row>();
      for (const result of replies) {
        if (result.status !== "fulfilled" || result.value.kind !== "board") continue;
        for (const column of result.value.columns) {
          for (const row of column.rows) {
            if (!row.tombstone) merged.set(row.reff, row);
          }
        }
      }
      if (merged.size) {
        setAvailable([...merged.values()]);
      }
    }).catch(() => {
      // The active board remains a useful, honest subset when every broader
      // projection is unavailable.
    });
    return () => {
      alive = false;
    };
  }, [rpcSpaceId, projects]);

  const recents = useMemo(() => {
    const byRef = new Map(available.map((row) => [row.reff, row]));
    return loadRecentIssues(spaceId).flatMap((reff) => {
      const row = byRef.get(reff);
      return row ? [row] : [];
    });
  }, [spaceId, available]);
  const results = useMemo(() => {
    const text = query.trim();
    if (!text) return available;
    return available
      .map((row) => ({
        row,
        score: cmdkFilter(row.key_alias ?? row.reff, text, [
          row.title,
          row.reff,
          row.project_id,
          row.status,
        ]),
      }))
      .filter(({ score }) => score > 0)
      .sort((a, b) => b.score - a.score)
      .map(({ row }) => row);
  }, [available, query]);

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
        shouldFilter={false}
        onMouseDown={(event) => event.stopPropagation()}
        className="ui-surface border-line-strong bg-raised shadow-overlay flex h-fit max-h-[70vh] w-[min(680px,94vw)] flex-col overflow-hidden rounded-lg border"
      >
        <div className="border-line flex items-center gap-3 border-b px-4">
          <Search className="text-mute size-4" />
          <Command.Input
            autoFocus
            value={query}
            onValueChange={setQuery}
            placeholder="Search issues by title, reference, project, or status…"
            className="placeholder:text-mute min-w-0 flex-1 bg-transparent py-3 text-lg outline-none"
          />
          <Kbd>Esc</Kbd>
        </div>
        <Command.List className="overflow-y-auto p-2">
          {results.length === 0 && (
            <div className="text-mute p-8 text-center">
              <p>No issue matches “{query.trim()}”.</p>
              <p className="mt-1 text-xs">Try a title, identifier, project, or status.</p>
            </div>
          )}
          {!query.trim() && recents.length > 0 && (
            <Command.Group heading="Recent" className="[&_[cmdk-group-heading]]:text-mute [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase">
              {recents.map((row) => <IssueResult key={`recent-${row.reff}`} row={row} recent projects={projects} states={states} onOpen={choose} />)}
            </Command.Group>
          )}
          <Command.Group heading={query.trim() ? `${results.length} results` : "All issues"} className="[&_[cmdk-group-heading]]:text-mute [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase">
            {results.map((row) => <IssueResult key={row.reff} row={row} projects={projects} states={states} onOpen={choose} />)}
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}

function IssueResult({ row, recent, projects, states, onOpen }: { row: Row; recent?: boolean; projects: ProjectDto[]; states: WorkflowState[]; onOpen: (reff: string) => void }) {
  const project = projects.find((candidate) => candidate.id === row.project_id);
  const state = states.find((candidate) => candidate.id === row.status);
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
      {project && <span className="text-mute shrink-0 text-xs">{project.key}</span>}
      {state && (
        <span className="text-mute flex shrink-0 items-center gap-1 text-xs">
          <StatusIcon category={state.category} color={catalogColor(state.color)} />
          {state.name}
        </span>
      )}
      {row.provisional && <span className="text-warn text-2xs">arriving</span>}
    </Command.Item>
  );
}
