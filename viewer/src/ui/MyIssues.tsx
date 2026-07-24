import { useEffect, useState } from "react";
import { CircleDot } from "lucide-react";

import { rpc } from "../api";
import type { Row } from "../types";
import { EmptyState, LoadingState } from "./AppState";
import { interactiveRow } from "./primitives";

/** A workspace-level projection of everything assigned to the current actor.
 * Opening a row enters its owning project; the destination never silently
 * inherits whichever project happened to be open before this page. */
export function MyIssues({
  spaceId,
  revision,
  onOpen,
  onError,
}: {
  spaceId: string;
  revision: number;
  onOpen: (reff: string) => void;
  onError: (message: string) => void;
}) {
  const [rows, setRows] = useState<Row[] | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const result = await rpc(spaceId, {
          cmd: "list",
          project: null,
          filter: { mine: true, all: true },
        });
        if (alive && result.kind === "list") {
          setRows(result.rows.filter((row) => !row.tombstone));
        }
      } catch (error) {
        if (alive) onError(error instanceof Error ? error.message : String(error));
      }
    })();
    return () => {
      alive = false;
    };
  }, [spaceId, revision, onError]);

  if (rows === null) {
    return <LoadingState title="Loading your issues" body="Reading assignments across this workspace." />;
  }
  if (rows.length === 0) {
    return (
      <EmptyState
        icon={<CircleDot className="size-5" />}
        title="No issues assigned to you"
        body="Issues assigned to you across every project will appear here."
      />
    );
  }

  return (
    <ul className="min-h-0 flex-1 overflow-y-auto">
      {rows.map((row) => (
        <li key={row.reff}>
          <button
            type="button"
            className={`${interactiveRow({ density: "normal" })} flex w-full items-center gap-3 px-4 py-2 text-left`}
            onClick={() => onOpen(row.key_alias ?? row.reff)}
          >
            <span className="text-mute w-20 shrink-0 truncate font-mono text-xs tabular-nums">
              {row.key_alias ?? row.reff}
            </span>
            <span className="min-w-0 flex-1 truncate text-sm">{row.title}</span>
            <span className="text-mute shrink-0 text-xs capitalize">{row.priority}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}
