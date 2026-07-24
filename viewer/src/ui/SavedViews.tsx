import * as Popover from "@radix-ui/react-popover";
import { Bookmark, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import type { DisplayState } from "../core/display";
import type { FilterState } from "../core/filter";
import type { WorkView } from "../core/registry";
import { loadSavedViews, removeView, saveView, type SavedView } from "../core/savedViews";
import { Button, IconButton, Input, navigationItem, PopoverContent } from "./primitives";

export function SavedViews({ space, project, view, filter, display, onApply, onChange }: { space: string; project: string; view: WorkView; filter: FilterState; display: DisplayState; onApply: (view: SavedView) => void; onChange?: () => void }) {
  const [views, setViews] = useState(() => loadSavedViews(space, project));
  const [name, setName] = useState("");

  useEffect(() => setViews(loadSavedViews(space, project)), [space, project]);

  const create = () => {
    const title = name.trim();
    if (!title) return;
    const id = `${Date.now().toString(36)}-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    setViews(saveView(space, project, { id, name: title, filter, display, view }));
    onChange?.();
    setName("");
  };

  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <IconButton label="Local saved views">
          <Bookmark className="size-4" />
        </IconButton>
      </Popover.Trigger>
      <PopoverContent align="end" className="w-72 p-2">
          <div className="mb-2 px-1">
            <p className="font-semibold">Saved views</p>
            <p className="text-mute text-xs">Private to this browser and local space.</p>
          </div>
          {views.length === 0 ? (
            <p className="text-mute px-2 py-3 text-center text-sm">No saved views yet.</p>
          ) : (
            <div className="mb-2 flex max-h-52 flex-col gap-px overflow-y-auto">
              {views.map((view) => (
                <div key={view.id} className="group/view relative">
                  <button onClick={() => onApply(view)} className={`${navigationItem()} pr-8`}>{view.name}</button>
                  <IconButton label={`Delete ${view.name}`} className="absolute top-0.5 right-0.5 opacity-0 group-hover/view:opacity-100 focus-visible:opacity-100" onClick={() => { setViews(removeView(space, project, view.id)); onChange?.(); }}>
                    <Trash2 className="size-3" />
                  </IconButton>
                </div>
              ))}
            </div>
          )}
          <div className="border-line flex items-center gap-1 border-t pt-2">
            <Input size="sm" value={name} onChange={(event) => setName(event.target.value)} onKeyDown={(event) => event.key === "Enter" && create()} placeholder="Name this view…" className="min-w-0 flex-1" />
            <Button variant="outline" disabled={!name.trim()} onClick={create}>
              <Plus className="size-3" /> Save
            </Button>
          </div>
      </PopoverContent>
    </Popover.Root>
  );
}
