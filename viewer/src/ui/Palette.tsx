import { Command } from "cmdk";
import { useMemo } from "react";

import { fuzzyScore } from "../core/fuzzy";
import { formatBinding } from "../core/keys";
import { registry, type Ctx } from "../core/registry";
import { Kbd } from "./primitives";

/**
 * The command palette — a **projection** of the registry, not a menu.
 *
 * It declares no commands and keeps no list: it renders whatever
 * `registry.active(ctx)` returns, so a command contributed by an extension appears
 * here for free, in its group, with its binding.
 *
 * `cmdk` supplies the parts that are tedious to get right and invisible when they
 * are — roving focus, `aria-activedescendant`, scroll-into-view, the listbox
 * semantics. The *ranking* stays ours, via cmdk's `filter` hook: the fuzzy scorer
 * ported from the TUI's palette, so "prefix and word-boundary hits beat scattered
 * subsequences" still holds and stays unit-tested.
 *
 * Note `shouldFilter` is left at its default (true) deliberately. Setting it false
 * does not mean "filter with my `filter`" — it means "the caller filters, cmdk
 * won't", and it makes the `filter` prop dead code. The symptom is a palette that
 * cheerfully shows every command for every query.
 */
export function Palette({ ctx, onClose }: { ctx: Ctx; onClose: () => void }) {
  const results = useMemo(() => {
    // `overlay: true` would hide every command gated on `!overlay` — but those are
    // exactly the ones you opened the palette to run. Rank against the world as it
    // will be once the palette closes, which is the world the user means.
    const active = registry.active({ ...ctx, overlay: false });
    const groups = new Map<string, typeof active>();
    for (const b of active) {
      const g = b.command.group ?? "Other";
      groups.set(g, [...(groups.get(g) ?? []), b]);
    }
    return [...groups.entries()];
  }, [ctx]);

  return (
    <div
      className="fixed inset-0 z-50 flex justify-center bg-black/45 pt-[12vh] backdrop-blur-[2px]"
      onMouseDown={onClose}
    >
      <Command
        label="Command palette"
        loop
        onMouseDown={(e) => e.stopPropagation()}
        className="border-line-strong bg-raised shadow-overlay flex h-fit max-h-[60vh] w-[min(560px,92vw)] flex-col overflow-hidden rounded-lg border"
        filter={score}
      >
        <Command.Input
          autoFocus
          placeholder="Type a command…"
          className="border-line placeholder:text-mute border-b bg-transparent px-4 py-3 text-lg outline-none"
        />
        <Command.List className="overflow-y-auto p-2">
          <Command.Empty className="text-mute p-3">No matching command</Command.Empty>
          {results.map(([group, cmds]) => (
            <Command.Group
              key={group}
              heading={group}
              className="[&_[cmdk-group-heading]]:text-mute [&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-1 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:uppercase"
            >
              {cmds.map((b) => (
                <Command.Item
                  key={b.command.id}
                  value={b.command.title}
                  keywords={[b.command.id]}
                  onSelect={() => {
                    onClose();
                    void b.command.run({ ...ctx, overlay: false });
                  }}
                  className="data-[selected=true]:bg-accent data-[selected=true]:text-accent-fg flex cursor-default items-center gap-3 rounded px-3 py-1.5"
                >
                  <span className="flex-1">{b.command.title}</span>
                  <span className="flex gap-1">
                    {b.bindings.map((k, i) => (
                      <Kbd key={i}>{formatBinding(k, { glyphs: true })}</Kbd>
                    ))}
                  </span>
                </Command.Item>
              ))}
            </Command.Group>
          ))}
        </Command.List>
      </Command>
    </div>
  );
}

/**
 * cmdk's filter contract: return 0 to hide, higher sorts first.
 *
 * Bridges our scorer, whose `null`-means-no-match and unbounded range are not what
 * cmdk expects. An empty search shows everything in registration order (score 1),
 * which is the registry's own `order`-derived shape rather than an alphabetical
 * one nobody asked for.
 */
function score(value: string, search: string, keywords?: string[]): number {
  if (!search.trim()) return 1;
  let best: number | null = null;
  for (const hay of [value, ...(keywords ?? [])]) {
    const s = fuzzyScore(search, hay);
    if (s !== null && (best === null || s > best)) best = s;
  }
  // Shift above zero: a legitimate match can score 0 or less (the length penalty),
  // and 0 means "hide" to cmdk — so a real hit would silently vanish.
  return best === null ? 0 : Math.max(best + 100, 1);
}
