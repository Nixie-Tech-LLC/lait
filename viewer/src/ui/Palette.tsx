import { useEffect, useMemo, useRef, useState } from "react";

import { rank } from "../core/fuzzy";
import { formatBinding } from "../core/keys";
import { registry, type Ctx } from "../core/registry";

/**
 * The command palette — a **projection** of the registry, not a menu.
 *
 * It declares no commands of its own and has no list to keep in sync: it renders
 * whatever `registry.active(ctx)` returns. A command contributed by an extension
 * shows up here for free, with its binding, in the right group. That is the whole
 * argument for the seam, made visible.
 */
export function Palette({ ctx, onClose }: { ctx: Ctx; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const listId = "palette-list";

  // The palette is opened from a key, so focus must follow without a click.
  useEffect(() => input.current?.focus(), []);

  const results = useMemo(() => {
    // `overlay: true` would hide every command gated on `!overlay` — but those
    // are exactly the ones you opened the palette to run. Rank against the world
    // as it will be once the palette closes, which is the world the user means.
    const active = registry.active({ ...ctx, overlay: false });
    return rank(active, query, (b) => [b.command.title, b.command.id]).slice(0, 12);
  }, [ctx, query]);

  useEffect(() => setSel(0), [query]);

  const run = (i: number) => {
    const hit = results[i];
    if (!hit) return;
    onClose();
    void hit.command.run({ ...ctx, overlay: false });
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    // The palette owns its keys while open — the global driver must not also act
    // on them. Everything here stops here.
    if (e.key === "ArrowDown" || (e.key === "n" && e.ctrlKey)) {
      e.preventDefault();
      e.stopPropagation();
      setSel((s) => Math.min(s + 1, results.length - 1));
    } else if (e.key === "ArrowUp" || (e.key === "p" && e.ctrlKey)) {
      e.preventDefault();
      e.stopPropagation();
      setSel((s) => Math.max(s - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      e.stopPropagation();
      run(sel);
    } else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      onClose();
    }
  };

  return (
    <div className="scrim" onMouseDown={onClose}>
      <div
        className="palette"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <input
          ref={input}
          className="palette__input"
          placeholder="Type a command…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          role="combobox"
          aria-expanded="true"
          aria-controls={listId}
          aria-activedescendant={results[sel] ? `cmd-${results[sel].command.id}` : undefined}
        />
        <ul className="palette__list" id={listId} role="listbox">
          {results.map((b, i) => (
            <li key={b.command.id}>
              <button
                id={`cmd-${b.command.id}`}
                role="option"
                aria-selected={i === sel}
                className="palette__row"
                onMouseEnter={() => setSel(i)}
                onClick={() => run(i)}
              >
                <span className="palette__title">{b.command.title}</span>
                {b.command.group && <span className="palette__group">{b.command.group}</span>}
                <span className="keys">
                  {b.bindings.map((k, j) => (
                    <kbd key={j}>{formatBinding(k, { glyphs: true })}</kbd>
                  ))}
                </span>
              </button>
            </li>
          ))}
          {results.length === 0 && <li className="palette__none">No matching command</li>}
        </ul>
      </div>
    </div>
  );
}
