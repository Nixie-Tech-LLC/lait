import { useMemo } from "react";

import { formatBinding } from "../core/keys";
import { registry, type Bound, type Ctx } from "../core/registry";

/**
 * The `?` overlay — the second projection of the registry.
 *
 * The TUI's rule, kept: **everything appears here.** The legend is a filter; this
 * is not. A binding that exists but is undocumented is a binding nobody uses, and
 * keeping this list by hand is how it would drift out of date by Tuesday.
 *
 * Unbound commands are shown too. They are real — the palette can run them — and
 * a blank key column is exactly the invitation to rebind one.
 */
export function Shortcuts({ ctx, onClose }: { ctx: Ctx; onClose: () => void }) {
  const groups = useMemo(() => {
    // Ignore the overlay gate: this list documents the app, not this instant.
    const all = registry.active({ ...ctx, overlay: false });
    const by = new Map<string, Bound[]>();
    for (const b of all) {
      const g = b.command.group ?? "Other";
      by.set(g, [...(by.get(g) ?? []), b]);
    }
    return [...by.entries()];
  }, [ctx]);

  const warnings = registry.warnings;

  return (
    <div className="scrim" onMouseDown={onClose}>
      <div
        className="sheet"
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <header className="sheet__head">
          <h2>Keyboard shortcuts</h2>
          <button className="link" onClick={onClose}>
            close
          </button>
        </header>

        {warnings.length > 0 && (
          // Overrides warn and never gate, so a bad one is invisible unless we
          // say so — and the one place a user looks for key trouble is here.
          <ul className="sheet__warn">
            {warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        )}

        <div className="sheet__body">
          {groups.map(([group, cmds]) => (
            <section key={group}>
              <h3 className="eyebrow">{group}</h3>
              <ul className="shortcuts">
                {cmds.map((b) => (
                  <li key={b.command.id}>
                    <span>{b.command.title}</span>
                    <span className="keys">
                      {b.bindings.map((k, i) => (
                        <kbd key={i}>{formatBinding(k, { glyphs: true })}</kbd>
                      ))}
                    </span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
