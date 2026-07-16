import { useMemo } from "react";
import { X } from "lucide-react";

import { formatBinding } from "../core/keys";
import { registry, type Bound, type Ctx } from "../core/registry";
import { IconButton, Kbd } from "./primitives";

/**
 * The `?` overlay — the registry's second projection.
 *
 * The TUI's rule, kept: **everything appears here.** A legend can filter; this
 * cannot. A binding that exists but is undocumented is a binding nobody uses, and
 * a hand-maintained list of them is out of date by Tuesday.
 *
 * Unbound commands are listed too, with an empty key column. They are real — the
 * palette runs them — and the gap is the invitation to rebind one.
 */
export function Shortcuts({ ctx, onClose }: { ctx: Ctx; onClose: () => void }) {
  const groups = useMemo(() => {
    // Ignore the overlay gate: this documents the app, not this instant.
    const all = registry.active({ ...ctx, overlay: false });
    const by = new Map<string, Bound[]>();
    for (const b of all) by.set(b.command.group ?? "Other", [...(by.get(b.command.group ?? "Other") ?? []), b]);
    return [...by.entries()];
  }, [ctx]);

  return (
    <div
      className="fixed inset-0 z-50 flex justify-center bg-black/45 pt-[10vh] backdrop-blur-[2px]"
      onMouseDown={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        onMouseDown={(e) => e.stopPropagation()}
        className="border-line-strong bg-raised shadow-overlay flex max-h-[70vh] w-[min(560px,92vw)] flex-col overflow-hidden rounded-lg border"
      >
        <header className="border-line flex items-center border-b px-4 py-3">
          <h2 className="flex-1 text-lg font-semibold">Keyboard shortcuts</h2>
          <IconButton label="Close" chord="Esc" onClick={onClose}>
            <X className="size-4" />
          </IconButton>
        </header>

        {registry.warnings.length > 0 && (
          // Overrides warn and never gate, so a broken one is invisible unless we
          // say so — and this is the one place a user looks for key trouble.
          <ul className="border-line bg-warn/10 text-warn border-b px-4 py-2 text-sm">
            {registry.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        )}

        <div className="overflow-y-auto p-2">
          {groups.map(([group, cmds]) => (
            <section key={group} className="mb-2">
              <h3 className="text-mute px-3 py-1 text-2xs font-semibold tracking-wider uppercase">
                {group}
              </h3>
              <ul>
                {cmds.map((b) => (
                  <li key={b.command.id} className="flex items-center gap-3 px-3 py-1">
                    <span className="flex-1">{b.command.title}</span>
                    <span className="flex gap-1">
                      {b.bindings.map((k, i) => (
                        <Kbd key={i}>{formatBinding(k, { glyphs: true })}</Kbd>
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
