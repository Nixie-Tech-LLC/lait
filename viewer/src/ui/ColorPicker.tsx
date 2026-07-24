import { Check } from "lucide-react";

import { CATALOG_COLORS, catalogColor } from "./colors";
import { cn } from "./primitives";

/**
 * A swatch grid over the catalog colours — the piece that was simply missing.
 *
 * The viewer rendered `catalogColor()` swatches everywhere but gave no way to
 * *choose* one: a new project took the default colour, and a label minted on the
 * fly was gray forever. This is the chooser. It offers only the designed catalog
 * names (never a free hex or a colour wheel) for the same reason `colors.ts`
 * refuses `color: blue` — a colour outside the palette is one we cannot promise
 * contrast for, in either theme.
 *
 * It is deliberately a plain fieldset of buttons, not a popover: it is always shown
 * inside a surface that is already floating (a dialog, a popover), and a menu inside
 * a menu is a trap. The caller decides where it sits; this only draws the swatches.
 */
export function ColorPicker({
  value,
  onChange,
  className,
}: {
  value: string;
  onChange: (name: string) => void;
  className?: string;
}) {
  return (
    <div role="radiogroup" aria-label="Colour" className={cn("flex flex-wrap gap-1.5", className)}>
      {CATALOG_COLORS.map((name) => {
        const selected = value.trim().toLowerCase() === name;
        return (
          <button
            key={name}
            type="button"
            role="radio"
            aria-checked={selected}
            aria-label={name}
            title={name}
            onClick={() => onChange(name)}
            className={cn(
              "flex size-6 items-center justify-center rounded-full ring-offset-2 ring-offset-[var(--color-raised)] transition-[box-shadow]",
              selected ? "ring-fg ring-2" : "hover:ring-line-strong hover:ring-2",
            )}
            style={{ background: catalogColor(name) }}
          >
            {selected && <Check className="size-3.5 text-white" />}
          </button>
        );
      })}
    </div>
  );
}
