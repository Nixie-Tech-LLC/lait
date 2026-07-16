import { cva, type VariantProps } from "class-variance-authority";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import * as Tooltip from "@radix-ui/react-tooltip";

/**
 * The primitives every surface builds from.
 *
 * Radix ships no Button, and that is correct — a native `<button>` needs no
 * behaviour wrapper, and Radix has no styling opinion to give. What we were
 * missing was never a component library; it was a **variant system**. Without one
 * every button grows its own class string, and they drift: we had five different
 * "button" recipes disagreeing about padding, border, and weight, which is how a
 * header ends up looking assembled rather than designed.
 *
 * So: `cva` maps intent (`variant`, `size`) to classes, once. A caller says
 * `<Button variant="ghost">`, never `px-2 py-1 rounded border …`. `cn` merges any
 * override through `tailwind-merge`, so a later `px-3` actually replaces the
 * variant's padding instead of both landing in the class list and letting source
 * order decide.
 *
 * The default is **ghost**. Chrome should recede until you need it — a toolbar of
 * bordered buttons competes with the content it exists to serve.
 */

export function cn(...parts: ClassValue[]): string {
  return twMerge(clsx(parts));
}

const button = cva(
  // Shared: the parts that are true of every button, including the focus ring,
  // which is not optional in a keyboard-first app.
  "inline-flex shrink-0 select-none items-center justify-center gap-1.5 rounded font-medium transition-colors disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        /** The default. Invisible until hovered — for chrome. */
        ghost: "text-mute hover:bg-hover hover:text-fg",
        /** A visible affordance without shouting. */
        outline: "border-line-strong bg-bg hover:bg-hover text-fg border",
        /** Exactly one per screen, at most. */
        primary: "bg-accent text-accent-fg hover:opacity-90",
        /** Destructive, and only where the engine will ask anyway. */
        danger: "text-mute hover:bg-danger/10 hover:text-danger",
        /** Selected state in a segmented group. */
        active: "bg-active text-fg",
      },
      size: {
        /** Icon-only chrome: a 24px square, the toolbar unit. */
        icon: "size-6",
        sm: "h-6 px-2 text-sm",
        md: "h-7 px-2.5",
      },
    },
    defaultVariants: { variant: "ghost", size: "sm" },
  },
);

export type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof button>;

export function Button({ className, variant, size, ...rest }: ButtonProps) {
  return <button className={cn(button({ variant, size }), className)} {...rest} />;
}

/**
 * An icon button with a tooltip carrying its shortcut.
 *
 * The label is required and does double duty: `aria-label` for anyone not looking
 * at it, and the tooltip for anyone who is. An icon-only control without a label
 * is a puzzle; `title` alone is one that screen readers read inconsistently and
 * that never mentions the key.
 */
export function IconButton({
  label,
  chord,
  className,
  variant,
  children,
  ...rest
}: Omit<ButtonProps, "size"> & { label: string; chord?: string }) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <button
          aria-label={label}
          className={cn(button({ variant, size: "icon" }), className)}
          {...rest}
        >
          {children}
        </button>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          sideOffset={6}
          className="border-line-strong bg-raised shadow-overlay z-50 flex items-center gap-1.5 rounded border px-2 py-1 text-xs"
        >
          {label}
          {chord && <Kbd>{chord}</Kbd>}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

/** A key hint. One spelling, everywhere it appears. */
export function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        "border-line-strong bg-bg text-dim rounded-sm border px-1 font-mono text-2xs leading-4",
        className,
      )}
    >
      {children}
    </kbd>
  );
}

/** Tooltips need one provider; delay is short because these are chrome hints,
 *  not explanations you should have to wait for. */
export function TooltipProvider({ children }: { children: React.ReactNode }) {
  return (
    <Tooltip.Provider delayDuration={400} skipDelayDuration={200}>
      {children}
    </Tooltip.Provider>
  );
}
