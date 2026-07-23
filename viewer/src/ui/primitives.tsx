import { cva, type VariantProps } from "class-variance-authority";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import * as Popover from "@radix-ui/react-popover";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as Tooltip from "@radix-ui/react-tooltip";
import { Check, LoaderCircle } from "lucide-react";

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
  // which is not optional in a keyboard-first app. `transition` (not just
  // `transition-colors`) so the `active:` press scales back smoothly on release;
  // the scale is a transform, so it costs no layout.
  "inline-flex shrink-0 select-none items-center justify-center gap-1.5 rounded font-medium transition active:scale-[0.98] disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        /** The default. Invisible until hovered — for chrome. */
        ghost: "text-mute hover:bg-hover hover:text-fg",
        /** A visible affordance without shouting. */
        outline: "border-line-strong bg-bg hover:bg-hover text-fg border",
        /** Exactly one per screen, at most. */
        primary: "bg-accent text-accent-fg hover:opacity-90",
        /** A quiet destructive affordance — the inline "X" that only reddens on
         *  hover. For the button that actually confirms a destroy, use
         *  `destructive`. */
        danger: "text-mute hover:bg-danger/10 hover:text-danger",
        /** The filled destructive commit — the confirm button in a delete dialog.
         *  White-on-danger clears AA (see the palette note). Replaces the old
         *  `primary` + `bg-danger` override that every call site had to remember. */
        destructive: "bg-danger text-accent-fg hover:opacity-90",
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
  VariantProps<typeof button> & {
    /**
     * Show a spinner and go inert. Callers used to hand-roll this — a manual
     * `aria-busy`, a disabled toggle, and a text swap to "Saving…" — and each did
     * two of the three. `loading` does all three from one flag: the spinner leads,
     * the button disables so a second click can't fire, and `aria-busy` tells a
     * screen reader why. The label stays the caller's to change (or not).
     */
    loading?: boolean;
  };

export function Button({ className, variant, size, loading, disabled, children, ...rest }: ButtonProps) {
  return (
    <button
      className={cn(button({ variant, size }), className)}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {loading && <LoaderCircle className="size-3.5 animate-spin" aria-hidden />}
      {children}
    </button>
  );
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
          style={{ transformOrigin: "var(--radix-tooltip-content-transform-origin)" }}
          className="ui-surface border-line-strong bg-raised shadow-overlay z-50 flex items-center gap-1.5 rounded border px-2 py-1 text-xs"
        >
          {label}
          {chord && <Kbd>{chord}</Kbd>}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

/**
 * A checkbox that belongs to the theme.
 *
 * The native control was the only form element still rendering as the OS drew it —
 * a blue-by-default box that ignores `--color-accent` and looks pasted-in beside
 * everything else. Radix hands us the box's behaviour (focus, space-to-toggle, the
 * indeterminate state) with no appearance, so the appearance is ours: the accent
 * fill and the check we use everywhere a boolean is set.
 */
export function Checkbox({
  className,
  ...props
}: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      className={cn(
        "border-line-strong bg-bg text-accent-fg data-[state=checked]:bg-accent data-[state=checked]:border-accent data-[state=indeterminate]:bg-accent data-[state=indeterminate]:border-accent flex size-4 shrink-0 items-center justify-center rounded border transition-colors disabled:opacity-50",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator>
        <Check className="size-3" />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

/**
 * A switch, for a setting that takes effect the instant you flip it.
 *
 * A checkbox says "this will be true when you submit"; a switch says "this is on
 * now." That is the only reason to prefer one — so the switch is for the live
 * toggles (a preference, a "create another"), never for a form you still have to
 * confirm. Same accent, so on-ness reads the same as a checked box.
 */
export function Switch({ className, ...props }: React.ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn(
        "border-line-strong bg-active data-[state=checked]:bg-accent data-[state=checked]:border-accent relative inline-flex h-4 w-7 shrink-0 items-center rounded-full border transition-colors disabled:opacity-50",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb className="bg-fg data-[state=checked]:bg-accent-fg pointer-events-none block size-3 translate-x-0.5 rounded-full transition-transform data-[state=checked]:translate-x-[13px]" />
    </SwitchPrimitive.Root>
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

/**
 * The floating shell every Popover shares — the counterpart to `MenuContent`.
 *
 * There was a `MenuContent` for dropdowns but no equivalent for popovers, so the
 * shell string (`border-line-strong bg-raised shadow-overlay z-50 rounded-lg
 * border`) was hand-copied into every picker, display panel, and status popover —
 * and it had already drifted (the inbox popover reached for a `bg-overlay` token
 * that doesn't exist, so it rendered with no fill). One component ends that: the
 * chrome is decided here, callers pass only what differs (width, padding, align).
 *
 * It owns the `Portal` too, so a caller writes `<PopoverContent>` rather than
 * `<Popover.Portal><Popover.Content …>` — one less nesting to get wrong, and the
 * portal is not an opinion any single popover should be re-making.
 *
 * `ui-surface` gives the entrance the modal surfaces already had; the
 * transform-origin is pinned to Radix's computed anchor so the scale grows from the
 * trigger's edge instead of the popover's center.
 */
export function PopoverContent({
  className,
  sideOffset = 4,
  style,
  ...props
}: React.ComponentProps<typeof Popover.Content>) {
  return (
    <Popover.Portal>
      <Popover.Content
        sideOffset={sideOffset}
        style={{ transformOrigin: "var(--radix-popover-content-transform-origin)", ...style }}
        className={cn(
          "ui-surface border-line-strong bg-raised shadow-overlay z-50 rounded-lg border outline-none",
          className,
        )}
        {...props}
      />
    </Popover.Portal>
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
