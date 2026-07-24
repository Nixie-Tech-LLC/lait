import { cva, type VariantProps } from "class-variance-authority";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import * as Popover from "@radix-ui/react-popover";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as Tooltip from "@radix-ui/react-tooltip";
import { Check, LoaderCircle, Pencil } from "lucide-react";

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
  "inline-flex shrink-0 select-none items-center justify-center gap-1.5 rounded-md font-medium transition-colors disabled:pointer-events-none disabled:opacity-45",
  {
    variants: {
      variant: {
        /** The default. Invisible until hovered — for chrome. */
        ghost: "text-mute hover:bg-hover hover:text-fg",
        /** A visible affordance without shouting. */
        outline: "border-line bg-bg hover:border-line-strong hover:bg-hover text-fg border",
        /** Exactly one per screen, at most. A neutral inverse commit keeps blue
         *  available for focus and state instead of making every save look like
         *  a Jira call-to-action. */
        primary: "bg-fg text-bg hover:bg-fg/85",
        /** A quiet destructive affordance — the inline "X" that only reddens on
         *  hover. For the button that actually confirms a destroy, use
         *  `destructive`. */
        danger: "text-mute hover:bg-danger/10 hover:text-danger",
        /** The filled destructive commit — the confirm button in a delete dialog.
         *  White-on-danger clears AA (see the palette note). Replaces the old
         *  `primary` + `bg-danger` override that every call site had to remember. */
        destructive: "bg-danger text-accent-fg hover:bg-danger/85",
        /** Selected state in a segmented group. */
        active: "bg-active text-fg",
        /** A named action inside dense chrome. Unlike `primary`, this sits beside
         * icon buttons without turning the toolbar into a callout banner. */
        toolbar:
          "border-line bg-raised text-dim hover:border-line-strong hover:bg-hover hover:text-fg border",
        /** Text action embedded in prose or metadata. It never grows a capsule. */
        inline: "text-dim hover:text-fg hover:underline underline-offset-2",
      },
      size: {
        /** Icon-only chrome: a 24px square, the toolbar unit. */
        icon: "size-6",
        sm: "h-6 px-2 text-sm",
        md: "h-7 px-2.5 text-sm",
        inline: "h-auto p-0 text-xs",
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

export function InlineAction(props: Omit<ButtonProps, "variant" | "size">) {
  return <Button variant="inline" size="inline" {...props} />;
}

const badge = cva(
  "inline-flex min-w-0 items-center gap-1 whitespace-nowrap rounded-full border px-1.5 text-2xs leading-4",
  {
    variants: {
      tone: {
        neutral: "border-line bg-raised text-dim",
        accent: "border-accent/30 bg-accent/10 text-accent",
        danger: "border-danger/30 bg-danger/5 text-danger",
        success: "border-ok/30 bg-ok/10 text-ok",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

/** True compact metadata: counts, tags, reactions and state labels. */
export function Badge({
  tone,
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badge>) {
  return <span className={cn(badge({ tone }), className)} {...props} />;
}

/** An actual interactive pill: reactions and removable/filter chips only. */
export function ChipButton({
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(
        "border-line bg-bg text-dim hover:border-line-strong hover:bg-hover aria-pressed:border-accent/40 aria-pressed:bg-accent/10 aria-pressed:text-fg inline-flex h-6 items-center gap-1 rounded-full border px-1.5 text-xs outline-none transition-colors focus-visible:ring-accent/50 focus-visible:ring-1 disabled:pointer-events-none disabled:opacity-45",
        className,
      )}
      {...props}
    />
  );
}

const field = cva(
  "border-line bg-bg placeholder:text-mute w-full rounded-md border text-sm outline-none transition-colors focus:border-line-strong focus:ring-1 focus:ring-line-strong/30 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-danger aria-invalid:focus:ring-danger/20",
  {
    variants: {
      size: {
        sm: "h-7 px-2",
        md: "h-8 px-2.5",
      },
    },
    defaultVariants: { size: "md" },
  },
);

/**
 * Shared trigger geometry for controls that open a popover. Opening a menu is
 * behaviour, not a visual role: property values should remain quiet, while a
 * standalone composer/filter control needs a visible boundary. Neither is a
 * semantic pill; true tags and reactions get their own primitive.
 */
export const controlTrigger = cva(
  "inline-flex items-center gap-1.5 rounded-md text-sm outline-none transition-colors disabled:pointer-events-none disabled:opacity-45 data-[state=open]:bg-active",
  {
    variants: {
      variant: {
        property:
          "hover:bg-hover -mx-1 min-h-7 min-w-0 px-1.5 text-left",
        chip:
          "border-line bg-bg hover:border-line-strong hover:bg-hover min-h-7 border px-2",
        filter:
          "border-line bg-raised hover:border-line-strong hover:bg-hover min-h-7 border px-2",
        toolbar:
          "text-dim hover:bg-hover hover:text-fg min-h-6 px-1.5",
      },
    },
    defaultVariants: { variant: "chip" },
  },
);

export type ControlTriggerVariant = NonNullable<
  VariantProps<typeof controlTrigger>["variant"]
>;

/** Shared list interaction states. Content layout remains the caller's concern;
 * hover, selection, focus and dividers do not. */
export const interactiveRow = cva(
  "group cursor-default outline-none transition-colors focus-visible:bg-hover focus-visible:ring-accent/50 focus-visible:ring-1 focus-visible:ring-inset",
  {
    variants: {
      surface: {
        list: "border-line/50 border-b",
        contained: "rounded-md",
      },
      selected: {
        true: "bg-active text-fg",
        false: "hover:bg-hover",
      },
      density: {
        compact: "min-h-8",
        normal: "min-h-9",
      },
    },
    defaultVariants: {
      surface: "list",
      selected: false,
      density: "compact",
    },
  },
);

/** One navigation hit-area and state language for the app rail and settings. */
export const navigationItem = cva(
  "flex w-full min-w-0 items-center gap-2 rounded-md px-2 text-left text-sm outline-none transition-colors focus-visible:ring-accent/50 focus-visible:ring-1",
  {
    variants: {
      selected: {
        true: "bg-active text-fg",
        false: "text-dim hover:bg-hover hover:text-fg",
      },
      density: {
        compact: "h-6",
        normal: "h-7",
        roomy: "h-8",
      },
    },
    defaultVariants: { selected: false, density: "normal" },
  },
);

export type InputProps = Omit<React.InputHTMLAttributes<HTMLInputElement>, "size"> &
  VariantProps<typeof field>;

/** The single-line field recipe. Validation is driven by `aria-invalid`, so
 * callers do not need to rebuild border and focus states for each form. */
export function Input({ className, size, ...props }: InputProps) {
  return <input className={cn(field({ size }), className)} {...props} />;
}

export type TextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement> & {
  resize?: "none" | "vertical";
};

/** Multi-line counterpart to `Input`; it shares the same surface, radius,
 * validation and focus language without forcing a fixed height. */
export function Textarea({ className, resize = "vertical", ...props }: TextareaProps) {
  return (
    <textarea
      className={cn(
        field(),
        "h-auto min-h-16 px-2.5 py-2",
        resize === "vertical" ? "resize-y" : "resize-none",
        className,
      )}
      {...props}
    />
  );
}

/** Compact form caption used by settings and dialogs. Sentence case keeps form
 * hierarchy quieter than the old all-caps Jira-like labels. */
export function FieldLabel({
  children,
  className,
  ...props
}: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label className={cn("text-dim flex flex-col gap-1.5 text-sm", className)} {...props}>
      {children}
    </label>
  );
}

/**
 * A readable surface that can become an editor. Links and nested controls retain
 * their own behavior; keyboard users get an explicit edit action instead of a
 * clickable `div` that falsely claims the whole markdown body is a button.
 */
export function EditableSurface({
  children,
  onEdit,
  label = "Edit",
  className,
}: {
  children: React.ReactNode;
  onEdit: () => void;
  label?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "group/editable hover:bg-hover/70 relative -mx-2 min-h-10 rounded-md px-2.5 py-2 transition-colors",
        className,
      )}
      onClick={(event) => {
        if ((event.target as HTMLElement).closest("a, button, input, select, textarea")) return;
        onEdit();
      }}
    >
      {children}
      <IconButton
        label={label}
        onClick={(event) => {
          event.stopPropagation();
          onEdit();
        }}
        className="absolute top-1 right-1 opacity-0 group-hover/editable:opacity-100 focus-visible:opacity-100"
      >
        <Pencil className="size-3" />
      </IconButton>
    </div>
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
        "border-line-strong bg-bg text-accent-fg data-[state=checked]:bg-accent data-[state=checked]:border-accent data-[state=indeterminate]:bg-accent data-[state=indeterminate]:border-accent flex size-4 shrink-0 items-center justify-center rounded-sm border transition-colors disabled:opacity-50",
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
