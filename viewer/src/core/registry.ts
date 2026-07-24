/**
 * The seam.
 *
 * There is one vocabulary in this client — the `Command` — and one door into it,
 * [`contribute`]. Keys, the palette, the shortcuts overlay, buttons, and menus do
 * not *do* anything: they resolve to a command id and run it. Every surface that
 * lists commands is a **projection** of this registry, never a second list.
 *
 * The property that makes the seam real rather than decorative: **the core uses
 * it too.** Every built-in command in `src/commands/` is registered through
 * `contribute()`, exactly as a third party would. There is no privileged path, so
 * anything the core can do, an extension can do — and anything the core does
 * wrong, an extension can override. A test pins this.
 *
 * Inherited from the TUI's `keymap.rs`, deliberately and verbatim in spirit:
 *
 * - **Overrides replace an action's key set; they do not add an alias.** If a
 *   command ships with `["mod+k", ":"]` and you override it to `["ctrl+p"]`, `:`
 *   stops working. This surprised people in the terminal too, and it is still the
 *   right call: the alternative is bindings you cannot remove.
 * - **Warn, never gate.** An unknown id or an unparseable chord produces a
 *   warning and is skipped. A typo in a config file must never take the client
 *   down — you would have no way to fix it from inside a broken app.
 */

import { parseBinding, type Binding } from "./keys";
import type { Field } from "./overlay";

/** The root surfaces. These are also the stable view segments in the viewer URL;
 *  see `route.ts` for the canonical, machine-independent route contract. */
export type View =
  | "list"
  | "board"
  | "calendar"
  | "timeline"
  | "projects"
  | "inbox"
  | "activity"
  | "settings";

/** The work-view render modes a saved view / the switcher toggles between —
 *  the same filtered query, drawn four ways. A strict subset of `View`. */
export const WORK_VIEWS = ["list", "board", "calendar", "timeline"] as const;
export type WorkView = (typeof WORK_VIEWS)[number];
export function isWorkView(v: View): v is WorkView {
  return (WORK_VIEWS as readonly string[]).includes(v);
}

/**
 * A field a picker can be opened on.
 *
 * These are the *editable* fields of an issue that resolve to a set — the ones
 * UI.md §5.1 gives quick-action keys (`a` assign, `b` label, `p` priority, `s` set
 * status, `m` move project). Title and description are text, not a set, so they are
 * not here: they are edited in place.
 */
export type IssueField = "assignee" | "label" | "status" | "priority" | "project";

/** The work-state verbs. One `Request` each, and each bundles more than a status —
 *  see `replica.rs::work_state`. */
export type WorkAction = "start" | "done" | "stop";

/** Everything a command can touch. The app supplies it; extensions receive it. */
export interface Ctx {
  /** The root surface on screen. */
  view: View;
  /** The selected space, or null. */
  spaceId: string | null;
  /** An agent's space: the engine refuses writes, so the UI must not offer them. */
  readOnly: boolean;
  /** The focused issue's canonical ref, when a list/board has one. */
  selection: string | null;
  /** How many issues carry a bulk-selection check. Gates the bulk commands
   *  (and lets Esc mean "clear checks" only while there are checks to clear). */
  checkedCount: number;
  /** True while an overlay owns input (palette, modal, editor). */
  overlay: boolean;
  /** Imperative surface the app exposes to commands. */
  app: AppApi;
}

export interface AppApi {
  openPalette(): void;
  openIssueSearch(): void;
  closePalette(): void;
  toggleShortcuts(): void;
  toggleSidebar(): void;
  toggleDetail(): void;
  goto(view: View): void;
  openFilter(): void;
  /** Reset every filter facet to the neutral state (show all). */
  clearFilter(): void;
  toast(message: string): void;
  refresh(): void;
  select(reff: string | null): void;
  /** Show `value` for `(doc, field)` now, send the write, and let the doorbell
   *  retire the guess. See core/overlay.ts. */
  predict(doc: string, field: Field, value: string, send: () => Promise<unknown>): Promise<boolean>;
  createIssue(): void;
  deleteIssue(reff: string): void;
  pickSpace(id: string): void;
  moveSelection(delta: number): void;

  /** Open the picker for `field` on the selected issue. Reveals the detail pane if
   *  it is closed — a picker for an issue you cannot see is a menu with no subject. */
  openField(field: IssueField): void;
  /** Run a work-state verb on the selected issue (`issue_start`/`_done`/`_stop`). */
  work(action: WorkAction): void;
  /** Reorder the selected issue within its board column. `-1` up, `1` down. */
  reorder(delta: number): void;
  /** Shift the selected issue to the previous/next workflow column (UI.md §5.1 `H`/`L`). */
  shiftStatus(delta: number): void;
  /** Copy the selected issue's ref to the clipboard (UI.md §5.1 `y`). */
  yankRef(): void;
  /** The project whose board is on screen; `null` = the daemon's default chain. */
  pickProject(key: string | null): void;
  /** Open the new-project composer. */
  createProject(): void;

  /** Clear the tombstone on a deleted issue (no-ops with a toast otherwise). */
  restoreIssue(reff: string): void;
  /** Assign the selected issue to me (UI.md's `start` without the status move). */
  assignMe(): void;
  /** Send the selected issue to its column's top or bottom. */
  moveTo(pos: "top" | "bottom"): void;
  /** Toggle the bulk-selection check on the selected issue. */
  toggleCheck(): void;
  /** Check every visible issue. */
  checkAll(): void;
  /** Drop every bulk-selection check. */
  clearChecks(): void;
  /** Open the display-options popover (group / order / deleted). */
  openDisplay(): void;
  /** Show the current project's workflow — states, transitions, gates. */
  openWorkflow(): void;
  /** Show the space's role definitions. */
  openRoles(): void;
  /** Set this browser's appearance without touching shared space state. */
  setTheme(theme: "system" | "light" | "dark"): void;
}

export interface Command {
  /** Stable, kebab-case, dotted by area (`issue.create`). The override key. */
  id: string;
  /** Human label — what the palette and the shortcuts overlay show. */
  title: string;
  /** Palette grouping and shortcuts-overlay section. */
  group?: string;
  /** Default bindings, in this notation: `"mod+k"`, `"g i"`, `"c"`, `"?"`. */
  keys?: readonly string[];
  /** Whether the command applies right now. Absent = always. */
  when?: (ctx: Ctx) => boolean;
  run: (ctx: Ctx) => unknown;
}

/** A patch over an existing command. `keys: null` unbinds it entirely. */
export type CommandPatch = Partial<Omit<Command, "id">> & { keys?: readonly string[] | null };

/**
 * One contribution. This is the entire extension API.
 *
 * `keys` is sugar for the overwhelmingly common override — rebinding — and mirrors
 * the shape the TUI already taught people (`tui.key.<action-id> = "<chord>"`), so
 * the mental model carries across surfaces.
 */
export interface Contribution {
  commands?: readonly Command[];
  /** id → chord, chords, or `null` to unbind. */
  keys?: Readonly<Record<string, string | readonly string[] | null>>;
  /** id → patch. Replace a `run`, retitle, re-scope with `when`. */
  overrides?: Readonly<Record<string, CommandPatch>>;
  /** CSS custom properties, applied to `:root`. The visual half of the seam. */
  theme?: Readonly<Record<string, string>>;
}

export interface Disposable {
  dispose(): void;
}

/** A resolved command: its definition plus whatever bindings actually apply. */
export interface Bound {
  command: Command;
  bindings: Binding[];
  /** The notation, for display. */
  chords: string[];
}

export class Registry {
  private commands = new Map<string, Command>();
  private patches = new Map<string, CommandPatch>();
  private keyOverrides = new Map<string, readonly string[] | null>();
  private themes: Array<Record<string, string>> = [];
  /** Human warnings — surfaced in the UI, never thrown. */
  readonly warnings: string[] = [];

  /**
   * The single door. Returns a handle that undoes exactly this contribution,
   * which is what makes the registry testable and an extension unloadable.
   */
  contribute(c: Contribution): Disposable {
    const added: string[] = [];
    for (const cmd of c.commands ?? []) {
      if (this.commands.has(cmd.id)) {
        // Last write wins, loudly. Silent shadowing is how two features end up
        // fighting over one id and nobody can tell which won.
        this.warn(`duplicate command id "${cmd.id}" — the later one wins`);
      }
      this.commands.set(cmd.id, cmd);
      added.push(cmd.id);
    }

    const patched: string[] = [];
    for (const [id, patch] of Object.entries(c.overrides ?? {})) {
      this.patches.set(id, { ...this.patches.get(id), ...patch });
      patched.push(id);
    }

    const rebound: string[] = [];
    for (const [id, keys] of Object.entries(c.keys ?? {})) {
      this.keyOverrides.set(id, keys === null ? null : typeof keys === "string" ? [keys] : keys);
      rebound.push(id);
    }

    const theme = c.theme ? { ...c.theme } : null;
    if (theme) this.themes.push(theme);

    return {
      dispose: () => {
        for (const id of added) this.commands.delete(id);
        for (const id of patched) this.patches.delete(id);
        for (const id of rebound) this.keyOverrides.delete(id);
        if (theme) this.themes = this.themes.filter((t) => t !== theme);
      },
    };
  }

  private warn(msg: string) {
    this.warnings.push(msg);
  }

  /** Every command, with patches applied. Registration order. */
  all(): Command[] {
    return [...this.commands.values()].map((c) => ({ ...c, ...this.patches.get(c.id) }));
  }

  get(id: string): Command | undefined {
    const base = this.commands.get(id);
    return base ? { ...base, ...this.patches.get(id) } : undefined;
  }

  /**
   * Validate the overrides against what actually exists.
   *
   * Called once after the core and any extensions have contributed — an override
   * naming a command that does not exist is a typo the user needs to see, and the
   * only honest place to notice is after everything has had its say.
   */
  validate(): string[] {
    for (const id of this.keyOverrides.keys()) {
      if (!this.commands.has(id)) this.warn(`no command "${id}" to rebind — see the ? overlay`);
    }
    for (const id of this.patches.keys()) {
      if (!this.commands.has(id)) this.warn(`no command "${id}" to override`);
    }
    return this.warnings;
  }

  /** The merged theme, last contribution winning per property. */
  theme(): Record<string, string> {
    return Object.assign({}, ...this.themes);
  }

  /**
   * A command's effective bindings.
   *
   * An override **replaces** the defaults rather than extending them — see the
   * module note. Unparseable chords warn and are dropped, leaving the command
   * reachable through the palette even when its key is broken.
   */
  bound(cmd: Command): Bound {
    const override = this.keyOverrides.get(cmd.id);
    const chords: string[] =
      override === null ? [] : override !== undefined ? [...override] : [...(cmd.keys ?? [])];

    const bindings: Binding[] = [];
    const kept: string[] = [];
    for (const c of chords) {
      const b = parseBinding(c);
      if (!b) {
        this.warn(`"${c}" is not a key I understand (for "${cmd.id}")`);
        continue;
      }
      bindings.push(b);
      kept.push(c);
    }
    return { command: cmd, bindings, chords: kept };
  }

  /** Every bound command that applies right now. The projection every surface reads. */
  active(ctx: Ctx): Bound[] {
    return this.all()
      .filter((c) => (c.when ? c.when(ctx) : true))
      .map((c) => this.bound(c));
  }
}

/** The client's registry. One per app; exported so extensions can reach it. */
export const registry = new Registry();

/**
 * Contribute commands, keybindings, overrides, or theme.
 *
 * The only supported way to change what this client does — used by the core for
 * every one of its own features, so an extension is never a second-class citizen.
 */
export function contribute(c: Contribution): Disposable {
  return registry.contribute(c);
}
