/**
 * The core's own commands — contributed through the public seam.
 *
 * This file has no privileges. It calls `contribute()` exactly as a third party
 * would, which is the point: if the core needed a back door, the seam would be a
 * decoration. A test asserts every built-in is reachable and overridable through
 * the registry, so the claim stays true.
 *
 * Bindings follow Linear's grammar, because it is the one our users already have
 * in their fingers: `mod+k` for the palette, `g` sequences for navigation, bare
 * letters for actions, `?` for help.
 */

import { contribute, type Ctx } from "../core/registry";

const hasSpace = (c: Ctx) => c.spaceId !== null;
const canWrite = (c: Ctx) => hasSpace(c) && !c.readOnly;
const hasSelection = (c: Ctx) => c.selection !== null;

export const coreCommands = contribute({
  commands: [
    // ---- global -----------------------------------------------------------
    {
      id: "palette.open",
      title: "Open command palette",
      group: "General",
      keys: ["mod+k"],
      // Not `when: !overlay` — the palette is how you escape a wrong overlay.
      run: (c) => c.app.openPalette(),
    },
    {
      id: "shortcuts.toggle",
      title: "Keyboard shortcuts",
      group: "General",
      keys: ["?"],
      run: (c) => c.app.toggleShortcuts(),
    },
    {
      id: "view.refresh",
      title: "Refresh",
      group: "General",
      keys: ["r"],
      when: (c) => !c.overlay,
      run: (c) => c.app.refresh(),
    },
    {
      id: "overlay.close",
      title: "Close",
      group: "General",
      keys: ["esc"],
      when: (c) => c.overlay,
      run: (c) => c.app.closePalette(),
    },

    // ---- navigation -------------------------------------------------------
    // `g` sequences, because that is the grammar a tracker's users already have
    // in their fingers. The prefix is never pre-empted by a shorter match that
    // shares it, so `g` can start `g i` and still mean nothing on its own.
    ...(
      [
        ["list", "l", "Issues"],
        ["board", "b", "Board"],
        ["inbox", "i", "Inbox"],
        ["activity", "a", "Activity"],
        ["members", "m", "Members"],
      ] as const
    ).map(([view, key, title]) => ({
      id: `go.${view}`,
      title: `Go to ${title}`,
      group: "Navigation",
      keys: [`g ${key}`],
      when: (c: Ctx) => !c.overlay,
      run: (c: Ctx) => c.app.goto(view),
    })),

    {
      id: "filter.open",
      title: "Filter issues",
      group: "View",
      keys: ["/"],
      when: (c) => !c.overlay && hasSpace(c) && (c.view === "list" || c.view === "board"),
      run: (c) => c.app.openFilter(),
    },

    // ---- motion -----------------------------------------------------------
    {
      id: "nav.down",
      title: "Move down",
      group: "Navigation",
      keys: ["j", "down"],
      when: (c) => !c.overlay && hasSpace(c),
      run: (c) => c.app.moveSelection(1),
    },
    {
      id: "nav.up",
      title: "Move up",
      group: "Navigation",
      keys: ["k", "up"],
      when: (c) => !c.overlay && hasSpace(c),
      run: (c) => c.app.moveSelection(-1),
    },

    {
      id: "view.detail",
      title: "Toggle issue detail",
      group: "View",
      // Linear binds space to peek, and the muscle memory is worth inheriting.
      keys: ["space"],
      when: (c) => !c.overlay && hasSelection(c),
      run: (c) => c.app.toggleDetail(),
    },

    // ---- issues -----------------------------------------------------------
    {
      id: "issue.create",
      title: "New issue",
      group: "Issues",
      keys: ["c"],
      when: (c) => !c.overlay && canWrite(c),
      run: (c) => c.app.createIssue(),
    },
    {
      id: "issue.delete",
      title: "Delete issue",
      group: "Issues",
      // No bare key: deletion is the one verb where a mis-key is unrecoverable,
      // and the engine will ask its own question anyway (409 confirm_required).
      when: (c) => !c.overlay && canWrite(c) && hasSelection(c),
      run: (c) => c.selection && c.app.deleteIssue(c.selection),
    },
  ],
});
