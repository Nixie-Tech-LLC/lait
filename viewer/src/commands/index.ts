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
