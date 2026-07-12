# lait viewer

A local, browser-based **Linear-style** viewer for your lait projects and issues.

It is a plain **Vite + React + TypeScript** SPA. Its only backend is a Vite
dev-server middleware that shells out to the **`lait --json`** CLI — so every read
*and every edit* is a real lait command that flows through lait's daemon and Loro
CRDT layer. There is **no second database** and nothing to keep in sync: the viewer
is just another lait client, like the TUI or the MCP server.

```
browser (React)  ──HTTP /api──▶  Vite middleware  ──spawn──▶  lait --json <cmd>  ──▶  lait daemon ──▶ Loro store (.lait/)
```

## Run it

```bash
cd viewer
npm install
npm run dev
```

Then open the printed URL (default http://localhost:5178).

The middleware finds the `lait` binary automatically, preferring (in order):

1. `$LAIT_BIN` (an explicit path), then
2. `../target/release/lait[.exe]`, `../target/debug/lait[.exe]`, then
3. `lait` on your `PATH`.

It runs `lait` with the repo root as the working directory, so it reads the same
`.lait/` store the CLI/TUI use. To point at a different workspace, set `LAIT_HOME`
(or `LAIT_STORE`) in the shell before `npm run dev`, same as any lait command.

## What works today (v1)

- **Projects** — sidebar list, create new project.
- **Issues** — grouped **list** view and per-project **board** view.
- **Issue detail drawer** — edit title, change status & priority, add comments,
  delete (tombstone). All are native lait mutations.
- **Create issue** — title, project, priority, description.
- **Invite people** (sidebar → *Invite people*) — the ergonomic invite surface:
  - **QR code** + one-click **copy** of the `lait://join/…` link (`GET /api/invite`,
    which parses `lait invite`'s raw output and renders an SVG QR server-side).
  - **✉ Email invite** — a `mailto:` link that pre-fills a full invite message
    (install one-liners + `lait connect …`). No SMTP, no app password: it just
    opens the sender's mail client.
  - **Join requests → Approve** — polls `GET /api/join-requests` (derived from the
    daemon's `lait log` Join events minus existing members) and approves with one
    click via `POST /api/members` → `lait members add <id>`, which seals them the
    workspace key. Also lists current members.

  Note: a pending request only appears once a peer actually runs `lait connect`
  against your link over the P2P transport; the approve wiring is validated, but
  seeing a live request needs a second node.

## Not yet (easy follow-ups)

- Drag-and-drop reordering / column moves on the board (wire to `POST
  /api/issues/:reff/move`, already implemented server-side).
- Assignee & label editing UI (endpoints `…/assign`, `…/label` exist).
- Live refresh — the CLI daemon exposes a doorbell/subscribe stream; today the
  viewer refetches after each write. Could subscribe for push updates.
- Activity feed / history view (`GET /api/activity`, `lait history <ref>`).

## Files

- `vite.config.ts` — registers the `lait-api` middleware.
- `server/lait.ts` — resolves the binary and runs `lait --json`, parsing the
  versioned `Response` DTO.
- `server/api.ts` — the REST → CLI router.
- `src/types.ts` — TypeScript mirrors of `src/dto.rs`.
- `src/api.ts` — browser fetch client.
- `src/components/*` — Sidebar, IssueList, Board, IssueDetail, modals.
