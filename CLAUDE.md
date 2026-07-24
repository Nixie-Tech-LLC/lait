# Working on lait (agent notes)

lait is a local-first, peer-to-peer issue tracker: a Rust engine (`src/`, `crates/`)
and a React viewer (`viewer/`) that `lait serve` hosts over the engine on loopback.

## Driving the viewer in a headless browser

The viewer is a React SPA. **Do not navigate it with synthetic clicks.** An eval'd
`element.click()` fires React's `onClick` *inside* the eval; the resulting re-render
plus `history` update detaches the automation (CDP) execution context, so you get an
opaque `Uncaught` and the click usually has no effect. Dispatched events and
`history.replaceState` are unaffected — so navigate with the built-in event, which
the app handles on a deferred task:

```js
window.dispatchEvent(new CustomEvent("lait:nav", { detail: { view: "settings" } }))
```

`detail` fields:
- `{ view }` — `list | board | projects | inbox | activity | settings`
- `{ project }` / `{ issue }` — select a project (KEY) or issue (ref)
- `{ tab }` — Settings sub-page: `general | members | labels | workflow | access`
- `{ overview: "<PROJECT_KEY>" }` — Projects → that project's overview page

To reach a sub-state, dispatch the view first, wait ~1s for it to mount, then
dispatch the sub-state. `wmux browser open <full-route-url>` also works (a full page
load avoids the in-eval history problem). The hook lives in `viewer/src/App.tsx`
(search `lait:nav`); Settings and Projects add their own listeners. It is inert in
normal use — nothing dispatches it.

Start a server and get its URL/token: `lait serve --json` → `{url, token, port}`.

## Rebuilding after a viewer change

`src/serve/shell.rs` embeds `src/serve/assets/` via `include_dir!` at **compile
time**, so a viewer edit is only visible through `lait serve` after both steps:

```sh
(cd viewer && npm run build)   # regenerates src/serve/assets/*
cargo build                    # re-embeds the fresh bundle
```

Kill running daemons first — a running `lait` binary holds the `.exe` lock and the
link step fails (`taskkill //F //IM lait.exe` on Windows).

## Verifying

- Viewer: `cd viewer && npx tsc -b --noEmit && npx vitest run`
- Engine: `cargo test` (kill daemons first; they hold the `.exe` lock during the
  test build). Pre-commit/pre-push hooks run `cargo fmt --all --check` — run
  `cargo fmt --all` before committing Rust.
