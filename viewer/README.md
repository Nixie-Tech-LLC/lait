# lait's web client

A keyboard-first board over the local control plane. This directory builds into
`../src/serve/assets`, which `lait serve` embeds and serves.

If you are extending lait — a theme, extra commands, a different frontend against the
same control plane — this is the reference. The whole client is a **projection of a
command registry** (`src/core/registry.ts`); read that file first.

## The dev loop

```bash
cd viewer
npm install
npm run dev          # → http://localhost:5178
```

That one command does everything: it starts the engine (`lait serve --json`), reads
the run's token off its first line, and launches Vite with the token wired into the
dev proxy. Edit `src/`, see it in the browser. No token to copy, no second terminal.

It drives `../target/debug/lait` by default (then `release`, then `PATH`) — so
`cargo build` once first. Overrides:

| Env | Effect |
|---|---|
| `LAIT_BIN` | Path to the `lait` binary to run instead of the `target/` one. |
| `LAIT_SPACE` | Space name, id, or path passed to `lait -w` (useful from a multi-space checkout). |
| `LAIT_PORT` | Engine port (default `7717`). |
| `LAIT_TOKEN` | **Skip spawning.** Use an engine you started yourself, with this token. |

`npm run dev -- --host` and any other flags pass straight through to Vite.

### Driving your own engine

Set `LAIT_TOKEN` and the script won't spawn one — it uses yours. Get the token from
the engine you started:

```bash
lait serve --json      # → {"url":"…","token":"…","port":7717}
LAIT_TOKEN=<that-token> npm run dev
```

`npm run dev:vite` is the bare Vite server with nothing wired up, for when you want to
manage the engine entirely by hand.

### Why a token at all — the one thing worth understanding

Vite serves the client on `:5178`; the engine listens on `:7717`. **Two origins.**
`lait serve` refuses cross-origin requests on purpose — a strict `Host`/`Origin`
allowlist is what stops a hostile web page from reaching your loopback engine via DNS
rebinding (`src/serve/auth.rs`). Relaxing that guard for dev convenience would make it
stop meaning anything.

So the guard never relaxes. The **dev proxy** adapts instead
(`vite.config.ts`): it strips the browser's `Origin`, and presents the run's token as
a bearer credential the cross-origin cookie jar cannot supply. Production ships with
no dev flag in the binary at all — the client is same-origin because the engine serves
it, which is the precondition for the whole guard.

## The production path

`npm run build` writes the bundle straight into `../src/serve/assets`, and **that
directory is committed to git.** This looks wrong until three facts line up:

- `Cargo.toml` excludes `viewer/` from the published crate.
- `build.rs` never shells out to a JS toolchain, so `cargo install lait` stays
  reproducible with only Rust.
- `src/serve/shell.rs` embeds the bundle with `include_dir!` at **compile time**.

So the bundle cannot be built during `cargo build` (that would need npm) and cannot
live in `viewer/` (that never reaches crates.io). Committing the built output under
`src/` is what keeps `lait serve` a single self-contained binary for people who
install from source. CI diffs a fresh rebuild against the committed one, so a stale
bundle fails the build rather than shipping silently.

**After editing `src/`, a change is visible three ways, in increasing cost:**

| You want | Do |
|---|---|
| Fast iteration with HMR | `npm run dev` (nothing else) |
| The change inside a real `lait serve` | `npm run build && cargo build && lait serve` |
| CI to accept the branch | commit the rebuilt `../src/serve/assets` |

`cargo build` picks up an asset change on its own now — `build.rs` tells cargo the
bundle is a source input. (Older docs told you to `touch src/serve/shell.rs` first;
that ritual is gone.)

## Layout

| Path | What |
|---|---|
| `src/core/registry.ts` | The command seam. Everything is a projection of this. |
| `src/core/` | Pure, tested logic: keys, filter, overlay, workflow, activity, fuzzy. |
| `src/ui/` | React components. `Picker` is the shared control every field uses. |
| `src/api.ts` | The whole backend: `fetch` over the control plane. |
| `src/types.ts` | Hand-maintained mirror of the engine's Layer-B DTOs. Read the header. |
| `scripts/dev.mjs` | The one-command loop above. |

## Tests

```bash
npm run check        # tsc, no emit
npm test             # vitest — the core/ logic
```

The core is where the tests are, because the core is where the decisions are. A
component test that renders a `Picker` proves less than the `filter`/`overlay`/
`workflow` tests that pin what the client is *allowed to believe*.
