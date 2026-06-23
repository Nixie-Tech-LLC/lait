# Install Hygiene & Identity Pruning — Design

**Date:** 2026-06-23
**Status:** Approved (brainstorm)

## Problem

Two independent install mechanisms leave the machine in a "messy" state:

- GitLab CI `install.sh` installs to `~/.local/bin`.
- The cargo-dist installer installs to `~/.cargo/bin` (with a `groupchat-update`
  self-updater alongside).

Neither knows about the other, so reinstalling produces **duplicate / old
binaries that shadow each other on `$PATH`** and never converge to a single
clean install. Observed in practice: two `groupchat` v0.2.2 binaries, one in
each dir, with the cargo-dist installer warning "shadowed by other commands in
your PATH."

Separately, the per-session identity model ("model B") mints a **fresh identity
per session** under `agents/agent-<sid>/`, so abandoned identity homes
accumulate over time.

## Non-goals

- **Cleaning dev build artifacts (`target/`).** A dev concern, not the shipped
  binary's job.
- **Wiping node state on reinstall.** Old state does *not* break a new binary
  (see below), and wiping it would destroy the user's identity. Explicitly
  rejected.
- **Auto-editing the user's shell rc** (`~/.zshrc`, etc.). Too invasive; warn
  instead.

## Key finding: old state is safe with a new binary

Verified against `src/config.rs`:

- `secret.key` — stable hex-encoded key; carries over by design. This is
  **identity continuity**, the desired behavior, not a bug.
- `profile.json` — newer fields (`auto_approve`, `mute_below`) are
  `#[serde(default)]`, so old files written before those fields still parse.
  serde ignores unknown fields, so newer files don't break older binaries
  either.
- The runtime already self-heals stale peers via `Contacts::remove_stale_nick`
  ("a peer rejoins under the same nick with a fresh identity, e.g. after a
  reinstall").

The only real risks — none of which are "reinstall breaks the binary":

1. **Behavioral leftovers**, e.g. a stale `profile.json` with
   `auto_approve: true` from a past invite.
2. **Latent schema-break risk**: there is no on-disk version field or migration
   layer, so a *future* incompatible format change would fail `from_str`.
3. **Accumulation** of abandoned per-session identity homes.

This is why state-wiping is **decoupled** from reinstall and made an explicit,
opt-in housekeeping command.

## Design

Two new subcommands, clean split by risk.

### `groupchat doctor` — binary/install hygiene (safe, automatable)

Converges the machine to a single install. Touches **binaries, `$PATH`
diagnosis, and running daemons only** — never identity/state.

Steps:

1. **Discover** candidate binaries: every directory in `$PATH`, plus known
   install dirs (`~/.cargo/bin`, `~/.local/bin`, `/usr/local/bin`,
   `/opt/homebrew/bin`, `~/bin`). Canonicalize (resolve symlinks) and dedupe.
2. **Choose keeper**: `std::env::current_exe()` — the running binary is the
   authority. Installers run `<new-binary> doctor`, so the keeper is the
   freshly-installed copy. Overridable with `--keep <path>`.
3. **Remove** every other groupchat binary via `fs::remove_file`. Also remove an
   orphaned `groupchat-update` whose sibling binary was removed; keep the
   updater next to the keeper. Permission errors (e.g. `/usr/local/bin`) are
   **reported, not fatal**.
4. **PATH check**: if the keeper's dir is missing from `$PATH`, or is shadowed by
   another dir earlier in `$PATH`, print a clear hint with the exact line to add.
   Never edit shell rc.
5. **Stale daemon**: find running daemons (per-home `control.sock` / process
   scan) and stop them so the new binary's daemon takes over. `--no-stop-daemon`
   to skip.

Flags: `--dry-run` (report only), `--yes` / `-y` (no prompt; used by installers),
`--keep <path>`, `--no-stop-daemon`. Default behavior prompts for confirmation
before removing anything; in a non-interactive context (no TTY) it refuses
destructive steps unless `--yes` is given.

Output: a report — found / kept / removed / PATH status / daemons stopped.

### `groupchat prune` — identity housekeeping (manual, opt-in, confirmed)

Lists per-session identity homes under `config_root()/agents/` with: nick,
last-active (mtime), whether currently mapped in `sessions.json`, and size; lets
the user remove abandoned ones. **Never automatic; never tied to reinstall.**

Flags: interactive selection by default; `--unmapped` (only identities absent
from `sessions.json`), `--older-than <dur>`, `--yes`. Always confirms before
deleting unless `--yes`.

### Installer integration

- **GitLab `install.sh`** (we control it): after placing the binary, call
  `groupchat doctor --yes`.
- **cargo-dist installer** (generated; no easy post-install hook): rely on a
  cheap startup duplicate-detection (below). No auto-delete on plain runs.
- **Startup hint**: on any invocation, a cheap check — are there ≥2 `groupchat`
  on `$PATH`, or is `current_exe()` shadowed? — prints a single hint line to
  stderr ("duplicate/shadowed install — run `groupchat doctor`"). Never deletes.

## Module layout

- New `src/doctor.rs`:
  - **Pure decision functions** (unit-testable, no I/O): keeper selection given a
    candidate set; "which to remove"; PATH-shadow detection given a synthetic
    `$PATH`; orphaned-updater detection.
  - **Side-effecting ops**: discovery, `fs::remove_file`, daemon stop — thin
    wrappers around the pure logic.
- `prune` logic reuses `config::registry()` / `config_root()`; lives in
  `doctor.rs` or a small `prune.rs`.
- Wire `Doctor` and `Prune` subcommands into `main.rs` / the `Command` enum.

## Testing

- **Pure functions**: keeper selection; removal set; PATH-shadow detection over a
  synthetic `$PATH`; orphan-updater detection.
- **fs ops**: against a temp dir — create fake `groupchat` binaries in several
  dirs, run removal, assert the keeper survives and others are gone; assert a
  permission error on one path doesn't abort the rest.
- **prune**: temp config root with fake identity homes + `sessions.json`; assert
  `--unmapped` / `--older-than` selection picks the right set.

## Error handling

- Never remove `current_exe()`.
- Permission-denied on a path → report and continue; don't abort the run.
- No-TTY + no `--yes` → refuse destructive steps with a clear message.
