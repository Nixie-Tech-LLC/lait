# Changelog

## v0.4.4 — crates.io + winget publishing

- **All channels live.** Adds automated **crates.io** publishing
  (`publish-crates.yml`, same `workflow_run` trigger — `cargo install lait` +
  docs.rs) and enables **winget** submission. With Homebrew, Scoop, `cargo
  binstall`, and the GitHub Release, a single version tag now publishes to every
  supported channel automatically.

## v0.4.3 — fully automatic release publishing

- **One release run publishes everywhere.** The Homebrew, Scoop, and winget
  publishers are now cargo-dist **custom publish jobs** (`publish-jobs` →
  reusable `workflow_call` workflows), invoked by the release run itself after it
  hosts the release. No more manual `workflow_dispatch` after each tag — pushing a
  version tag builds, releases, and pushes to the tap + bucket end to end. Each job
  still mints its own short-lived token from the org GitHub App and soft-skips if
  its credentials are absent.

## v0.4.2 — distribution: one command on every platform

- **GitHub is the canonical home.** Removed the GitLab CI + `homepage` split-brain
  (Cargo.toml + the Claude plugin now point at `github.com/Nixie-Tech-LLC/lait`);
  local node state (`.lait/`, `.groupchat/`) is gitignored.
- **Every install path works.** `cargo install`, `cargo binstall` (prebuilt, no
  compile), Homebrew (`brew install nixie-tech-llc/tap/lait`), Scoop, winget, a
  Docker image for an always-on **seed node**, and `lait completions <shell>` /
  `lait man` generated from the CLI itself. New `docs/INSTALL.md` covers the matrix.
- **Distribution CD.** On each release, the Homebrew formula and Scoop manifest are
  published automatically using a short-lived token minted from the org GitHub App
  (no long-lived PAT); a CI job structurally validates the Scoop + winget manifests.
- Hardened tests for the new stateless CLI surfaces (`tests/cli_surfaces.rs`).

## v0.4.1 — native in-place updater

- **Native in-place updater.** `lait update` now self-updates in-process from the
  latest GitHub release — no external `lait-update` companion binary. It stops a
  running daemon first (so the swap isn't blocked by a held file handle on
  Windows), then downloads this platform's release asset and atomically replaces
  the running executable. Pure-Rust throughout (`ureq` + rustls for HTTP,
  gzip/zip extraction, atomic self-replace), consistent with the no-C-deps ethos.
  Unix release archives switch from `.tar.xz` to `.tar.gz` so extraction needs no
  liblzma; the cargo-dist external updater is no longer shipped (`install-updater
  = false`).

## v0.4.0 — renamed `groupchat` → `lait`

Project rename. The binary, library, package, MCP server, and all identifiers are
now `lait`. This is a **clean break** (pre-1.0): env vars are `LAIT_*` (was
`GROUPCHAT_*`), the per-repo store directory is `.lait/` (was `.groupchat/`), the
config/identity root moves accordingly, the invite link scheme is `lait://join/`,
and the wire ALPNs + crypto domain-separation tags are re-tagged under `lait/…`.
A `lait` node therefore does not interoperate with a `groupchat` node, and an
existing `.groupchat/` store is not adopted — re-found the workspace from a fresh
`lait` invite. The GitHub repository moved to `Nixie-Tech-LLC/lait` (old URLs
redirect).

## v0.3.2 — durability & sync-liveness hardening

Follow-up hardening from a durability audit of the local-first / iroh
distribution layer (tracked as the `DUR` project inside groupchat itself):

- **Crash- and power-loss-durable local writes (DUR-2).** `write_atomic` now
  `fsync`s the temp file before the rename and `fsync`s the parent directory
  after it (unix), closing the rename-without-`fsync` window where an already-
  acked write could be lost on power loss. Atomicity is unchanged; a no-op on
  Windows, where `MoveFileEx` durability is handled by the filesystem.
- **Restart reconnection (DUR-1).** The daemon persists the peers it has met
  (`peers.json`, written when the mesh forms) and seeds gossip bootstrap from
  them on start, so a restarted node actively rejoins the mesh instead of waiting
  to be re-announced to. Verified end-to-end: a node killed mid-workspace
  restarts and reconverges to changes made while it was down.
- **Stay online to serve sync (DUR-3).** A daemon that has ever meshed with a
  peer no longer idle-shuts-down, so its changes stay pullable; only a solo,
  never-meshed node (auto-spawned for a one-off command) still idles out.
- **Always-on seed (DUR-4).** `groupchat daemon --seed` runs a node that never
  idles — once added to the workspace with `members add`, it holds full history
  and serves offline-to-offline handoff and GC-boundary backfill.
- **Pinned seed peers — the P2P "remote".** `groupchat seed add <ticket|id>`,
  `seed ls`, `seed rm` pin an always-on seed your node always dials and eagerly
  backfills from on startup, so a cold or long-offline client converges through
  its seed even when no ordinary peer is online. Pins grant no trust (genesis/ACL
  still gate every op).
- **Repo-bound stores (DUR-5).** The workspace store is discovered git-style:
  `groupchat` walks up from the cwd for a `.groupchat/` and binds it, else auto-
  creates one in the cwd — so each repo gets its own workspace, daemon, and room
  (defaulted to the repo directory name). Identity is now **global** (one
  `secret.key` under the config dir) so one identity spans every repo, like a
  single `git` `user.email`. `$GROUPCHAT_HOME` still collapses both into one
  self-contained dir; a `.gitignore` is dropped in each store so it is never
  committed. (Windows: the extended-length `\\?\` prefix is now stripped from
  resolved store paths, which several Windows tools/APIs choke on.)
- **In-place updates — `groupchat update`.** Runs the bundled cargo-dist
  self-updater (`groupchat-update`) from one entry point, stopping a running
  daemon first so the binary can be swapped (notably on Windows, where a live
  daemon holds a lock on the exe). Falls back to clear guidance when the updater
  isn't installed (e.g. a `cargo install` build).

Still open (tracked in `DUR`): the blind encrypted relay — a ciphertext-only,
untrusted-host seed (DUR-6).

## v0.3.0 — the P2P, E2EE issue tracker (release candidate)

groupchat becomes a working **local-first, peer-to-peer, end-to-end-encrypted
issue tracker** — a decentralized, rapid-feedback alternative to Linear that runs
as a native Rust node, built on [iroh](https://www.iroh.computer/) (P2P QUIC) and
[Loro](https://loro.dev/) CRDTs over a git-backed durable store. Verified
multi-node over real iroh on Linux, macOS, and Windows.

### Highlights

- **A fast, standalone tracker (P0).** Create / edit / move / assign / label /
  comment / close issues from a CLI, a full-screen [ratatui](https://ratatui.rs)
  TUI, or an MCP agent — all driving one daemon that owns the Loro documents.
  Boards and lists render from a catalog cache (no per-issue loads); issues carry
  a short git-style `iss_` handle plus a friendly `ENG-142` alias. The TUI stays
  live off a doorbell event stream and echoes edits optimistically.
- **Live P2P sync (P1).** Catalog-first sync over a custom iroh ALPN: two nodes
  converge in ~2s with no central server. A portable **seed** role — any headless
  node advertised in a ticket — backfills a cold client from nothing but the
  ticket. Three-state presence (online / away / offline).
- **End-to-end encryption + membership (P3).** Workspace data is E2EE, gated by a
  **signed ed25519 ACL op-graph** (add / remove / roles, deterministic replay,
  remove-wins). The workspace key is distributed via X25519 sealed boxes and
  **rotated on removal** (lazy revocation); a non-member — or a removed member —
  sees only ciphertext. `members add/remove/rotate-key/ls` on the CLI, MCP, and a
  TUI members view. Pure-Rust crypto (RustCrypto/dalek) — no C toolchain, no
  `aws-lc`.
- **Agent-native (MCP).** The full tracker surface is exposed as MCP tools that
  return the same versioned DTO the CLI `--json` emits; a build-gate parity test
  keeps the human and agent surfaces in lock-step.

### Cross-platform & release

- Builds and runs on **Linux, macOS, and Windows**; the hardened CI gate (build +
  test with `-D warnings`, fmt, clippy, doctests, MSRV 1.91, `cargo-deny`,
  portability guard, DTO/MCP parity, a per-OS end-to-end smoke, and a release
  dry-run) covers all three. The gate reproduces green on Windows and Linux
  (the latter incl. real-iroh multi-host convergence); the earlier macOS smoke
  regression (a broken-pipe panic) is fixed.
- Release binaries for macOS (arm64 + x86), Linux (arm64 + x86), and **Windows
  (x64)** are produced by the cargo-dist pipeline on a version tag, with shell +
  PowerShell installers, per-target self-updater, and SHA-256 checksums. The
  Windows and Linux binaries have been built and run natively; the macOS targets
  build via the release pipeline.

### Validation & fixes (this candidate)

An independent validation pass (adversarial security + CRDT review, real
multi-host P2P on separate Linux hosts, and scaling measurement) hardened the
candidate:

- **Revocation is now sound.** The signed-ACL op signature binds its causal
  `parents` and the workspace id, closing a bypass where an evicted member could
  re-parent an admin's still-valid `AddMember` op past their removal. ACL replay
  is also fully deterministic (Kahn topological sort), so every node computes the
  same membership and seals each epoch key to the same set.
- **Issue bodies sync across real networks.** A connection-teardown race that
  truncated the trailing document frames (only catalog rows converged, bodies
  stayed provisional) is fixed; a cross-node body-sync assertion guards it.
- **Piping CLI output no longer panics** (`groupchat board | head`).

Install (once released):

```sh
# macOS / Linux
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Nixie-Tech-LLC/groupchat/releases/download/v0.3.0/groupchat-installer.sh | sh
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/Nixie-Tech-LLC/groupchat/releases/download/v0.3.0/groupchat-installer.ps1 | iex"
```

Upgrade in place with `groupchat-update`.

### Known limitations (accepted / deferred)

- The E2EE layer implements a proven *design* by hand and is **research-grade**:
  unaudited, and it needs independent review before carrying truly sensitive data.
- Lazy revocation only (no clawback of already-synced data); metadata (sizes,
  timing) is visible to a relay; all members of a workspace read all its issues.
- The blind-relay **ciphertext-chunk sedimentree** compaction (P2) is designed but
  its GC is deferred — encrypted sync already makes the seed a blind relay.
- Deferred: RIBLT scale escape-hatch, account-aggregates-devices identity, and a
  CGKA (BeeKEM) key-agreement upgrade over the current sealed-box distribution.
- **Write throughput is not yet optimized.** Each issue create/edit rewrites the
  whole catalog snapshot, rebuilds the alias table, and makes a git commit, so
  bulk authoring is super-linear in workspace size (per-issue interactive latency
  is fine at hundreds of issues, noticeable at thousands). Board/list reads and
  cold-load remain catalog-only. Incremental persistence (append `export(updates)`
  + batched commits) is the planned fix.
- **Catalog-first sync assumes bidirectional gossip.** The changed-doc set is
  derived from the LWW-merged catalog head; under strictly one-directional
  connectivity a puller whose own head write out-ranks the provider's can defer a
  fetch until a reverse pull re-stamps it. It self-heals under the normal
  gossip-both-ways mode; deriving the changed set from the catalog op-diff is the
  planned hardening.

Foundation preserved from the earlier chat-oriented releases: the iroh endpoint +
ed25519 identity, signed-gossip room, presence, daemon + cross-platform control
channel, CLI, and MCP plumbing.
