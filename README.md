# lait

A **local-first, peer-to-peer issue tracker** — a decentralized, rapid-feedback
alternative to Linear that runs as a native Rust node, built on
[iroh](https://www.iroh.computer/) (P2P QUIC + NAT traversal) and
[Loro](https://loro.dev/) CRDTs, with a git-backed durable store.

> **Status: P0–P3 complete, verified multi-node.** A working, standalone tracker
> (create/edit/move/assign/label/comment/close issues from a CLI, a full-screen
> TUI, or an MCP agent over one git-backed daemon), with **live P2P sync over
> iroh** (no central server — two nodes converge in ~2s), a **portable seed** that
> backfills a cold client from just a ticket, and **end-to-end encryption** gated
> by a signed membership graph with add/remove + key rotation (a non-member sees
> only ciphertext; removal + rotation enforces lazy revocation). Remaining: P4
> release engineering + hardening. See [`docs/ROADMAP.md`](docs/ROADMAP.md) for
> phase status and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) /
> [`docs/SCHEMA.md`](docs/SCHEMA.md) / [`docs/UI.md`](docs/UI.md) for the design.

## What it is (the plan)

Issues are **Loro CRDT documents**, propagated **peer-to-peer over iroh** with no
central server; each node keeps a durable copy in a local **git repo**. It is
built in provable layers:

1. **Functionality (git-backed):** a Loro issue model + catalog + fast TUI,
   persisted in a local git repo. A standalone tracker with Linear-grade speed —
   no network, no crypto.
2. **Propagation (iroh):** live P2P sync over QUIC, reactive across nodes.
3. **Access control (E2EE):** encrypted, blind-relay sync with membership and
   revocation.

The full design, phase plan, and decision log live in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the concrete data shapes and
authority model live in [`docs/SCHEMA.md`](docs/SCHEMA.md); the CLI and TUI
surfaces live in [`docs/UI.md`](docs/UI.md).

## What runs today (P0)

One binary, four surfaces, sharing one persistent node:

- `lait daemon` — the long-lived node: **owns the Loro documents** (a
  per-workspace catalog + one doc per issue) over a **git-backed durable store**,
  plus the iroh endpoint (an ed25519 `EndpointId` identity), a signed-gossip
  topic for announce/presence, and a local control channel. Auto-spawned on first use.
- `lait <cmd>` — the CLI: flat verbs act on issues (`new`, `edit`, `move`,
  `assign`, `label`, `comment`, `show`, `ls`, `board`, `history`), plural nouns
  manage registries (`projects`, `labels`). `--json` emits a stable, versioned
  DTO for scripts and agents.
- `lait tui` — a full-screen [ratatui](https://ratatui.rs) board client that
  stays live off a doorbell event stream and echoes edits optimistically.
- `lait mcp` — an MCP (stdio) server exposing the same commands as tools, so
  an agent files and drives issues natively (returning the same versioned DTO).

Issues are addressed by a short, git-style `iss_` handle (collision-free) with a
friendly `KEY-n` alias (`ENG-142`). Refs resolve daemon-side; an ambiguous ref
returns a candidate list, not an error. Boards render from the catalog cache
(no per-issue loads), so a large workspace still paints instantly.

State lives in a per-repo `.lait/` store (or a self-contained `$LAIT_HOME`):
`config.json` (local settings) and a `repo/` git store (`genesis.json`,
`catalog.loro`, `docs/<id>.loro`); one global `secret.key` identity spans every
store. Only public keys and Loro snapshots are stored — never secrets. Stores are
created **only** by `lait init` (found) or `lait join` (from an invite) — nothing
mints one implicitly.

### How it maps to iroh

| Piece | Mechanism |
|---|---|
| Identity / handle | a persistent `EndpointId` (ed25519 public key) |
| The workspace | an `iroh-gossip` topic (derived from the workspace id) |
| Announce + presence | signed gossip heartbeats + neighbor events + a `Bye` on shutdown |
| Liveness probe | a direct QUIC handshake on a custom ALPN |
| Signed messages | ed25519 `SignedMessage` sign/verify (→ signed membership ops later) |

## Cross-platform

The node builds and runs on **Linux, macOS, and Windows** — CI builds and tests
all three on every change. The daemon's control channel is a Unix-domain socket
on unix and a named pipe on Windows (via `interprocess`); the single-instance
guard is a cross-platform advisory lock (`fs2`); TLS uses the portable `ring`
rustls backend (CI fails if `aws-lc-rs` ever enters the tree). Prebuilt release
binaries are produced for macOS, Linux, **and Windows** (with a PowerShell
installer), and the per-OS CI smoke drives the real tracker flow on each.

## Build (from source)

```bash
cargo build --release
```

Requires **Rust 1.91+** (the floor is driven by iroh 1.0.0-rc.1).

To catch formatting issues before they reach CI, enable the pre-push hook once
per clone (it runs `cargo fmt --all --check` and blocks the push if it fails;
bypass with `git push --no-verify`):

```bash
git config core.hooksPath .githooks
```

## Install

`lait` is a single self-contained binary, built for **macOS, Linux, and Windows**
(arm64 + x86_64) and published as a GitHub Release on every tag. Pick a channel —
they all land the same `lait`. Full matrix + verification in
[`docs/INSTALL.md`](docs/INSTALL.md).

```bash
# macOS / Linux — shell installer (places lait in ~/.cargo/bin)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.sh | sh

# Homebrew (macOS / Linux)
brew install nixie-tech-llc/tap/lait

# prebuilt binary via Cargo, no compile
cargo binstall lait

# from source (Rust 1.91+)
cargo install lait --locked
```

```powershell
# Windows — PowerShell installer
powershell -ExecutionPolicy Bypass -c "irm https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.ps1 | iex"
# …or:  scoop install lait   ·   winget install NixieTechLLC.Lait
```

Upgrade any install in place with `lait update` — a native self-updater that pulls
the latest release and swaps the binary (stopping a running daemon first). Shell
completions and a man page come from the binary itself
(`lait completions <shell>`, `lait man`). For an always-on **seed node**, see the
[Docker setup](docker-compose.yml).

### Nightly / dev builds

Every merge to `main` publishes prebuilt binaries to a rolling **[`dev`
prerelease](https://github.com/Nixie-Tech-LLC/lait/releases/tag/dev)** (Linux x64,
macOS arm64/x64, Windows x64) — bleeding edge, for dogfooding the latest `main`.
It's a GitHub *prerelease*, so it never shows as "Latest" and never touches the
package managers or crates.io.

```bash
# grab the current dev build for your platform
gh release download dev -R Nixie-Tech-LLC/lait
```

A dev binary reports its commit so it's unmistakable from a tagged release:
`lait --version` → `lait 0.4.5-dev+<sha> (<date>)`.

## Quickstart (the tracker)

```bash
cd my-project
lait init                                    # found a space here (named after the
                                             # directory, first project seeded)
lait new "fix login race" -P high --start    # file it AND claim it: assigned to you,
                                             # in progress, on branch mp-1-fix-login-race
# ...code, commit...
lait done                                    # ✓ — the ref comes from the branch
lait                                         # bare lait = your focus: inbox + your issues
lait start MP-2                              # claim the next one (branch created)
lait comment "looking into it"               # ref inferred from the branch too
lait board                                   # workflow columns × ordered rows
lait new "polish header" -l ux               # labels are created on first use
lait projects add DSN "Design"               # more projects when you need them
lait inbox                                   # what's addressed to you (durable)
lait tui                                     # full-screen interactive board
lait spaces                                  # every space on this machine
lait -w my-project board                     # target a space from anywhere
lait config set project.default DSN          # default project for `new`/`board`
```

Scripts capture the resolved handle from `--json`:

```bash
id=$(lait new "fix login" -p ENG --json | jq -r .reff)
```

`lait watch` follows the presence/join event stream and can run a hook per event
(`--exec CMD`) or raise a desktop notification (`--notify`). The hook runs in the
platform shell (`sh -c` on Unix, `cmd /C` on Windows) with the event as JSON on
stdin **and** in the environment:

```bash
# ping a webhook whenever someone asks to join
lait watch --exec 'curl -s -X POST "$WEBHOOK" -d "$LAIT_EVENT_NICK joined"'
```

| Env var | Value |
|---|---|
| `LAIT_EVENT_KIND` | `join` · `presence` · `system` |
| `LAIT_EVENT_NICK` | the peer's display name |
| `LAIT_EVENT_ID` | the peer's endpoint id |
| `LAIT_EVENT_TEXT` | human message |
| `LAIT_EVENT_SEQ` · `LAIT_EVENT_TS` | session sequence · unix ts |

## CLI reference

Issue verbs (act on one issue by `<ref>` — a short `iss_` handle or a `KEY-n` alias).
On a git branch named `eng-142-fix-login`, the ref is **optional** for `show` / `edit`
/ `move` / `history` / `delete` — lait infers `ENG-142` from the branch:

```bash
git switch -c eng-142-fix-login
lait show            # → ENG-142, no ref needed
lait edit --status in_progress
```

| Command | Description |
|---|---|
| `new <title> [-p PROJ] [-a USER…] [-P PRIO] [-l LABEL…] [-b BODY] [--start]` | Create an issue (`-p` optional: branch key → `project.default` → sole project; unknown labels created on first use) |
| `start [ref] [--no-branch]` | Claim + activate + branch: assign yourself, first active status, checkout `key-n-slug` |
| `done [ref]` · `stop [ref]` | Finish (first done status) · put down gracefully (backlog, unassigned). Refs infer from the branch |
| `inbox [--clear]` | Durable addressed-to-you: assignments, comments on your work, @mentions |
| `ls [-p PROJ] [--mine] [--status S] [--label L] [--all]` | List rows from the catalog cache (`-p` is a pure filter) |
| `board [PROJ]` | Render a project's board (positional optional, same chain as `new`) |
| `show <ref>` | Full issue (lazily loads the issue doc) |
| `edit <ref> [--title T] [--status S] [--priority P]` | Patch LWW fields (one activity row) |
| `move <ref> [-p PROJ] [--top\|--bottom\|--before R\|--after R]` | Set project and/or board order |
| `assign <ref> <userref…> [--remove]` | Add/remove assignees |
| `label <ref> [+LABEL…] [-LABEL…]` | Add/remove labels |
| `comment <ref> [BODY]` | Append a comment (no BODY → stdin) |
| `delete <ref>` | Tombstone an issue (stays in history) |
| `history <ref>` | The issue's derived activity feed |

Registries + node:

| Command | Description |
|---|---|
| `init [--name N] [--nick N]` | Found a space here (mints the genesis, seeds a first project) |
| `spaces [ls \| forget <sel> \| prune]` | Every space on this machine: name, origin, status, path |
| `config [get \| set \| unset \| ls]` | Layered local settings (`user.nick`, `project.default`); store wins over global |
| `projects [add KEY [NAME] \| ls]` | Manage the project registry (name defaults to the key) |
| `labels [new <name> --color C \| ls]` | Manage the label registry |
| `members [add \| remove \| requests \| approve \| name \| rotate-key \| ls]` | Manage E2EE membership (signed ACL); `add` seals the key, `remove` rotates it, `approve` admits a pending joiner, `name` sets a local label for a key |
| `activity [--since N]` | Workspace-wide recent transitions |
| `tui` | Launch the full-screen board |
| `status` · `id` · `shutdown` | Node/space status · endpoint id · stop the daemon |
| `invite [--require-approval] [--reusable] [--ttl-hours N]` · `join <link> [--dir D]` | Invite a teammate; `join` creates the joiner's store (cwd or `--dir`) and the default pass admits them automatically (add `--require-approval` for the gated `members requests`/`members approve` flow) |
| `who` · `watch` | Peers online · follow the event stream |
| `profiles` / `resume <name>` | List profiles / switch to a named profile (each a separate identity + store) |

Global flags: `--home DIR`, `-w SEL` (target a workspace by name/id/path from any
directory), `--json`, `--no-color`. Exit codes: `0` ok · `1` usage/error · `2` ref
not found / ambiguous · `3` daemon unreachable.

## Use from an AI agent (MCP)

Register the MCP server with your agent in one step:

```bash
lait install-mcp --client claude     # or: cursor | windsurf | generic
```

It merges a `lait` entry into that client's `mcpServers` (preserving any
others), using this binary's absolute path and carrying `LAIT_HOME` if set.
`--scope user|project` picks the config location; `--print` shows the result
without writing.

Or add it to `.mcp.json` by hand:

```json
{
  "mcpServers": {
    "lait": {
      "command": "/absolute/path/to/lait",
      "args": ["mcp"],
      "env": { "LAIT_HOME": "/Users/you/.lait" }
    }
  }
}
```

Tools exposed: the full tracker surface — `issue_new`, `issue_edit`,
`issue_move`, `assign`, `label`, `comment`, `issue_delete`, `issue_view`, `list`,
`board`, `history`, `project_new`, `project_list`, `label_new`, `label_list`,
`activity`, `member_add`, `member_remove`, `key_rotate`, `members` — plus
transport (`status`, `my_id`, `invite_ticket`, `join_room`, `connect`, `who`).
Each returns the **same versioned JSON DTO** the CLI `--json` emits; a build-gate
parity test keeps the agent and human surfaces in lock-step.

## Multi-node & end-to-end encryption

The default invite carries a **signed, single-use pass**, so a teammate is on the
board after a single `join` — no separate approval round-trip:

```bash
# host — mint an invite link (carries the workspace, genesis, and a single-use pass)
lait invite                        # → a link (+ a scannable QR); send it over

# teammate — join from the link (creates the store in the cwd, or pass --dir);
# the pass admits you automatically
lait join <INVITE> --nick bob
lait status                        # you: member   ← board decrypts and syncs

# later: revoke — rotates the key so bob can't read new content (lazy revocation)
lait members remove bob
```

The pass is a **bearer** capability: authority rides the channel you send the link
over, bounded by expiry (`--ttl-hours`, default 7 days) and one use. Tune it, or
keep a human in the loop:

```bash
lait invite --reusable --ttl-hours 24   # one link admits the whole team for a day
lait invite --require-approval          # pass-less link — the classic gated flow:

# teammate — join lands as a *request*; you stay encrypted until an admin approves
lait join <INVITE> --nick bob
lait status                             # you: pending   ← waiting to be approved

# host — see who's waiting, confirm the short key out-of-band, then approve by
# key/prefix (the nick is an unverified claim; `--as` is a local name you assign)
lait members requests                   # bob  (claims "bob")   <key-prefix>
lait members approve <key-prefix> --as bob
```

Workspace data is E2EE: issues sync as ciphertext, and a node that isn't in the
signed ACL (or has been removed) sees only ciphertext. Auto-approval never weakens
this — the seal still happens key-side on an admin node holding the workspace key;
the pass only removes the manual keystroke. Changes propagate live P2P over iroh
with no central server; any always-on node advertised in a ticket acts as a
portable seed that backfills cold clients.

## Running several nodes on one machine

Set a distinct `LAIT_HOME` per node — one founds, the other joins from the invite
(there is no shared "room name": the gossip topic derives from the workspace id
carried in the ticket):

```bash
LAIT_HOME=/tmp/alice lait init --name demo --nick alice
LAIT_HOME=/tmp/alice lait invite                       # → <INVITE>
LAIT_HOME=/tmp/bob   lait join <INVITE> --nick bob
```
