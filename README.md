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
  plus the iroh endpoint (an ed25519 `EndpointId` identity), a signed-gossip room
  for announce/presence, and a local control channel. Auto-spawned on first use.
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

State lives under `$LAIT_HOME` (or the platform config dir): `secret.key`,
`profile.json`, and a `repo/` git store (`genesis.json`, `catalog.loro`,
`docs/<id>.loro`). Only public keys and Loro snapshots are stored — never secrets.

### How it maps to iroh

| Piece | Mechanism |
|---|---|
| Identity / handle | a persistent `EndpointId` (ed25519 public key) |
| The room / workspace | an `iroh-gossip` topic (derived from the room name) |
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

## Quickstart (the tracker)

```bash
lait projects new "Engineering" --key ENG   # create a project
lait new "fix login race" -p ENG -P high     # → prints iss_… (and ENG-1)
lait new "add dark mode"  -p ENG -P low
lait board ENG                               # workflow columns × ordered rows
lait edit ENG-1 --status in_progress         # refer by KEY-n or iss_ prefix
lait assign ENG-1 @me
lait comment ENG-1 "looking into it"
lait show ENG-1                              # full issue: body, comments, meta
lait ls --mine                               # your open issues
lait activity                                # workspace transition feed
lait tui                                     # full-screen interactive board
```

Scripts capture the resolved handle from `--json`:

```bash
id=$(lait new "fix login" -p ENG --json | jq -r .reff)
```

## CLI reference

Issue verbs (act on one issue by `<ref>` — a short `iss_` handle or a `KEY-n` alias):

| Command | Description |
|---|---|
| `new <title> [-p PROJ] [-a USER…] [-P PRIO] [-l LABEL…] [-b BODY]` | Create an issue |
| `ls [-p PROJ] [--mine] [--status S] [--label L] [--all]` | List rows from the catalog cache |
| `board <PROJ>` | Render the project's board |
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
| `projects [new <name> --key KEY \| ls]` | Manage the project registry |
| `labels [new <name> --color C \| ls]` | Manage the label registry |
| `members [add <userref> [--admin] \| remove <userref> \| rotate-key \| ls]` | Manage E2EE membership (signed ACL); add seals the key, remove rotates it |
| `activity [--since N]` | Workspace-wide recent transitions |
| `tui` | Launch the full-screen board |
| `status` · `id` · `stop` | Node/workspace status · endpoint id · stop daemon |
| `invite` · `join` · `connect` · `who` · `wait` · `watch` | P2P transport (P1 surface) |
| `agents` / `resume <name>` | Manage per-session identities |

Global flags: `--home DIR`, `--json`, `--no-color`. Exit codes: `0` ok · `1`
usage/error · `2` ref not found / ambiguous · `3` daemon unreachable.

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

```bash
# host — create work, then share a ticket (carries the workspace + genesis)
lait invite                        # → a base32 ticket; send it to a peer

# peer — join from the ticket (adopts the workspace, backfills over sync)
lait connect <TICKET> --nick bob
lait id                            # → bob's key; send it to the host

# host — admit bob (seals him the workspace key); now bob can decrypt + edit
lait members add <BOB_KEY>
lait members                       # admin you · member bob
# later: revoke — rotates the key so bob can't read new content (lazy revocation)
lait members remove <BOB_KEY>
```

Workspace data is E2EE: issues sync as ciphertext, and a node that isn't in the
signed ACL (or has been removed) sees only ciphertext. Changes propagate live P2P
over iroh with no central server; any always-on node advertised in a ticket acts
as a portable seed that backfills cold clients.

## Running several nodes on one machine

Set a distinct `LAIT_HOME` per node:

```bash
LAIT_HOME=/tmp/alice lait init --nick alice --room demo
LAIT_HOME=/tmp/bob   lait init --nick bob   --room demo
```
