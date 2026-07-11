# groupchat

A **local-first, peer-to-peer issue tracker** — a decentralized, rapid-feedback
alternative to Linear that runs as a native Rust node, built on
[iroh](https://www.iroh.computer/) (P2P QUIC + NAT traversal) and
[Loro](https://loro.dev/) CRDTs, with a git-backed durable store.

> **Status: P0 complete (single node).** A working, standalone, git-backed issue
> tracker runs today: create/edit/move/assign/label/comment/close issues from a
> CLI, a full-screen TUI, or an MCP agent, all driving one daemon that owns the
> Loro documents. Live P2P sync (P1), the encrypted blind-relay seed (P2), and
> E2EE membership/rotation (P3) are the next phases — the wire formats are
> designed so they add on without reshaping P0. See
> [`docs/ROADMAP.md`](docs/ROADMAP.md) for phase status and
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) /
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

- `groupchat daemon` — the long-lived node: **owns the Loro documents** (a
  per-workspace catalog + one doc per issue) over a **git-backed durable store**,
  plus the iroh endpoint (an ed25519 `EndpointId` identity), a signed-gossip room
  for announce/presence, and a local control channel. Auto-spawned on first use.
- `groupchat <cmd>` — the CLI: flat verbs act on issues (`new`, `edit`, `move`,
  `assign`, `label`, `comment`, `show`, `ls`, `board`, `history`), plural nouns
  manage registries (`projects`, `labels`). `--json` emits a stable, versioned
  DTO for scripts and agents.
- `groupchat tui` — a full-screen [ratatui](https://ratatui.rs) board client that
  stays live off a doorbell event stream and echoes edits optimistically.
- `groupchat mcp` — an MCP (stdio) server exposing the same commands as tools, so
  an agent files and drives issues natively (returning the same versioned DTO).

Issues are addressed by a short, git-style `iss_` handle (collision-free) with a
friendly `KEY-n` alias (`ENG-142`). Refs resolve daemon-side; an ambiguous ref
returns a candidate list, not an error. Boards render from the catalog cache
(no per-issue loads), so a large workspace still paints instantly.

State lives under `$GROUPCHAT_HOME` (or the platform config dir): `secret.key`,
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

## Install (prebuilt, macOS/Linux)

`groupchat` is a single self-contained binary. Every tag is built for macOS
(arm64 + x86) and Linux (arm64 + x86) and published as a GitHub Release.

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Nixie-Tech-LLC/groupchat/releases/latest/download/groupchat-installer.sh | sh
```

The installer places `groupchat` in `~/.cargo/bin`. Upgrade in place with
`groupchat-update`.

## Quickstart (the tracker)

```bash
groupchat projects new "Engineering" --key ENG   # create a project
groupchat new "fix login race" -p ENG -P high     # → prints iss_… (and ENG-1)
groupchat new "add dark mode"  -p ENG -P low
groupchat board ENG                               # workflow columns × ordered rows
groupchat edit ENG-1 --status in_progress         # refer by KEY-n or iss_ prefix
groupchat assign ENG-1 @me
groupchat comment ENG-1 "looking into it"
groupchat show ENG-1                              # full issue: body, comments, meta
groupchat ls --mine                               # your open issues
groupchat activity                                # workspace transition feed
groupchat tui                                     # full-screen interactive board
```

Scripts capture the resolved handle from `--json`:

```bash
id=$(groupchat new "fix login" -p ENG --json | jq -r .reff)
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
groupchat install-mcp --client claude     # or: cursor | windsurf | generic
```

It merges a `groupchat` entry into that client's `mcpServers` (preserving any
others), using this binary's absolute path and carrying `GROUPCHAT_HOME` if set.
`--scope user|project` picks the config location; `--print` shows the result
without writing.

Or add it to `.mcp.json` by hand:

```json
{
  "mcpServers": {
    "groupchat": {
      "command": "/absolute/path/to/groupchat",
      "args": ["mcp"],
      "env": { "GROUPCHAT_HOME": "/Users/you/.groupchat" }
    }
  }
}
```

Tools exposed: the full tracker surface — `issue_new`, `issue_edit`,
`issue_move`, `assign`, `label`, `comment`, `issue_delete`, `issue_view`, `list`,
`board`, `history`, `project_new`, `project_list`, `label_new`, `label_list`,
`activity` — plus transport (`status`, `my_id`, `invite_ticket`, `join_room`,
`connect`, `who`). Each returns the **same versioned JSON DTO** the CLI `--json`
emits; a build-gate parity test keeps the agent and human surfaces in lock-step.

## Running several nodes on one machine

Set a distinct `GROUPCHAT_HOME` per node:

```bash
GROUPCHAT_HOME=/tmp/alice groupchat init --nick alice --room demo
GROUPCHAT_HOME=/tmp/bob   groupchat init --nick bob   --room demo
```
