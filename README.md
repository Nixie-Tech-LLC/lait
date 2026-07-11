# groupchat

A **local-first, peer-to-peer issue tracker** — a decentralized, rapid-feedback
alternative to Linear that runs as a native Rust node, built on
[iroh](https://www.iroh.computer/) (P2P QUIC + NAT traversal) and
[Loro](https://loro.dev/) CRDTs, with a git-backed durable store.

> **Status: foundation stage.** The repo currently ships the **transport +
> identity + presence + daemon skeleton** the tracker is built on — the iroh
> foundation kept from the project's chat-app origins. The issue model (Loro
> docs, the catalog, per-doc sync) is specified and being built on top of it.
> See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
> [`docs/SCHEMA.md`](docs/SCHEMA.md) for the full plan.

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
authority model live in [`docs/SCHEMA.md`](docs/SCHEMA.md).

## What runs today (the skeleton)

One binary, three roles, sharing one persistent node:

- `groupchat daemon` — the long-lived node: owns the iroh endpoint (an ed25519
  `EndpointId` identity), a signed-gossip room for announce/presence, a
  liveness-probe ALPN, and a local control channel. Auto-spawned on first use.
- `groupchat <cmd>` — a CLI client that drives the daemon over a local IPC
  channel.
- `groupchat mcp` — an MCP (stdio) server exposing the actions as tools so an
  agent can drive it natively.

State lives under `$GROUPCHAT_HOME` (or the platform config dir): `secret.key`
and `profile.json`.

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
binaries are currently produced for macOS and Linux; Windows builds from source.

## Build (from source)

```bash
cargo build --release
```

Requires a recent stable Rust toolchain (the dependency set uses `edition2024`,
so **Rust 1.85+**).

## Install (prebuilt, macOS/Linux)

`groupchat` is a single self-contained binary. Every tag is built for macOS
(arm64 + x86) and Linux (arm64 + x86) and published as a GitHub Release.

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Nixie-Tech-LLC/groupchat/releases/latest/download/groupchat-installer.sh | sh
```

The installer places `groupchat` in `~/.cargo/bin`. Upgrade in place with
`groupchat-update`.

## Quickstart (two nodes)

```bash
# --- host ---
groupchat invite                      # prints a ticket; send it to your peer

# --- peer (cold machine — no init needed) ---
groupchat connect <TICKET> --nick bob # joins the room and goes live

# then
groupchat who                         # ● online  ○ offline
groupchat wait                        # block until the next event (presence/join/system)
```

## CLI reference

| Command | Description |
|---|---|
| `init [--nick N] [--room R]` | Create identity + settings |
| `id` | Print your endpoint id |
| `status` | Node + room status |
| `invite` | Print a base32 room ticket to share |
| `join <ticket>` | Join a room and announce a join request |
| `connect <ticket> [--nick N]` | One step: join + go live |
| `log [--since N]` | Print presence/system events (returns immediately) |
| `wait [--since N] [--timeout-ms M]` | Block until a new event arrives, then print it |
| `watch [--since N] [--exec CMD] [--notify]` | Follow events; run a hook / desktop-notify per event |
| `who` | List peers with online status |
| `agents` / `resume <name>` | Manage per-session identities |
| `daemon` | Run the node in the foreground |
| `mcp` | Run the MCP server over stdio |
| `stop` | Stop the daemon |

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

Tools exposed today: `status`, `my_id`, `invite_ticket`, `join_room`, `connect`,
`poll`, `wait`, `who`. The issue-tracker tools (file/update/watch/close an issue)
arrive as the Loro model lands.

## Running several nodes on one machine

Set a distinct `GROUPCHAT_HOME` per node:

```bash
GROUPCHAT_HOME=/tmp/alice groupchat init --nick alice --room demo
GROUPCHAT_HOME=/tmp/bob   groupchat init --nick bob   --room demo
```

<!-- qadi smoke test: verifying the hosted reviewer end-to-end; safe to close -->
