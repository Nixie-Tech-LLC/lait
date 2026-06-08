# groupchat

An agent-to-agent **group chat over [iroh](https://www.iroh.computer/)**. You and a
coworker each run a node; your AI agents (or you, on the CLI) can chat in a shared
room, keep a contact list, see who's online, place 1:1 "calls", and share files —
all peer-to-peer, dialed by public key, no server in the middle.

Built on `iroh` (p2p QUIC + NAT traversal), `iroh-gossip` (the room), and
`iroh-blobs` (resource sharing).

## How it maps to iroh

| Feature | Mechanism |
|---|---|
| Identity / contact handle | a persistent `EndpointId` (public key) |
| The group chat room | an `iroh-gossip` topic (derived from the room name) |
| "add me to the chat" | a signed `JoinRequest` + member approval |
| Presence (online/offline) | gossip heartbeats + neighbor events |
| 1:1 call (contacts + online only) | a direct QUIC stream on a custom ALPN |
| Share a resource | `iroh-blobs`: a file becomes a `BlobTicket` |

## Architecture

One binary, three roles, sharing one persistent node:

- `groupchat daemon` — the long-lived node (owns the endpoint, gossip, blobs,
  presence, calls). Auto-spawned on first use.
- `groupchat <cmd>` — a CLI client that drives the daemon over a Unix socket.
- `groupchat mcp` — an MCP (stdio) server exposing the same actions as tools so
  an agent can drive it natively.

State lives under `$GROUPCHAT_HOME` (or the platform config dir): `secret.key`,
`contacts.json`, `profile.json`, and the `blobs/` store.

## Build

```bash
cargo build --release
```

## Quickstart (two people) — one step each

```bash
# --- you ---
groupchat invite --nick alice         # prints a ticket; send it to your coworker
                                      # (minting an invite auto-approves who joins with it)

# --- coworker (cold machine — no init needed) ---
groupchat connect <TICKET> --nick bob # joins, auto-adds you as a contact, goes live

# now chat, see presence, call, and share
groupchat send "hey, want to pair?"
groupchat wait                        # block until the next message lands (event-based)
groupchat who                         # ● online  ○ offline, ✓contact
groupchat call bob --message "jump on a call?"
groupchat share ./design.pdf
groupchat get design.pdf --out ./design.pdf
```

After `invite` + `connect`, both sides are mutual contacts and live — no `init`,
no manual approvals. (The longhand path — `init`, `join`, and explicit
`contacts add` on each side — still works if you want to approve joiners by hand.)

Contacts gate the calls: you can only call someone who is in your contacts and
currently online, and inbound calls from non-contacts are refused.

## CLI reference

| Command | Description |
|---|---|
| `init [--nick N] [--room R]` | Create identity + settings |
| `id` | Print your endpoint id |
| `status` | Node + room status |
| `invite` | Print a room ticket to share (and auto-approve who joins with it) |
| `join <ticket>` | Join a room and request to be added (manual approval path) |
| `connect <ticket> [--nick N]` | **One step:** join + auto-add the host + go live (no `init` needed) |
| `send <text...>` | Broadcast a chat message |
| `log [--since N]` | Print chat/system events (returns immediately) |
| `wait [--since N] [--timeout-ms M]` | **Block** until a new event arrives, then print it (event-based) |
| `who` | List peers with online/contact status |
| `contacts add <id> [nick]` / `list` / `remove <id>` | Manage contacts |
| `call <who> [--message M]` | 1:1 call an online contact |
| `share <path> [--label L]` | Share a file, announce it |
| `get <label\|ticket> [--out PATH]` | Download a resource |
| `resources` | List shared resources |
| `daemon` | Run the node in the foreground |
| `mcp` | Run the MCP server over stdio |
| `stop` | Stop the daemon |

## Use from an AI agent (MCP)

Register the MCP server with your agent. For Claude Code, add to `.mcp.json`:

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

Tools exposed: `my_id`, `invite_ticket`, `join_room`, `connect`, `contacts_add`,
`contacts_list`, `chat_send`, `chat_poll`, `chat_wait`, `who`, `call`,
`share_resource`, `get_resource`, `resources`, `status`.

The fast path for an agent: the host calls `invite_ticket`; the other side calls
`connect` once (joins, auto-adds the host, goes live). To follow the
conversation, loop on **`chat_wait`** (passing back the `last` cursor) — it
blocks server-side and returns the instant a message arrives, so the agent is
woken by events instead of busy-polling `chat_poll`.

## Running several nodes on one machine

Set a distinct `GROUPCHAT_HOME` per node:

```bash
GROUPCHAT_HOME=/tmp/alice groupchat init --nick alice --room demo
GROUPCHAT_HOME=/tmp/bob   groupchat init --nick bob   --room demo
```
