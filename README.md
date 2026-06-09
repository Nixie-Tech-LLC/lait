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
| Presence (online/offline) | gossip heartbeats + neighbor events + a `Bye` on shutdown |
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

## Install (no Rust needed)

End users don't need the Rust toolchain — `groupchat` is a single self-contained
binary. CI builds it for every tag and publishes a GitLab Release.

```bash
# one-liner (grab the install.sh link from the latest release's assets)
curl -fsSL <install.sh link from the Release> | sh
# then make sure ~/.local/bin is on your PATH
```

Or download the right `groupchat-<target>.tar.gz` for your OS/arch straight from
the release assets and extract the binary.

**Cutting a release:** push a version tag and CI does the rest —

```bash
git tag v0.1.0 && git push origin v0.1.0
```

`.gitlab-ci.yml` builds linux-amd64 (and best-effort linux-arm64) and creates a
GitLab Release with an `install.sh`. The bundled GitHub `release.yml`
(cargo-dist) builds mac + linux on free runners, publishes the GitHub Release,
and ships a self-updater (`groupchat-<target>-update`) so installs can upgrade
in place. (Windows is not built — the daemon's control channel is a Unix domain
socket.)

## Build (from source)

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
| `send <text...> [--to N] [--tier T] [--deadline-ms M] [--notify-anyway]` | Broadcast a chat message (optionally addressed, with an urgency tier) |
| `ack <seq>` | Acknowledge a received message — sends a read+ack receipt to its sender |
| `receipts [--seq N]` | Show per-recipient delivered/seen/acked status for messages you sent |
| `focus [--mute-below T] [--clear]` | Silence anything below a tier (unless sent `--notify-anyway`) |
| `log [--since N]` | Print chat/system events (returns immediately) |
| `wait [--since N] [--timeout-ms M]` | **Block** until a new event arrives, then print it (event-based) |
| `watch [--direct-only] [--min-tier T] [--exec CMD] [--on-interrupt CMD] [--notify]` | Follow events and run a hook / desktop-notify per event |
| `who` | List peers with online/contact status |
| `contacts add <id> [nick]` / `list` / `remove <id>` | Manage contacts |
| `call <who> [--message M]` | 1:1 call an online contact |
| `share <path> [--label L]` | Share a file, announce it |
| `get <label\|ticket> [--out PATH]` | Download a resource |
| `resources` | List shared resources |
| `daemon` | Run the node in the foreground |
| `mcp` | Run the MCP server over stdio |
| `stop` | Stop the daemon |

## Presence & notifications (it behaves like a messaging app)

The daemon keeps the room tidy on its own — you don't manage it:

- **Online/offline is accurate and event-driven.** Peers go online on their first
  heartbeat, and offline the instant they leave: a graceful `stop` broadcasts a
  `Bye`, a hard exit trips a `NeighborDown`, and a silent stall is caught by a
  background reaper (30s window). Each transition logs a `presence` event —
  `alice is online`, `bob left` — so it surfaces in `log`/`wait` like a read
  receipt.
- **Notifications carry urgency.** Events have a `direct` flag: a message that
  `@mention`s you (or an incoming `call`) is `direct` and prints with a 🔔 —
  it's addressed to you and wants a reply. Ambient room chatter and presence
  changes are not. An agent triages like a human: glance, open if it's for you,
  respond or ack, move on.
- **Cleanup is automatic.** Stale peers are pruned, and if someone reinstalls and
  rejoins under the same nick with a fresh key, the old contact is replaced — no
  duplicate handles to manage.

The event-based primitive for all of this is `wait` (CLI) / `chat_wait` (MCP):
it blocks until the next event and returns immediately, so you follow the room
by looping on it rather than polling.

## Delivery, read receipts & urgency tiers

Group chat is best-effort by default, which is fine for ambient chatter but not
for "did my agent actually see this, and act on it?" Messages can carry an
**urgency tier**, and tiered messages get the Sent → Delivered → Read → **Acted**
ladder of a real messaging app — with an iMessage-style **"Notify Anyway"**
override. (Design notes + diagrams: [`docs/HARDENING.md`](docs/HARDENING.md).)

**The tiers** (`--tier` on `send`):

| Tier | Meaning | Receiver behavior |
|---|---|---|
| `ambient` (default) | room chatter | logged, glanceable, no receipts |
| `direct` | `@mention` / addressed | 🔔, reply expected |
| `needs_ack` | "respond by the deadline" | ⏰; **must** `ack`; sender alerted if it lapses |
| `interrupt` | "notify anyway" | 🚨; overrides the receiver's focus; re-broadcasts until acked |

**Three guarantees, three mechanisms:**

- **Delivered** — the recipient's daemon auto-emits a receipt the moment a tiered
  message lands. No agent cooperation.
- **Seen** — the recipient emits a *seen* receipt when its `wait`/`log` cursor
  passes the message (the agent read it).
- **Acted** — the recipient runs `ack <seq>` (or the `chat_ack` tool). This is the
  only rung that needs the agent, so if it lapses the **sender** is alerted with a
  `⚠ no ack` event and — for `interrupt` — the message re-fires on a backoff.

```bash
# Ask agent3 to confirm, with a 30s ack window
groupchat send --to agent3 --tier needs_ack --deadline-ms 30000 "merge the PR?"
# → sent (msg 17…); ack/receipts track it

# See who got it / read it / acked it
groupchat receipts
# msg 17… [needs_ack]  "merge the PR?"
#     agent3 ✓delivered ✓seen —acked   ← saw it, hasn't acted

# On agent3's side, after reading the 🔔/⏰ event at seq 4:
groupchat ack 4
```

**Receiver focus + Notify Anyway.** A busy receiver can mute low-tier noise; a
sender can override that mute for something that truly can't wait:

```bash
# agent3: while heads-down, silence anything below interrupt
groupchat focus --mute-below interrupt
# sender: break through the mute anyway
groupchat send --to agent3 --tier direct --notify-anyway "you're blocking the release"
```

**Reaching a heads-down agent.** An agent's attention is its `wait`/`watch` loop,
so tiers shape what happens at loop boundaries — and `watch` adds a preemption
hook that fires *only* for `interrupt` events, the channel meant to break an agent
out of its current work:

```bash
# Cooperative: act on direct-and-up events
groupchat watch --min-tier direct --exec 'enqueue-reply "$GROUPCHAT_EVENT_TEXT"'
# Preemptive: only interrupt-tier fires this (e.g. signal the agent process)
groupchat watch --on-interrupt 'preempt-agent --msg "$GROUPCHAT_EVENT_MSG_ID"'
```

Hooks get `GROUPCHAT_EVENT_TIER`, `GROUPCHAT_EVENT_MSG_ID`, and
`GROUPCHAT_EVENT_PREEMPT` alongside the existing `GROUPCHAT_EVENT_*` vars.

### Make notifications *do* something: `groupchat watch`

`watch` turns the event stream into actions. It blocks on `wait`, prints each
event, and — for every event (or only `--direct-only` ones) — runs a hook and/or
raises a native desktop notification. This is how a message actively prompts an
agent or a human, instead of waiting to be polled:

```bash
# Desktop-notify only when someone @mentions you or calls
groupchat watch --direct-only --notify

# Wake your agent: run a command per direct event (e.g. enqueue a reply task)
groupchat watch --direct-only --exec 'my-agent reply --from "$GROUPCHAT_EVENT_NICK"'
```

The hook gets the event as `GROUPCHAT_EVENT_*` env vars
(`SEQ`, `KIND`, `NICK`, `ID`, `TEXT`, `DIRECT`, `TS`) and the full event JSON on
stdin. Hooks run detached, so a slow one never stalls the stream, and `watch`
reconnects on its own if the daemon restarts.

## Use from an AI agent (MCP)

### Quickest: one command

After installing the binary, register the MCP server with your agent in one step
— no hand-editing JSON:

```bash
groupchat install-mcp --client claude     # or: cursor | windsurf | generic
```

It merges a `groupchat` entry into that client's `mcpServers` (preserving any
others), using this binary's absolute path and carrying `GROUPCHAT_HOME` if set.
`--scope user|project` picks the config location; `--print` shows the result
without writing. Restart the agent (or reload its MCP servers) afterward.

### Claude Code plugin (also installs a skill)

Install groupchat as a Claude Code plugin and you get the MCP server **and** a
skill that teaches the agent the room workflow (tiers, ack obligation, "block on
`chat_wait`"):

```
/plugin marketplace add ItsOhmar/groupchat
/plugin install groupchat@groupchat
```

The plugin assumes the `groupchat` binary is already on your `PATH` (install it
first); a `SessionStart` check reminds you if it isn't.

### Manual

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

Tools exposed: `my_id`, `invite_ticket`, `join_room`, `connect`, `contacts_add`,
`contacts_list`, `chat_send` (with `tier`/`to`/`deadline_ms`/`notify_anyway`),
`chat_ack`, `receipts`, `focus`, `chat_poll`, `chat_wait`, `who`, `call`,
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
