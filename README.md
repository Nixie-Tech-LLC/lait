# lait

**The issue tracker that lives in your repo.**

Track work at typing speed, onboard a teammate with one link, and let your
coding agents work the board like anyone else — no server, no signup, no
browser tab. If `cd` gets you into the project, you're already in.

```console
$ cd my-project
$ lait init                          # one-time: this repo now has its own tracker

$ lait new "fix login race" --start  # file the issue, take it, branch it
MP-1  fix login race  in_progress  · you
switched to new branch 'mp-1-fix-login-race'

# ...write the fix, commit...

$ lait done                          # the branch tells lait which issue
MP-1  fix login race  done
```

- **Instant** // your issues live beside your code and open in milliseconds —
  faster than a browser tab, on a plane, in a basement
- **One-link teams** // send an invite over any chat; `join` does the rest —
  no accounts, no admin console, no seat licenses
- **Agent-native** // AI agents are first-class members: they claim, comment,
  and close issues through MCP with the same audit trail as a human
- **Branch-native** // `lait start` cuts the branch; `done`, `comment`, and
  `show` read the issue off the branch you're on
- **Private by default** // everything is end-to-end encrypted between members;
  there is no server to trust because there is no server
- **Works everywhere** // one self-contained binary for macOS, Linux, and
  Windows; offline-first, syncs whenever teammates are online together

Whether you're solo in a side project, a team replacing a heavier tracker, or
wiring up agents that need a shared board, the whole product is the one binary
below.

> Curious how it works with no server? The short version: issues are CRDTs
> synced peer-to-peer, membership is a signed key graph, and every node keeps a
> durable local copy. The long version — architecture, data shapes, protocol,
> decision log — lives in [`docs/`](docs/README.md), starting with
> [`ARCHITECTURE.md`](docs/ARCHITECTURE.md); phase status is in
> [`docs/README.md`](docs/README.md).

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
`lait --version` → `lait <version>-dev+<sha> (<date>)`.

### Build from source

```bash
cargo build --release          # Rust 1.91+ (floor driven by iroh 1.0.0-rc.1)
```

Contributing? Enable the hooks once per clone
(`git config core.hooksPath .githooks`) so fmt issues never reach CI.

## Use it like this

Every transcript below is real output from the shipped binary.

### 1 · Solo: track a repo's work without leaving it

Your tracker lives beside your code the way `.git` does — one per project
directory, found by walking up from wherever you stand. `lait init` creates it
and sets up a first **project** (the issue prefix, like `MP-1`, `MP-2`…) named
after your directory, so there's nothing to configure before the first issue:

```console
$ cd my-project
$ lait init
founded space 'my-project' (ws_01JTHLH8QT…)
project: my-project (MP) — `lait new "..."` files into it

$ lait new "flaky websocket reconnect" -P high    # -P = priority
MP-1
```

From there, three views: bare `lait` is your **focus** (unread inbox + what
you're working on, in under 50 ms), `lait board` prints the columns, and
`lait serve` opens your spaces in a browser — every space on this machine, live.
Nothing needs the network — it's your tracker; teammates come later (scenario 2)
or never.

### 2 · Two of you: onboarding is one link

Invites are bearer links carrying everything a joiner needs (the space, the
trust root, a single-use auto-admit pass). Send one over any private channel;
`join` creates their store, admits them, and verifies the whole handshake:

```console
you$ lait invite                # → lait://join/… (+ QR, copied to clipboard)

them$ cd their-checkout && lait join <link> --nick bob
joining alice's space with an invite pass — you should be admitted automatically…
✔ space       ws_01JTHHNM05… ('acme')
✔ daemon      online
✔ membership  member
✔ peer        1 peer online
✔ synced      1 project(s), 2 issue(s)
you're in — get to work.
```

Everything is end-to-end encrypted; membership is a signed key graph, so
`lait members remove bob` rotates the key and revokes future reads. Prefer a
human gate? `lait invite --require-approval`, then `lait members approve`.

### 3 · The daily loop, on a branch

Branch names carry the issue (`mp-1-fix-login-race`), so the loop needs no refs
and no context switch — and your teammate's activity finds you, you don't poll it:

```console
$ lait start MP-3               # assign me + in_progress + branch, one commit
MP-3  flaky reconnect  in_progress  · you
switched to new branch 'mp-3-flaky-reconnect'
$ lait comment "root cause: reused nonce"      # ref inferred from the branch
$ lait done

$ lait                          # your focus, <50ms
Inbox (2): bob commented on MP-2 · someone moved MP-2
$ lait inbox
• MP-2  bob commented on  polish header  — on it, root cause is the header cache
• MP-2  someone moved  polish header  — backlog → in_progress
```

The inbox is durable (survives restarts, unlike a feed you scrolled past) and
attribution-honest: comments carry their real author; state changes never guess.

### 4 · Your coding agent is a teammate

Membership is a keypair and an issue is a perfect unit of agent work, so an MCP
agent files, claims, comments, and closes issues exactly like a human — same
verbs, same audit trail:

```console
$ lait install-mcp --client claude
$ lait new "backfill created_at on legacy rows" -b "batched, dry-run first"
$ lait assign MP-4 agent        # any member — agents included — by name or key
# the agent: issue_start → comment progress → issue_done, over `lait mcp`
$ lait inbox
• MP-4  agent commented on  backfill created_at…  — dry run: 48,112 rows. PR up.
```

### 5 · Many clients, one machine

Spaces are discovered from the directory you stand in, git-style — and the
registry makes them addressable from anywhere:

```console
$ lait spaces
acme        ws_01JTHHNM0  founded  up    [ACME, DSN]
  ~/code/acme/.lait
kiln        ws_01JTGX2P1  joined   idle  [KLN]  (from mira)
  ~/code/kiln/.lait

$ lait -w kiln board            # target any space from any directory
$ lait config set project.default DSN   # per-space default for `new`/`board`
```

Project selection is one fixed chain: explicit `-p` → your branch's key →
`project.default` → the only project → a teaching error. Filters (`ls -p`) are
never defaulted, and `move -p` is always explicit — nothing silently guesses.

### 6 · A team that's rarely online together

Sync is peer-to-peer; a team spread across timezones pins one always-on peer
(any box running the same binary) that backfills whoever comes online:

```console
seedbox$ lait join <link> && lait daemon --seed    # never idle-shuts-down
laptop$  lait remote add <link-for-this-space>     # sticky; dialed every start
```

The seed holds ciphertext and the signed op-graph — it can neither read (E2EE)
nor forge (genesis-anchored signatures). See [docker-compose.yml](docker-compose.yml).

### Scripting

Every command emits a stable, versioned DTO under `--json` — the same shapes the
MCP tools return:

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
| `assign <ref> <who…> [--remove]` | Add/remove assignees |
| `label <ref> [+LABEL…] [-LABEL…]` | Add/remove labels |
| `comment [ref] [BODY]` | Append a comment. One arg on a KEY-n branch = the body (ref inferred); no BODY → stdin |
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
| `activity [--since N]` | Space-wide recent transitions |
| `serve [--port N] [--open]` | Open your spaces in a browser (loopback-only) |
| `status` · `id` · `shutdown` | Node/space status · endpoint id · stop the daemon |
| `invite [--require-approval] [--reusable] [--ttl-hours N]` · `join <link> [--dir D]` | Invite a teammate; `join` creates the joiner's store (cwd or `--dir`) and the default pass admits them automatically (add `--require-approval` for the gated `members requests`/`members approve` flow) |
| `who` · `watch` | Peers online · follow the event stream |
| `profiles` / `resume <name>` | List profiles / switch to a named profile (each a separate identity + store) |

Global flags: `--home DIR`, `-w SEL` (target a space by name/id/path from any
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
without writing. The MCP server binds a space the same way the CLI does (cwd
discovery or `LAIT_HOME`) — run it where a space exists (`lait init` /
`lait join` first; nothing is created implicitly).

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
# host — mint an invite link (carries the space, genesis, and a single-use pass)
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

Space data is E2EE: issues sync as ciphertext, and a node that isn't in the
signed ACL (or has been removed) sees only ciphertext. Auto-approval never weakens
this — the seal still happens key-side on an admin node holding the space key;
the pass only removes the manual keystroke. Changes propagate live P2P over iroh
with no central server; any always-on node advertised in a ticket acts as a
portable seed that backfills cold clients.

## Running several nodes on one machine

Set a distinct `LAIT_HOME` per node — one founds, the other joins from the invite
(there is no shared "room name": the gossip topic derives from the space id
carried in the ticket):

```bash
LAIT_HOME=/tmp/alice lait init --name demo --nick alice
LAIT_HOME=/tmp/alice lait invite                       # → <INVITE>
LAIT_HOME=/tmp/bob   lait join <INVITE> --nick bob
```
