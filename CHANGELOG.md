# Changelog

## v0.6.0 — one word for one thing

> **A naming flag day, and a clean break.** The thing lait organises work in is a
> **space** — the CLI has said so since v0.5.0, and now the code, the on-disk state,
> and the wire say it too. `lait-engine` is now **`lait-fabric`**, and `UserId` is now
> **`DeviceId`**. Nothing is migrated: **founders must re-init, everyone else must
> re-join from a fresh invite.** Your `ws_…` ids and the `--workspace` / `workspaces`
> aliases still work — the ids in the wild keep working, and your fingers keep working.
>
> ```
> lait update            # everywhere
> lait init              # founders — nothing from v0.5.x is migrated
> lait join <link>       # everyone else, from a fresh invite
> ```

### One word for one thing

- **`lait-engine` is `lait-fabric`.** The kernel determines **legitimacy** — identity,
  authority, custody, recovery, and which transitions are valid given signed history.
  The fabric maintains the **shared world** — documents, persistence, history,
  convergence, projection. They are separate crates because the dependency edge is a
  correctness boundary: convergence cannot confer legitimacy. They ship, test, and
  version together as lait's substrate. "Engine" also collided with the CRDT engine
  the crate seals; prose that said "the engine" now says Loro, the fabric, or the
  daemon, whichever it meant.
- **"Workspace" is gone from the code.** `WorkspaceId` → `SpaceId`, `WorkspaceTicket`
  → `SpaceTicket`, `WorkspaceKey` → `SpaceKey`, `workspaces.json` → `spaces.json`, and
  the Loro identity key `workspaceId` → `spaceId`. v0.5.0's note that "internal
  identifiers and architecture docs keep 'workspace'" is superseded. **The `ws_` id
  prefix is unchanged**, and `--workspace` / `lait workspaces` / `recover-workspace`
  remain as aliases.
- **`UserId` is `DeviceId`.** A peer *is* its ed25519 key; `ActorId` is the person.
  This changes no bytes — the type is a newtype over a string in every encoding — only
  what the code calls itself. `PeerId` stays as the transport-layer alias. The CLI and
  MCP noun `<userref>` is now `<who>`, matching the control-plane field it feeds.

### The break

- **Schema v3, sync protocol v3, control protocol v2**, plus `lait/sync/2`,
  `lait/presence/2`, and gossip topic epoch `v3`. Old and new nodes cannot see each
  other at all: ALPN negotiation fails before a frame is exchanged, and the gossip
  topic differs.
- **v0.5.x stores are refused, not migrated.** The schema gate now has a lower bound
  as well as an upper one; opening an older store names the version and points at
  `lait init` / `lait join` rather than opening it and projecting it as spaceless.
- **A running v0.5.x daemon is replaced, not talked to.** It reads as behind the
  control-protocol window, so the first client contact kills and respawns it.
- **`workspaces.json` is not read.** The space registry is `spaces.json`; it is
  navigation state and rebuilds itself on the next `init`, `join`, or daemon open.

## v0.5.2 — the board works, history is durable, and issues have a shape

v0.5.0 put a board in the browser but left it read-rich and write-poor: you could
look at it, not work it. This release closes that, and lands two engine features on
top — a per-issue history that survives restarts and attributes every change, and an
issue graph (sub-issues, links, blockers) that could not exist before.

> **One flag day, but no re-init.** Sync protocol v1 is retired: a v0.5.2 node
> **refuses to sync with a v0.5.1-or-older node**, with a clear "the peer must
> upgrade lait" message rather than a silent divergence. This is deliberate — the new
> content-authority ops (below) would split E2EE if an old node silently dropped what
> it couldn't decode. So **every node in a workspace must `lait update` to v0.5.2**;
> do it and they sync again. Unlike v0.5.0, **nothing is re-initialized** — your
> stores, invites, and history all carry forward, and this is designed to be the
> *last* flag day of its kind.
>
> ```
> lait update      # on every node in the workspace
> ```

### The web client runs the daily loop

The browser could render the board; now it can drive it. Assign and unassign, add and
remove labels, `start` / `done` / `stop`, drag a card across columns (or move it by
keyboard), switch and create projects, filter by status — all with the same keymap the
terminal taught (`a` `b` `p` `s` `m`, `S`/`D`/`O`, `J`/`K`). Rows and cards show
assignee avatars instead of a "you +1" string. Every one of these verbs already
existed in the engine; the browser simply couldn't reach them.

### A history you can trust, and a shape for issues

- **Durable, attributed history.** Each issue's timeline is now read from its change
  log on disk, so it **survives daemon restarts** and names **who** made each change —
  a teammate's edit included, because the author travels with the op. (It replaces a
  per-session ring that forgot everything on restart and could only ever say "a peer
  changed this.")
- **The issue graph.** Issues now have **sub-issues** (a parent/child tree),
  **links** (`blocks` / `relates` / `duplicates`), and a computed set of **open
  blockers**. Sub-issues use a tree-move CRDT, so two people reparenting concurrently
  can never produce a cycle. The web surfaces all of it as a navigable Relations
  panel; creating edges from the browser lands next.

### Content authority and agents (CRAIT)

Membership and catalog structure are now carried by a **signed-DAG envelope** whose
authority is content-addressed and verifiable. Human members can **sponsor agent
keypairs**, and there is a **membership audit log** whose author is cryptographically
verified — the one feed in lait that isn't advisory — surfaced in the web Members
view, an unauthorized op shown rather than hidden.

### Contributor tooling

`npm run dev` is now one command: it starts the engine, reads its token, and wires the
dev proxy — no second terminal, no copy-paste. `lait serve --json` prints
`{url, token, port}` for scripting, and `cargo build` now picks up a rebuilt web
bundle on its own (the `touch src/serve/shell.rs` ritual is gone). A new
`viewer/README.md` documents the whole loop.

## v0.5.1 — `lait update` actually updates

`lait update` has never worked on Windows. It always failed with `specified file
not found in archive`, because the path it asked self_update to pull out of the
release zip was `lait.exe.exe`: self_update appends the platform's executable
suffix to `bin_name` *before* expanding `{{ bin }}`, so the template spelled
`.exe` a second time. v0.4.8 shipped that as a *fix* for this exact symptom, and
v0.5.0 carried it forward.

- **The path is checked against the release, not against itself.** The in-archive
  path is a claim about cargo-dist's layout, and the test only compared that claim
  to our own code — it asserted the template string verbatim, so it restated the
  bug rather than catching it. A new CI job downloads the archives users actually
  download and asserts the path self_update would extract is really inside them.
- **Every platform's path is now computable from any host.** It was behind
  `#[cfg(windows)]`, which can only ever be exercised on the platform it selects —
  which is why the Windows arm went unexercised through two releases. It takes the
  target as an argument and reads `self_update::get_target()`, the same string
  self_update substitutes, so what we plan and what it does cannot drift apart.

> **Updating from v0.5.0 or earlier on Windows needs one manual step**, since the
> broken code is in the binary doing the updating. Re-run the installer once and
> `lait update` works from then on:
>
> ```
> powershell -ExecutionPolicy Bypass -c "irm https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.ps1 | iex"
> ```

## v0.5.0 — the browser is the interactive surface

The 0.4.x line was a chat engine wearing an issue tracker's clothes. This one is
the tracker: `lait serve` puts a keyboard-first board in a browser over the same
control plane the CLI already spoke, the re-architecture pulls the last chat-era
assumptions out at the root, and the daily loop — `lait` → `start` → work →
`done` — finally reads like the thing you actually do.

> **Two breaks, both needing action.** Stores, invite tickets, and the wire all
> changed: **every node must re-init (founders) or re-join from a fresh invite
> (everyone else)**; nothing is migrated. And **`lait tui` is gone** — `lait serve`
> replaces it. Both are detailed below.

### The browser is the interactive surface; the TUI is gone

**Breaking: `lait tui` no longer exists.** `lait serve` replaces it — a keyboard-first
board in a browser, over the same Layer-B control plane. Also removed: the `tui.theme`,
`tui.tabs`, and `tui.key.<action-id>` config keys. Nothing else about the CLI, the
daemon, or the wire changed.

- **`lait serve` — the control plane over loopback HTTP + SSE.** The engine's contract
  has always been `control.rs`, but every client so far was a local process that could
  speak a named pipe; a browser cannot. This is the one adapter that closes the gap —
  the same `Request`/`Response`, the same `Doorbell` stream, re-bound to a socket a
  browser can reach. The engine grew a port, not a UI. See `docs/UI.md`.
- **The first surface that is global to the machine.** The control channel is keyed by
  home, so there is one daemon per space; a spaces picker means holding N. Listing only
  probes (opening the browser never wakes every daemon you have registered) — selecting
  a space is what attaches it.
- **Your agents are visible.** Agent spaces appear in the picker, tagged, so you can
  watch what they are doing. They are read-only there: a write through an agent's daemon
  would be signed *as* that agent. Write through your own space and sign as yourself.
- **Loopback auth, because the socket was the authentication.** `control.rs` never
  needed auth — a Unix socket is gated by file permissions, a named pipe by its DACL, so
  opening the channel *was* the credential. An HTTP port inherits none of that and adds a
  caller that never existed: the pages you visit. So: loopback-only bind, a per-run
  token, and a strict `Host`/`Origin` allowlist. The last is the load-bearing one — after
  a DNS rebind the browser believes the attacker is us and hands over the cookie, so the
  token stops being a secret; `Host` is the field they cannot launder.
- **Destructive verbs keep the CLI's question.** `confirm_destructive` refuses under
  `--json` because a pipe cannot be asked. A browser can, so the question comes back and
  the UI asks it — using `cli::destructive_question`'s own words, so the modal and the
  terminal cannot disagree about what is dangerous.
- **The client has one seam.** One vocabulary (`Command`), one door (`contribute`).
  Keys, the palette, and the `?` overlay are projections of one registry, never second
  lists. The core registers its own commands through that same door, so an extension can
  do anything the core can — and override anything the core gets wrong.
- **What the TUI left behind.** Its architecture outlived it: `UI.md` §4 (the doorbell
  stream, the correlation-free optimistic overlay) is still the contract, and `lait serve`
  implements it. Its keyboard design — one action vocabulary with stable ids, bindings as
  data with every listing a projection, a palette derived from the live `cmdspec` tree —
  is the web client's spine. `ratatui`/`crossterm` stay for the inline `lait members`
  picker, which was never part of the TUI; only `tui-textarea` left the tree.

### CLI ergonomics: ask before doing, and say what actually went wrong

Additive within epoch 1 — no flag day. The new `hello` handshake and the
`Candidates.near_miss_for` field both decode on clients that predate them.

- **The control channel has a version.** `CONTROL_PROTOCOL_VERSION`, exchanged in a
  `hello` handshake, completes the set the previous release started: the sync plane
  had `PROTOCOL_VERSION` and the store had `SCHEMA_VERSION`, but the CLI↔daemon
  channel had nothing — so a client meeting a daemon of another vintage found out by
  failing to decode its answer. That read as "no daemon", spawned a doomed second one
  over the held lock, and blamed a timeout 20s later. The reply is read as raw JSON
  *before* any typed decoding, so a mismatched daemon can say that it is mismatched
  without the answer depending on the schema that changed. A daemon that does not know
  `hello` identifies itself by rejecting it (v0.4.8 and earlier).
- **Upgrading no longer strands you.** `lait update` announced "stopped the running
  daemon" on any *decodable* reply — including an error, and including the "shutting
  down" a pre-`signal_shutdown` daemon sends and then ignores. It now verifies the
  process is actually gone. This was the bug that *delivered* the stale daemon that
  then couldn't be diagnosed.
- **A daemon this build can't talk to is now offered up for repair** rather than
  reported as a timeout: detected in ~0.02s (was 20.4s), named, and — with your
  consent — stopped and replaced, verifying it really stopped rather than trusting its
  acknowledgement. Never for a daemon *newer* than this build: replacing it downgrades
  the node, and a store written at a newer `SCHEMA_VERSION` would then refuse to open.
  There the answer is `lait update`. A spawned daemon that dies now fails fast with its
  own words (kept in `daemon.log`) instead of a 20s timeout.
- **lait asks before destroying** (`delete`, `members remove`, `members rotate-key`),
  and `-y/--yes` is the way through. `delete` names the issue's **title**: its ref comes
  from the git branch when omitted, so a stale checkout could tombstone the wrong issue
  with nothing on screen to notice it by. With no TTY (CI, an agent, a pipe) or under
  `--json`, nothing ever prompts — it fails naming `--yes`. See UI.md §2.4.
- **Errors report in one voice.** `main` returning `Result` handed every client-side
  failure to anyhow's `Termination`: a capitalised `Error:` beside the daemon path's
  lowercase `error:`, a `Caused by:` chain that leaked `data-encoding` and `postcard`
  internals ("non-zero trailing bits at 3") to anyone who pasted an invite badly,
  `--json` ignored (prose on stderr, *nothing* on stdout — indistinguishable from an
  empty result), and exit `1` for everything, including the not-founds UI.md §2.3
  documents as `2`. All four are fixed at one reporter; exit codes now derive from the
  error's type, never its prose.
- **Bad invites explain themselves** in terms of the invite, not our encoding.
- **"Did you mean" on a ref that matched nothing** — the candidate machinery already
  existed for ambiguous refs; typos are the more common way to get there. Suggestions
  only when a guess is defensible.
- **`--help` separates global flags from each command's own**, under `Global Options`.
- **A captured command on Windows no longer hangs forever.** `CreateProcess` inherits
  *every* inheritable handle, not just the three in `STARTUPINFO`, so the daemon a
  command auto-spawns came up holding a write-end of that command's stdout — its own
  `Stdio::null()` notwithstanding. The command exited, the pipe never closed, and
  anything reading to EOF (`$(lait new …)`, a test harness, an MCP client) waited on an
  EOF that could not arrive. The daemon is now spawned through `CreateProcessW` with a
  `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` naming the only three handles it may inherit, so
  it comes up holding what we handed it and nothing else — including nothing we
  inherited from *our* parent and never knew we had. lait also clears
  `HANDLE_FLAG_INHERIT` on its own stdio at startup, which bounds the same leak through
  the children spawned without that ceremony (a `hook`, the notification balloon);
  children given stdio explicitly still inherit it, as std duplicates the handle for
  them. Unix was never affected — those fds are `CLOSE_ON_EXEC` — and Windows now
  matches it exactly: nextest reports the suite leak-free on all three OSes.

### Protocol version negotiation, schema gate & release hardening

Composes with the workspace re-architecture break below — the same epoch-1 wire
change (`lait/sync/1`, `lait/presence/1`, workspace-id gossip topic) — adding
in-band version negotiation on top of it.

- **In-band version negotiation.** The sync handshake now carries a
  `protocol_version`; a peer outside the supported window
  `[MIN_SUPPORTED_PROTOCOL, PROTOCOL_VERSION]` is refused with a clear "upgrade
  lait" diagnostic instead of a silent decode failure. Undecodable gossip
  payloads (the other version-skew path) are logged at debug rather than dropped
  silently. From here on this window absorbs backward-compatible changes without
  another ALPN bump.
- **On-disk schema gate.** Opening a workspace store written by a *newer* lait now
  fails fast with an upgrade message rather than risking a lossy read
  (`SCHEMA_VERSION` is finally enforced on load).
- **`lait update` heals a dev-channel node.** A `dev` build now reports a
  clean-semver `X.Y.Z-dev.<sha>` to the updater (which sorts below stable), so
  `lait update` moves it onto the stable release instead of reporting "already up
  to date" and stranding it.
- **Distribution fixes.** `cargo binstall lait` now resolves the binary correctly
  on Linux/macOS (the archive nests under `lait-<target>/`; only Windows is flat).
  The MSRV CI gate actually tests 1.91 again (it was silently running on stable).
  Releases now ship a build-provenance attestation and a CycloneDX SBOM, and the
  build was migrated to a custom-artifacts architecture so binaries can be signed
  in place (macOS notarization + Windows Azure signing land next). See
  `docs/RELEASES.md`.

### The daily-loop DX pass (spaces, start/done/stop, inbox)

Shaped by a blind design exercise (Linear-style and Jira-style teams designing
this CLI from the same capability spec): both independently reinvented our
explicit-create + registry architecture, and exposed the gaps this pass closes.

- **`spaces`.** The user-facing noun is now *space*: `lait spaces [ls|forget|prune]`
  (`workspaces` kept as an alias), global `-w/--space` selector, all messages
  reworded. Internal identifiers and architecture docs keep "workspace".
- **Work-state verbs.** `lait start [ref]` = assign yourself + first
  active-category status + create/checkout `key-n-slug` (one commit = one
  activity row; `--no-branch` to skip; branch step silently skipped outside
  git). `lait done` / `lait stop` close the loop — refs infer from the branch,
  so the daily cycle is `lait` → `start` → work → `done` with no ref typed.
  `new --start` files and claims in one line. The daemon off-switch is renamed
  **`shutdown`** (`stop` the word belongs to the work loop).
- **A durable inbox.** `lait inbox [--clear]`: remote assignments, comments on
  your work, `@nick` mentions, and status moves on your issues — derived at
  sync-import time (attribution-honest: comments carry their real author,
  everything else renders actor-unknown rather than guessing), persisted to
  `inbox.json` with a read watermark, so unread items survive daemon restarts.
  Sits beside `activity` (the workspace firehose). TUI shows an unread badge.
- **Bare `lait` is your focus** — unread inbox summary + your open issues —
  instead of help.
- **Fewer nouns.** Labels are created on first use (`-l perf` just works;
  removals still error on unknown). Project creation is key-first:
  `projects add OPS ["Operations"]` (name defaults to the key; `new` aliased).
  Help is bucketed: the first screen leads with the daily loop; registries and
  node plumbing sink to the bottom. Empty outputs always name the next command.
- MCP gains `issue_start` / `issue_done` / `issue_stop` / `inbox` tools — an
  agent works an issue exactly like a human (claim → comment → done).

### Workspace & project re-architecture (BREAKING)

> **Clean break.** Stores, invite tickets, and the wire protocol all changed;
> old and new nodes cannot see each other (new gossip topics + ALPN bumps
> `lait/sync/1`, `lait/presence/1`). **Every node must re-init (founders) or
> re-join from a fresh invite (everyone else).** Pre-rewrite `.lait/` stores and
> tickets are not migrated.

Five early decisions were removed at the root instead of guarded (see
`ARCHITECTURE.md` §15 and `GUIDED-JOIN.md`):

- **Workspaces are founded explicitly.** `lait init [--name]` is the founding
  verb: it mints the genesis here, names the workspace (default: the directory),
  and **seeds a first project** so `lait new` works on the very next command.
  Nothing creates a store implicitly anymore — a command in a directory with no
  workspace errors with guidance instead of silently minting a decoy store (the
  old lazy mint created a genesis + sealed key as a side effect of `lait ls` in
  the wrong folder).
- **The gossip topic derives from the workspace id.** The chat-era "room" string
  (folder-seeded, drift-prone, three self-heal layers) is gone; the display name
  is a synced, cosmetic catalog field — renaming never re-topics and never
  invalidates tickets. `profile.json` is retired. Tickets are now
  `WorkspaceTicket { workspace, name, host, host_nick, invite }`; old tickets
  fail to parse with an "ask for a fresh one" hint.
- **`lait join` bootstraps the store client-side** (cwd or `--dir`) from the
  ticket before the daemon ever runs, so a daemon only opens a store already
  bound to the right workspace. Joining from a directory bound to a *different*
  workspace is a hard exit-2 error — the old silent adopt-if-empty /
  split-brain-if-not heuristic is deleted. `remote add` with a foreign-workspace
  ticket now errors ("join it first").
- **`lait workspaces` is complete and live.** The registry is written by
  `init`, `join`, and every daemon open — founders finally register. Rows carry
  name, origin (founded/joined), advisory project keys, and `ls` probes live
  status (`up`/`idle`/`missing`); `forget` deregisters, `prune` drops missing
  entries. A new global **`-w <name|ws_id|path>`** selector targets any
  registered workspace from any directory.
- **`lait config`** — git-style layered local settings: global + per-store
  `config.json`, store wins. Keys: `user.nick` (set applies live to a running
  daemon via a new `ConfigReload` request — never a silent wait-for-restart) and
  `project.default`; the `workspace.*` namespace is reserved for future synced
  settings. `lait init`'s old settings-editor role (and the `--room` footgun
  that silently re-topiced a live workspace) is gone.
- **Project defaulting that matches how you work.** `new`/`board` resolve their
  project through a fixed chain: explicit `-p` → the git branch's project key
  (`eng-142-fix` → `ENG`, used only if it resolves) → `project.default` →
  the sole project → a teaching error. `board`'s positional is now optional;
  `ls -p` stays a pure filter; `move -p` stays explicit-only. Project keys are
  validated (1–8 ASCII letters) so `KEY-n` aliases and branch inference stay
  parseable.

## v0.4.8 — Windows self-update fix

- **`lait update` works on Windows again.** cargo-dist ships the binary **flat**
  at the root of the Windows `.zip` (`lait.exe`) but **nested** under a
  `lait-<target-triple>/` directory in the unix `.tar.gz` archives; the updater
  assumed the nested layout everywhere, so every Windows self-update failed at
  extraction with `specified file not found in archive`. The in-archive path is
  now chosen per-OS (with a unit test pinning the contract). **Note:** the broken
  updater is baked into the running binary, so a Windows node on ≤ v0.4.7 must
  reinstall once via its installer (`scoop update lait`, `winget upgrade lait`,
  or the `install.ps1` one-liner) to land a fixed binary; `lait update` then
  works in place from v0.4.8 on.

## v0.4.7 — guided-join onboarding & instant-at-scale edits

- **Guided-join onboarding that names the one thing that's wrong.** A first
  invite silently passes ~10 gates (right directory, daemon up, membership
  sealed, a peer reachable, catalog converged) that otherwise all fail as the
  same empty board. A new verifier projects live daemon state into an ordered
  gate list (workspace / daemon / membership / peer / synced) and names the
  single actionable blocker, identically on every surface: `lait doctor` (alias
  `verify`) — run automatically as a tail on `lait join`, which also flags a
  store/workspace mismatch; an MCP `doctor` tool; and a TUI Doctor panel (`d`)
  with a joined-workspace selector (`w`). Gates are founder-aware: an admin, or
  an already-synced member, with no peers online isn't blocked.
- **The directory trap is closed.** Running commands from the wrong directory no
  longer auto-creates a decoy `.lait/` store: a join records `store path ->
  workspace` in a `workspaces.json` registry, and read-only commands (including
  `tui`) refuse to conjure an empty store when you've already joined a workspace
  — pointing you back at the real one instead.
- **Edits stay instant with thousands of issues.** Two edit-path costs that grew
  with issue count are gone. The alias/handle table is now maintained
  incrementally — O(log N) per change instead of an O(N²) rebuild on every edit
  and sync — and git snapshots are coalesced onto a periodic checkpoint off the
  mutation path instead of a `git add -A` per keystroke (durability is
  unchanged: every write is still fsync'd). In a 2,000-issue workspace, per-edit
  work dropped ~13x and the on-disk store shrank ~30x.

## v0.4.6 — one-step invites & self-updater fix

- **A default invite admits the joiner automatically — no `members approve`.**
  `lait invite` now embeds a **signed, single-use pass** in the ticket (Pattern A):
  the joiner runs `lait join <link>` once and transitions `pending → member` on
  its own, the board decrypting as the workspace key is sealed to it. This
  collapses the old two-humans round-trip (`invite → join → members requests →
  members approve`) into `invite → join`. The seal still happens key-side on an
  admin node that holds the workspace key, so **E2EE is unchanged**: a
  non-member/removed node still sees only ciphertext.
- **The pass is a bearer capability, bounded and revocable-by-design.** Authority
  rides the channel the link travels over, capped by an expiry (`--ttl-hours`,
  default 168 = 7 days) and, by default, a single redemption. A synced,
  admin-signed replay guard (a nonce recorded in the membership doc) burns a
  single-use pass atomically with the member add, so it can't seat a second
  joiner. A pass signed by a non-admin, expired, foreign-workspace, or
  already-spent is silently ignored — the join falls back to a pending request a
  human can still `members approve`.
- **Opt back into the gated flow, or widen the pass.** `lait invite
  --require-approval` mints a pass-less ticket (the classic `members
  requests`/`members approve` flow, preserved unchanged); `--reusable` admits a
  whole team until expiry instead of one person. `invite` output and the post-join
  `status` message now state which mode is in effect.
- Wire note: `RoomTicket` and the gossip `JoinRequest` gained an optional invite
  field — a coordinated format bump (nodes should run the same version).
- **`lait update` now extracts the binary from cargo-dist archives.** The native
  in-place updater looked for a bare `lait` at the archive root, but release
  tarballs nest the binary under a `lait-<target-triple>/` directory, so every
  update failed with `Could not find the required path in the archive: "lait"`.
  The updater now points at `lait-{{ target }}/{{ bin }}`, matching the layout
  produced by cargo-dist on every platform. **Note:** binaries built before this
  fix (≤ v0.4.5) can't self-heal — upgrade once via your installer (`brew upgrade
  lait`, `install.sh`, etc.); subsequent `lait update` calls then work.

## v0.4.5 — invite & remote ergonomics

- **User-refs resolve by local alias and id-prefix.** `<userref>` now accepts a
  key id-prefix (≥4 hex) or a **local alias** (petname) in addition to `@me` / a
  full 64-hex key, resolved daemon-side against a directory of known keys (members
  + live presence + recent join requests). Names come only from your private alias
  store — a self-asserted wire nick is **never** a resolution input, so it can't
  select a key at a trust boundary. Ambiguity returns a candidate list (UI.md
  §3.2). Applies to `members add/remove`, `assign`, and `new -a`.
- **Local petnames (identity, git-style).** The strong identity is the ed25519 key
  (what the signed ACL is keyed on); a friendly name is a **local alias** you
  attach to a key, stored in `aliases.json`, never broadcast, never part of the
  ACL. Set one with `lait members alias <key|prefix> <name>`, or inline while
  adding/approving via `--as <name>`. `members ls` shows the alias next to each
  key. (MCP: `member_alias`, plus `alias` on `member_add`/`member_approve`.)
- **Join-request approval (key-first).** `lait members requests` lists people who
  ran `connect`/`join` but aren't members yet, showing the **authenticated short
  key** and the joiner's nick only as an unverified *claim*. `lait members approve
  <prefix|key> [--as <name>]` seals them the workspace key — resolving strictly by
  key (confirm the short id out-of-band; an unauthenticated nick must never select
  who gets the key). The joiner's short key is also shown on `lait log` join lines.
  Both surface as MCP tools (`member_requests`, `member_approve`).
- **`remote` alias for `seed`.** `lait remote add/ls/rm` is a git-like alias of the
  seed registry. `seed ls` / `remote ls` now emit a structured DTO (id, nick,
  workspace, state, online) so `--json` is scriptable.
- **`lait invite` papercuts.** `invite` now always renders a scannable terminal QR
  of the invite link (suppressed under `--json` so scripts stay parseable).
  Clipboard copy works on Windows (`clip`, with a PowerShell fallback). `--email
  <addr>` opens your OS mail client with a prefilled invite (mailto — no SMTP, no
  credentials).

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
