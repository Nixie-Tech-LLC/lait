# Execution roadmap — P0 → P4

> Companion to [`ARCHITECTURE.md`](./ARCHITECTURE.md) (A§), [`SCHEMA.md`](./SCHEMA.md)
> (S§), [`UI.md`](./UI.md) (U§). Tests-first; the Definition of Done is the target.
> Each phase lands green under the hardened CI gate and integrates forward so the
> end state is **one** runnable product. Status is tracked inline (`done` /
> `in progress` / `todo`).
>
> **Current state (v0.4.8):** P0–P3 are done and verified multi-node; P4 is
> released and shipping (P4 release engineering is done end-to-end — see
> [`CHANGELOG.md`](../CHANGELOG.md) for per-version detail — with security review
> and multi-seed hardening the remaining deferrals).

## Definition of Done (the whole package)

A user installs the binary and runs the tracker across multiple nodes: create/
edit/move/assign/label/comment/close issues in a TUI; boards + activity render
fast; the TUI stays live off the doorbell stream (re-reads on dirty-notice,
rebaselines on Reset), edits echo optimistically, presence reads honestly; changes
propagate live P2P with no central server; a seed backfills offline peers; workspace
data is E2EE with working membership add/remove + key rotation; an agent drives it
over MCP. Green on Linux/macOS/Windows; release artifacts (incl. Windows) + a
self-updater build; tagged releases publish to every channel. **Met and shipping as
of v0.4.8.**

## CI gate (blocking, matrix {ubuntu, macos, windows})

`build --locked --all-targets` + `test --locked` with `-D warnings` · `fmt --check`
· `clippy -D warnings` · doctests · MSRV 1.91 · `cargo deny` (bans aws-lc-*) ·
portability guard (no unix-only API in control/lock path) · DTO/MCP parity
(`tests/mcp_parity.rs`) · e2e smoke on all three OSes · release dry-run (`dist plan`,
Windows target asserted). **Never weaken a gate to go green — fix the code.**

## P0 — Functionality, git-backed (single node) — **done**

Loro data model + catalog + git store + fast TUI + Layer-B façade + MCP.

- **done** loro §14 API validated as a probe (shallow-snapshot merge boundary
  recorded; divergent double-trim needs seed backfill — memory note).
- **done** `ids` (ULID DocId/Project/Label/Workspace + ed25519 UserId), injectable clock.
- **done** `issue` doc (LWW title/status/priority, LoroText description, present-key
  assignees/labels, comment list) + `catalog` doc (docs/projects/boards movable-list/
  labels/workflow/acl/aliases) with the **writer-direction** row cache and
  `head=blake3(frontiers)`.
- **done** git-backed `store` (genesis/catalog/docs, atomic writes, best-effort git,
  no C deps) + **load-time head recompute**.
- **done** `index`: KEY-n aliases with deterministic collision suffix + git-style
  **shortest-unique** canonical `iss_` handles (a bare ULID prefix collides in a ms —
  found + fixed via e2e).
- **done** Layer-B `control` (Request/Response tagged `kind`, Doorbell frames,
  streaming Subscription) + `tracker` core (validate-then-commit, board render rule
  S§5.5, completion S§5.7, pulled activity feed, dirty-set production).
- **done** daemon `node`: doorbell ring (per-boot epoch + per-session seq) + streaming
  Subscribe whose first frame is always Reset (unifies connect/reconnect/restart/
  ring-overrun; fixes idle-shutdown deafness).
- **done** CLI (`app`/`cli`) full U§2 verb surface + `--json` DTO + §2.3 exit codes;
  ratatui `tui` (board/list/detail/activity, doorbell refresh, correlation-free
  optimistic overlay); MCP tracker tools + parity guard.
- **done** tests: SCHEMA invariants (writer-direction, load-time recompute,
  single-membership self-healing boards, completion, KEY-n collision, one-request-
  one-row) + control-plane (validate-then-commit rings no doorbell, Reset rebaseline)
  + CRDT convergence proptests (LWW / map-union / movable-list / docs grow-set).
- **done** e2e smoke on the real binary, wired into CI per-OS.

## P1 — iroh live P2P sync + seed + three-state presence — **done**

Landed: the **catalog-first pull** sync protocol (`sync.rs`, custom ALPN) —
one Catalog VV-diff → changed-`head` set → per-doc VV-diff, multiplexed and
deadlock-free; gossip `Announce{workspace, catalog_head}` as the trigger, with
pull-on-neighbor-up + heartbeat re-announce; ticket-carried **workspace adoption**
so a new client roots from nothing but a ticket (A§6/A§10) and backfills; daemon
doorbell batching (one coalesced frame per sync-import); three-state presence
(`Payload::Presence{nick,state}`, input-driven online/away; `who` reports it); the
TUI ambient sync indicator (peers online). **Verified live: two real nodes converge
both directions over iroh in ~2s, no central server** (manual + `tests/two_node_sync.rs`).
The promotable seed role shipped (`lait daemon --seed`; `seed`/`remote` pin registry,
DUR-1/3/4). Deferred: the RIBLT escape-hatch and further multi-seed hardening.

- Catalog-first sync: gossip announce `{workspaceId, catalogHead}`; on a head change,
  exchange a Catalog VV-diff → the changed-`DocMeta.head` set → per-doc VV-diffs
  multiplexed as length-prefixed `DocId`-keyed frames over a custom ALPN; cold docs as
  `export(Snapshot)` blobs. Recompute rows on every `import()` (writer-direction).
- Doorbell batching level 1 (daemon): coalesce a whole sync-import transaction (+ local
  debounce) into **one** project-keyed frame; TUI visibility-filters (U§4.2). Wire the
  TUI sync indicator + peers panel (U§8).
- Seed: pull the always-on, promotable seed role forward — ticket-advertised bootstrap +
  backfill so a new client establishes the workspace from a ticket alone (A§10). Run-mode:
  `lait daemon --seed` (idle-shutdown disabled, DUR-4). Client onboarding: `lait
  seed add <ticket|id>` pins the seed into a sticky `seeds.json` registry (distinct from the
  opportunistic `peers.json`), unioned into the gossip bootstrap and eagerly pulled on every
  start so a client redials and backfills through its seed even with no other peer online;
  `seed ls` / `seed rm` manage pins. A pin is bootstrap+backfill, never trust (genesis/ACL
  still gate every op).
- Presence → three-state (online/away/offline, input-driven): a `postcard` wire bump
  (`Payload::Presence{ nick, state }`), all nodes upgrade together (U§4.5).
- Tests: two nodes converge (real binaries); a TUI client rebaselines on Reset after a
  peer restart; a stale `since` after restart yields Reset not deafness; batching (one
  sync-transaction ⇒ one coalesced frame); correlation-free overlay convergence under a
  concurrent remote edit (flicker allowed, converges).

## P2 — Seed blind relay + compaction — **todo**

- Ciphertext-chunk **sedimentree** envelope around the P1 per-`(peerId,counter)`-range
  frames (chunk each run's ciphertext, address by `BLAKE3(ciphertext)`, level =
  leading-zero count — determinism survives encryption, A§10). Encrypted-history seed,
  cold-start backfill, policy GC (no CRDT compaction on the relay).
- Re-introduce iroh-blobs for snapshots/attachments.
- Local shallow-snapshot store GC (safe only *because* the seed holds full history —
  the divergent-double-trim boundary is validated and load-bearing).
- Tests: relay reconciles + GCs without decrypting; backfill converges an offline peer
  across a compaction boundary.

## P3 — E2EE access control — **done (core)**

- **done** Signed ed25519 ACL op-graph (`acl.rs`): `AddMember/RemoveMember/SetRole`,
  content-addressed hash-DAG, deterministic replay from genesis, **remove-wins**
  over the causal ancestor closure, authority checked against the admin set.
- **done** Pure-Rust crypto (`crypto.rs`): ChaCha20-Poly1305 AEAD for sync
  payloads; X25519 sealed-box (ed25519→x25519 conversion) distributing the
  workspace key to a member addressed by their `UserId`. No C toolchain / no
  aws-lc (respects the bans).
- **done** Plaintext membership layer (`membership.rs`) synced *before* the
  encrypted catalog/docs (A§11 two-protocol split): the signed ACL + per-epoch
  sealed key envelopes. Encrypted sync payloads (epoch-tagged) = a blind relay /
  non-member sees only ciphertext.
- **done** Key epochs + **lazy revocation**: `member remove` rotates to a new
  epoch sealed only to remaining members; a keyring keeps old epochs decryptable.
  `members add/remove/rotate-key/ls` on CLI + MCP; TUI members view (view 4).
- **done, verified end-to-end (real iroh, `tests/two_node_sync.rs`)**: a
  non-member sees ciphertext; `member add` grants decryption; encrypted
  convergence both ways; `member remove` + rotation blocks the removed member from
  post-removal content. Plus in-process `e2ee_membership_gates_decryption` and the
  `acl.rs` replay/remove-wins/forged-sig/authority tests.
- Fixed en route: a joiner must adopt **empty** catalog/membership docs and import
  the founder's full state, else independently-`create()`d attached child
  containers make the root child-registers LWW-resolve to empty non-deterministically
  (also hardened P1's merge from luck-based to deterministic).
- Deferred (logged): RIBLT scale escape-hatch; account-aggregates-devices; CGKA
  (BeeKEM) for key agreement — the simpler sealed-box distribution is used.

> Deviation from the S§6 sketch: the ACL + sealed key envelopes live in a
> **separate plaintext membership doc**, not `Catalog.acl` — the catalog is
> encrypted on the wire, so the ACL/keys must be readable to bootstrap decryption
> (recorded here + in the code).

## P4 — Agent/MCP hardening + release engineering — **shipped (v0.4.x); hardening ongoing**

- **done** Agent-native MCP surface (full tracker + membership tools) generated/
  checked against the Layer-B DTOs (`tests/mcp_parity.rs`); MCP handshake verified.
- **done** Release engineering, end to end. `dist plan` produces all target
  OS/arches **incl. x86_64-pc-windows-msvc**, with shell + PowerShell installers
  and a native in-place self-updater (`lait update`, pure-Rust). A version tag now
  builds, releases, and publishes to **every channel automatically** — GitHub
  Release, Homebrew, Scoop, winget, `cargo binstall`, and crates.io — plus a
  rolling `dev` prerelease on every merge to `main`. Per-version detail lives in
  [`CHANGELOG.md`](../CHANGELOG.md).
- **done** Onboarding hardening beyond the original P4 scope: the guided-join
  verifier (`lait doctor`, [`GUIDED-JOIN.md`](./GUIDED-JOIN.md)) and one-step invite
  passes (Pattern A, [`GUIDED-JOIN.md`](./GUIDED-JOIN.md) / S§6.1) both landed.
- **shipped**: the project renamed `groupchat → lait` (v0.4.0) and has released
  through **v0.4.8**; the public tag that publishes each GitHub Release is the one
  step a human still drives.
- Deferred/logged: multi-seed hardening, an independent security review of the
  research-grade E2EE, and the receipt/tier hardening in [`HARDENING.md`](./HARDENING.md).

## Merge strategy

Each phase is a branch off the integration mainline, landed behind the full CI gate,
then integrated forward so the tree stays green + shippable at every merge. No silent
scope cuts — deferrals are logged here and in the relevant decision log.
