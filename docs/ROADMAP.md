# Execution roadmap — P0 → P4

> Companion to [`ARCHITECTURE.md`](./ARCHITECTURE.md) (A§), [`SCHEMA.md`](./SCHEMA.md)
> (S§), [`UI.md`](./UI.md) (U§). Tests-first; the Definition of Done is the target.
> Each phase lands green under the hardened CI gate and integrates forward so the
> end state is **one** runnable product. Status is tracked inline (`done` /
> `in progress` / `todo`).

## Definition of Done (the whole package)

A user installs the binary and runs the tracker across multiple nodes: create/
edit/move/assign/label/comment/close issues in a TUI; boards + activity render
fast; the TUI stays live off the doorbell stream (re-reads on dirty-notice,
rebaselines on Reset), edits echo optimistically, presence reads honestly; changes
propagate live P2P with no central server; a seed backfills offline peers; workspace
data is E2EE with working membership add/remove + key rotation; an agent drives it
over MCP. Green on Linux/macOS/Windows; release artifacts (incl. Windows) + a
self-updater build; a tagged RC is prepared with notes (human pushes the public tag).

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

## P1 — iroh live P2P sync + seed + three-state presence — **todo**

- Catalog-first sync: gossip announce `{workspaceId, catalogHead}`; on a head change,
  exchange a Catalog VV-diff → the changed-`DocMeta.head` set → per-doc VV-diffs
  multiplexed as length-prefixed `DocId`-keyed frames over a custom ALPN; cold docs as
  `export(Snapshot)` blobs. Recompute rows on every `import()` (writer-direction).
- Doorbell batching level 1 (daemon): coalesce a whole sync-import transaction (+ local
  debounce) into **one** project-keyed frame; TUI visibility-filters (U§4.2). Wire the
  TUI sync indicator + peers panel (U§8).
- Seed: pull the always-on, promotable seed role forward — ticket-advertised bootstrap +
  backfill so a new client establishes the workspace from a ticket alone (A§10).
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

## P3 — E2EE access control — **todo**

- Signed ed25519 membership/ACL op-graph in `Catalog.acl` (`{op_bytes, sig, parents}`),
  trust computed by deterministic **replay** from genesis keys, **remove-wins**
  revocation (S§6). Loro moves bytes; app adjudicates trust.
- Workspace symmetric key distribution + rotation on removal (lazy revocation);
  two-protocol split (sync ACL → derive key → sync encrypted Loro updates).
- TUI members view over `Catalog.acl` (read-only until the signed-op grammar lands),
  then `MemberAdd/Remove`, `KeyRotate` (U§8).
- Tests (adversarial): ACL replay + remove-wins property tests; a non-member sees only
  ciphertext (e2e); key rotation gates future content.

## P4 — Agent/MCP hardening + release engineering — **todo (MCP surface + parity done)**

- MCP hardening + multi-seed + security review + TUI polish (themes/resize/wide-table
  scroll).
- Release: cargo-dist artifacts for all target OS/arches **incl. Windows** + shell/
  powershell installers + self-updater; verify the install one-liner + `groupchat-update`
  install and launch. Prepare a tagged RC with drafted notes; **stop before pushing the
  public version tag** (the single human-gated step).

## Merge strategy

Each phase is a branch off the integration mainline, landed behind the full CI gate,
then integrated forward so the tree stays green + shippable at every merge. No silent
scope cuts — deferrals are logged here and in the relevant decision log.
