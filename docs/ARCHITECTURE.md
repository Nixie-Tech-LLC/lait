# Architecture & Plan — lait: a P2P issue tracker

> **Status:** design draft, pre-build. Native Rust. Loro CRDT, git-backed store,
> iroh P2P propagation. Built **functionality-first** (see [§13](#13-phased-build-plan)).
> Supersedes the current chat-oriented `lait` code; keeps the name + iroh
> foundation. The sync/catalog/index design (§5–§10) is validated against Loro's real
> API and Beelay's implementation (see [§15](#15-decision-log) for sources).

## 1. What this is

`lait` becomes a **local-first, peer-to-peer issue tracker** — a decentralized,
rapid-feedback alternative to Linear that runs as a **native Rust node**. It is built in
layers, each provable on its own:

1. **Functionality (git-backed):** a Loro-CRDT issue model + a fast TUI, persisted in a
   local **git repo** that is the durable store. A useful, standalone tracker with
   **Linear-grade devex speed** — no network, no crypto yet.
2. **Propagation (iroh):** live peer-to-peer sync over iroh (QUIC + NAT traversal),
   making it reactive/real-time across nodes with no central server.
3. **Access control (E2EE):** encrypted, blind-relay sync with membership/revocation —
   adapting a proven *design* (not a turnkey library; see [§2](#2-substrate--security-posture)).

Git is the **durable local store, never the sync transport.** This is *not* git-bug:
issues are Loro CRDT documents, propagated P2P over iroh; git holds each node's durable
copy and its persisted view of the shared root of trust (the genesis keys, [§6](#6-git-backed-store--trust-root)).

### Kept from today's lait
iroh endpoint + `EndpointId` (ed25519 identity) · iroh-gossip topic (→ per-workspace
announce/presence) · direct QUIC streams on a custom ALPN (→ pairwise Loro sync) ·
iroh-blobs (→ attachments/snapshots) · `SignedMessage` sign/verify primitive (→ signed
membership ops) · presence · daemon + control socket + CLI + `mcp` + agent registry.
Realistically the domain layer (chat/receipts/calls) is dropped; what survives is the
iroh transport *patterns* and the identity/presence/blob plumbing.

### Dropped
- **lait's "access control"** — a room is an *open* gossip topic; messages are
  signed but unencrypted; "contacts/approval" only gate the *calls* feature (local,
  unauthenticated). No confidentiality, no real authz. Rebuilt from scratch ([§11](#11-access-control--e2ee-later)).
- **Chat domain**, **iroh's role as anything but transport**, and **any browser/WebRTC** idea.

## 2. Substrate & security posture

**CRDT = Loro** (not Automerge). The decision survived validating both substrates against
this design ([§15](#15-decision-log)):
- There is **no audited, turnkey E2EE-for-CRDT library** (research proved this). So the
  "no hand-rolled security" rule can't hold literally — you implement a proven security
  *design* by hand on **either** substrate. That neutralizes Automerge's one importable
  precedent (Beelay) *at the design level*.
- With the envelope hand-rolled regardless, **Loro wins on what's left: performance, DX,
  and richer native types** (`LoroMovableList`, `LoroText`) — which is what "Linear devex
  speeds" demands, and that devex is the foundation the whole plan hinges on.

**The honest cost of Loro (eyes open).** Loro identifies changes by logical
`(peerId, counter)`, **not content hashes**. Automerge hash-links changes into a commit
DAG, which is what lets Beelay's blind relay and its `sedimentree` compaction operate on
*encrypted* data for free. On Loro we rebuild that content-addressing ourselves — but only
in one place (the P2 relay envelope, [§10](#10-seed-node--compaction-p2)), and it is
designed on paper now so earlier phases don't get retrofitted. Everything else Beelay does
we either simplify away (our hierarchy is explicit) or lift substrate-independently
(set reconciliation). See §5–§10.

**Security = adapt a proven design, later.** Candidates (pick deferred to the security
phase): Automerge's **Beelay** blind-relay pattern re-expressed over ciphertext chunks
([§10](#10-seed-node--compaction-p2)); **Keyhive/BeeKEM** CGKA for key agreement;
Loro-native **%ELO**. All are research-grade — adopting the *design* is the goal; the code
is unaudited and needs independent review before sensitive-data use. This is the project's
pacing dependency and is deliberately sequenced last.

## 3. Non-goals & accepted limitations

1. **Security is built last and is research-grade whenever built.** No turnkey option
   exists; the E2EE layer needs independent review before it carries sensitive data.
2. **Revocation = lazy revocation** (gates future content only; no clawback of synced data).
3. **No forward secrecy over history** once E2EE lands (retained-history CRDT property).
4. **Metadata leakage by design** — a blind relay sees change/version metadata (sizes,
   timing, structure, and per-blob `(peerId, counter)` ranges it needs to reconcile), not
   content. Accepted for a dev tool.
5. **Not for mutually-distrusting members** — all members of a workspace read all its
   issues; segmentation is by workspace.
6. **In-issue authorship is advisory, not authenticated.** Only the membership/ACL graph
   is signed ([§11](#11-access-control--e2ee-later)); individual Loro ops (`createdBy`,
   comment authors, activity) are self-asserted data inside the CRDT. Any member holding
   the workspace key could forge attribution. Acceptable under non-goal 5; stated so the
   "auditable history" claim isn't mistaken for cryptographic provenance.

## 4. Layered architecture

```
   ┌─ Node (human: TUI · agent: headless+MCP) ───────────────────────────┐
   │  Catalog doc  ── workspace/projects/board-order + per-issue heads    │
   │       │  drives discovery, boards, and the local index (§7,§9)       │
   │  Issue docs (one Loro document each)  ← the data model (§5)          │
   │       │ optimistic local ops, instant render                         │
   │       ▼                                                              │
   │  git repo  = DURABLE LOCAL STORE   (NOT a sync transport)            │
   │   • persisted Loro snapshots/updates (versioned, inspectable)        │
   │   • persisted copy of the genesis + signed membership/ACL graph      │
   └───────────────────────────┬─────────────────────────────────────────┘
                               │  iroh (QUIC P2P, NAT-traversed)   [P1+]
      ┌────────────────────────┼────────────────────────────────┐
      ▼                        ▼                                 ▼
   other nodes          Seed node (VM, headless)            other nodes
                        • holds full ENCRYPTED history        [P2+]
                        • blind relay (can't decrypt)
                        • ciphertext-chunk sedimentree GC
```

## 5. Data model

Hierarchy **Workspace → Projects → Issues.** Each **Issue is its own Loro document**,
addressed by a stable, content-independent **`DocId`** we mint (`iss_<ULID>`) — *not* a
Loro `peerId` (those stay an internal, per-session detail). One dedicated **Catalog
document** (per workspace) holds the membership of docs, the project config, and — the key
move — **board ordering and a per-issue head/row cache** so lists and boards render without
opening issue docs.

```
Catalog {                              // ONE Loro document per workspace
  docs:     LoroMap<DocId, DocMeta>    // authoritative set of issue docs that exist
  projects: LoroMap<ProjectId, Project>
  boards:   LoroMap<ProjectId, LoroMovableList<DocId>>  // NATIVE board order (§9)
  labels:   LoroMap<LabelId, {name, color}>
  workflowStates: [...]
  members:  <signed membership/ACL graph, root anchored in git (§6, §11)>
}

DocMeta {                              // one board row — enough to render without the issue
  projectId, kind, createdAt, deletedTombstone?
  title, status, priority, assigneeSummary   // DENORMALIZED CACHE, issue-doc is truth (§9)
  head: <opaque hash of the issue doc's oplog_frontiers>   // the sync digest (§8)
}

Issue {                                // one Loro document, addressed by DocId
  id (DocId), workspaceId, projectId
  title:       LoroText | register     // LWW-ish register (or Text if co-edited)
  description: LoroText                 // collaborative rich text
  status:      register                // LWW (+ collision noted in activity, §9)
  priority:    register                // LWW
  assignees:   LoroMap<UserId,bool>    // per-key add/remove (union-ish)
  labels:      LoroMap<LabelId,bool>
  comments:    LoroList<{author, ts, body}>
  createdBy, createdAt
  // activity feed + time-travel: derived FREE from Loro's op history
  // NOTE: board rank is NOT here — cross-issue ordering lives in Catalog.boards (§9)
}

Project { id, workspaceId, name, key, color }   // in Catalog.projects
```

Two deliberate placements, both resolving hazards flagged in review:
- **Board ordering lives in the Catalog, authoritatively** — a single `LoroMovableList<DocId>`
  per project, not a rank field copied onto each issue. This is the native movable-list win
  *and* it means order is one CRDT list that merges cleanly and is nobody's cache (§9).
- **The board-row fields in `DocMeta` are a one-directional cache** derived from the issue
  doc, never an independent source of truth (§9). This is why the old "ProjectIndex as a
  synced projection" is gone.

## 6. Git-backed store & trust root

One **git repo per node**, with a precise and *only* role: **durable local persistence.**

- **Durable store:** the node persists its Loro state (snapshots via `export(Snapshot)`,
  plus incremental `export(updates(...))`) as files committed to the repo. Git gives
  durability, versioning, and inspectability for free. On start, load = import the latest
  snapshot + updates for the Catalog, then lazily for issue docs on access.
- **Persisted trust material:** the repo also stores the node's copy of the **workspace
  genesis** (workspace id + founding admin public keys) and the **signed membership/ACL
  graph** ([§11](#11-access-control--e2ee-later)). **Public keys and signed ops only — no
  secrets in the repo.**

**Where the root of trust actually lives (clarified from the earlier draft).** Git is *not*
a shared "central truth" — every node has its own repo and git never transports between
them. The real root of trust is the **genesis key set**, distributed with the workspace
invite/ticket (the descendant of today's `RoomTicket`). The membership/ACL graph is
**synced P2P over iroh** like any other data and merely *persisted* in each node's git; it
is authenticated by chaining back to the genesis keys, not by living in a repo. So: git =
local durability; genesis-in-the-ticket = trust anchor. A node works fully standalone on
its git-backed store with no network.

## 7. Cataloging & discovery

Loro gives one document = one tree and **no multi-document container**, so the repo/catalog
layer is ours. We port the proven `automerge-repo` shape onto Loro:

- **`DocHandle`** = `{ DocId, LoroDoc, kind, head: Frontiers }`, lazily loaded from the git
  store on first access.
- **The Catalog doc** (§5) is the authoritative registry of which docs exist. **Syncing the
  Catalog tells a peer the entire `DocId` set** — no reachability crawl. (Beelay needs a
  server-side reachability index because Automerge docs link by arbitrary URL; our
  hierarchy is explicit, so an authoritative catalog replaces the crawl — strictly
  simpler.)
- Per node we keep a **head table** `DocId → Frontiers`, persisted in git, and mirror each
  issue's head into its `DocMeta.head` on every local write. That mirrored head is what
  makes discovery cheap (§8).

## 8. Propagation over iroh (P1+)

Announce over the existing `iroh-gossip` topic ("I have changes" + presence heartbeats);
sync over a direct QUIC stream on a custom ALPN. The sync itself is **catalog-first**:

**Phase 1 — catalog reconcile (one Loro diff).** Exchange a normal update-diff of the
Catalog doc (`export(ExportMode::updates(from: peer_catalog_vv))` → opaque bytes →
`import`). Because each `DocMeta.head` carries that issue's current head-hash, **diffing the
one Catalog doc already reveals exactly which issue docs changed** — the rows whose `head`
moved. This is the key result of the design: our authoritative, cheaply-diffable catalog
collapses Beelay's snapshot+set-reconciliation dance into a single CRDT diff, because we
(unlike Beelay) have one place that already knows every doc's head.

**Phase 2 — per-doc diff, multiplexed.** For each changed `DocId`, run standard Loro sync:
send my VV for that doc; peer replies `export(updates(from: my_vv))`. Multiplex all changed
docs over the one QUIC stream as length-prefixed frames keyed by `DocId` (automerge-repo's
per-doc `SyncMessage` multiplexing). Cold-start docs arrive as `export(Snapshot)` blobs over
the existing iroh-blobs path.

**Scale escape hatch.** If a workspace ever grows large enough that syncing the whole
Catalog each round is itself the cost, replace Phase 1 with **RIBLT** (rateless IBLT,
lifted from Beelay) over `{DocId, head}` so bandwidth drops to ∝ the number of *changed*
docs. The `head` field is designed now so this is a drop-in later; we do **not** build RIBLT
for P1.

Net: **catalog VV-diff → changed-head set → per-doc VV-diff multiplex**, with RIBLT reserved
as the O(differences) optimization.

## 9. UI, reactivity, indexing & conflicts

- **UI = TUI first** — the rapid-feedback, git-companion surface; Linear-grade speed via
  optimistic local Loro ops + instant render. (Tauri/local-web is a later option.)
- **Reactivity:** the node observes Loro doc changes via `subscribe_root` (local *and*
  imported) and re-renders.
- **Indexing (resolves the two-sources-of-truth hazard).** There is no separately-synced
  index. Board *ordering* is authoritative in `Catalog.boards` (a movable list of DocIds,
  nobody's cache). Board *fields* (`title`/`status`/`priority`/`assigneeSummary` in
  `DocMeta`) are a **cache with a single writer direction: the issue doc is always
  authoritative; the catalog row is a local recompute.** On every local edit *and* every
  `import()` of an issue doc, the node uses `get_changed_containers_in(...)` to see what
  changed and rewrites that issue's catalog row from the issue doc. A peer that has the
  catalog but not yet the issue doc sees a provisional row; when the issue doc arrives, the
  row self-heals. One source of truth, no cross-document transaction required.
- **Traversal & scale.** Workspace → project → ordered issues is answered entirely from the
  Catalog; a 5,000-issue workspace renders its boards from one document, not 5,000. The full
  issue body (`description`, comments, activity/time-travel) loads lazily only on open.
- **Conflict policy (decided):** silent LWW on single-value registers (`status`, `priority`)
  **plus** a non-blocking **activity-feed note** of the collision (detected by walking the
  concurrent op range — cheap, since Loro retains history). `assignees`/`labels` don't
  conflict (map-union); board order doesn't conflict (movable list).

## 10. Seed node & compaction (P2+)

Headless node on a VM. Two *different* compactions were previously conflated; they are
separate concerns:

- **Local store GC (any node, any phase).** Each node calls
  `export(ExportMode::shallow_snapshot(frontier))` to trim its own git-backed history.
  Cross-peer determinism is **not required** here — it is local persistence — so Loro's
  shallow snapshot (a per-peer GC) is exactly right.
- **Blind-relay history (the seed).** The seed holds the full **encrypted** update history
  as opaque blobs (can't decrypt), serves **cold-start backfill**, and GCs by policy —
  *without* doing Loro CRDT compaction (it can't read the ops). To make an encrypted,
  content-addressed history the relay can reconcile and GC deterministically, we rebuild
  Beelay's `sedimentree` **one layer down**: frame each doc's history as per-`(peerId)`
  linear runs, chunk each run's *ciphertext* into blobs addressed by `BLAKE3(ciphertext)`,
  and apply sedimentree's boundary rule (level = leading-zero count of the hash) to those
  ciphertext-blob hashes. Because the metric only needs a uniformly-distributed hash of the
  ciphertext, **determinism survives encryption** — precisely Beelay's "the hashes
  themselves aren't encrypted" insight, transplanted to our envelope. Concurrency across
  peers is resolved by Loro `import()` on the key-holders, never by the relay.

Multiple seeds are fine; **none is authoritative** — they can neither read nor forge. A
full encrypted-history replica is always reachable for backfill, which also mitigates the
"offline across a compaction boundary can't merge" risk.

**Seed = a headless role of the same portable node, capable of client-side rooting.** A
seed is *not* a separate server product: it is the ordinary `lait` binary run headless,
so it inherits the client's cross-platform portability (the control channel is a Unix socket
on unix / a named pipe on Windows; TLS is the portable `ring` backend) and **any client node
can be promoted to a seed**. Because it is a full node, it can *root* other clients: it is
the always-on peer whose address rides in the workspace ticket (the bootstrap anchor), it
holds and serves the genesis + signed ACL graph and the (P2+ encrypted) CRDT history for
cold-start backfill, so a brand-new client can establish the whole workspace from nothing but
a ticket. Crucially, "rooting" is **bootstrap + backfill, not trust authority**: the client
still validates every signed op against the genesis keys carried in its ticket ([§6](#6-git-backed-store--trust-root)),
so a seed can neither read (P2+) nor forge. This is what turns the always-on availability an
async tracker needs into a *portable, promotable peer role* rather than a mandatory central
server — and is why the seed belongs at **P1** (it is the bootstrap/backfill anchor two
rarely-co-online peers converge through), even though its *encrypted* blind-relay duties
still land at P2.

**Setting up a seed (CLI).** The seed role has two client-native halves, no separate server
product. On the always-on box: `lait daemon --seed` — the ordinary daemon with
idle-shutdown disabled (DUR-4) so it stays reachable to serve sync/backfill with no local
client attached. On a client: `lait seed add <ticket|endpoint-id>` — pins that peer into
a **sticky `seeds.json` registry**, distinct from the opportunistic `peers.json` bootstrap
cache (DUR-1). A ticket form also *adopts* the workspace and backfills (a fresh client
establishes the whole workspace from the ticket alone); a bare id form pins a peer whose
workspace you already share. Pins are **unioned into the gossip bootstrap set and eagerly
pulled on every daemon start**, so a client redials and reconverges through its seed even when
no laptop peer is online. `seed ls` shows pins + reachability; `seed rm <id|nick>` unpins.
Crucially a pin is **bootstrap + backfill, not trust**: the seed can neither read (P2+) nor
forge, because every op is still validated against the genesis keys in the ticket (§6) — the
pin only decides *who this node dials for history*, never *what it believes*.

**Forward-compatibility.** Because P1's wire format already frames updates as
per-`(peerId, counter)`-range blobs (§8), P2/P3 add the ciphertext-chunking + sedimentree
envelope *around* those blobs without reshaping the P1 sync protocol. The E2EE envelope is
designed now; only its implementation defers.

## 11. Access control & E2EE (later)

**In open P2P gossip you cannot prevent observation, so encryption *is* the access
control.** Non-members can see ciphertext on the topic; the **membership graph gates who
holds the workspace key.** Built last, adapting a proven design:

- **Membership/ACL:** signed ed25519 op-graph, root chained to the genesis keys distributed
  in the invite ([§6](#6-git-backed-store--trust-root)), roles `admin`/`member`;
  **remove-wins** revocation.
- **Keys:** one workspace symmetric key, distributed to members; rotated on removal (lazy
  revocation). Key agreement via an adopted design (Keyhive/BeeKEM, or simpler
  distribution) — chosen at this phase.
- **Invite pre-authorization (Pattern A):** an admin-signed, expiring, single-use **pass**
  (a bearer capability) rides in the invite ticket; an admin receiver honors it by signing
  the normal `AddMember` op automatically, so a teammate is admitted on a single `join` with
  no manual approve. This changes only the *trigger* for the seal, never who can seal — the
  key is still sealed key-side by an admin, so a non-member/removed node still sees only
  ciphertext. A synced, single-use nonce guard prevents replay. `--require-approval` keeps a
  human in the loop. Shape in [S§6.1](SCHEMA.md).
- **Blind relay:** the ciphertext-chunk sedimentree envelope of [§10](#10-seed-node--compaction-p2)
  is what lets the seed reconcile without decrypting.
- **Two-protocol split:** sync the signed ACL graph → authenticate + derive the key → sync
  encrypted Loro updates.

## 12. Agent node & MCP (P4)

The same node, headless, as a workspace **member** exposing an **MCP server** — the
descendant of `lait mcp` — so agents file/update/watch/close issues natively. Agent
VMs double as durable seed peers.

## 13. Phased build plan

| Phase | Deliverable | Proves |
|---|---|---|
| **P0** | **Pure functionality, git-backed.** Loro Issue model + **Catalog doc + `DocHandle` + board `LoroMovableList` + local materialized index** + fast TUI + git-backed store + genesis scaffolding. Single node, no network, no crypto. | Data model (correct, board-fast) + **Linear-devex TUI** + durable git-backed store — a provably-working standalone tracker |
| **P1** | **iroh P2P live sync.** Catalog-first sync: catalog VV-diff → changed-head set → per-doc VV-diff multiplexed over the QUIC ALPN + gossip announce/presence. | Real-time propagation, no central server |
| **P2** | **Seed + blind relay.** Ciphertext-chunk sedimentree envelope, encrypted-history seed, backfill, policy GC. | Availability without a data authority |
| **P3** | **E2EE access control.** Signed membership graph, key distribution/rotation, encrypted blind-relay sync — adopting a chosen proven design. RIBLT swap-in for Phase-1 if scale demands. | Confidentiality + membership/revocation |
| **P4** | **Agent node + MCP; hardening** (multi-seed, security review, UI polish). | Agent-native + production hardening |

No P1 wire rework is needed at P2/P3: formats are forward-compatible from the start (§10).

## 14. Open decisions

- **Which security design** to adapt at P3 (Beelay-ported / Keyhive-BeeKEM / Loro %ELO) —
  deferred; all research-grade.
- **UI surface beyond TUI** (Tauri vs local-web) — decide before/at P4.
- **Naming** — "lait" is kept (fits a rapid-feedback tool).
- **Validate before building (from the substrate research):** (a) two peers that
  `shallow_snapshot` at *different* frontiers must still merge — confirm and test; (b)
  `find_id_spans_between` / catalog-diff cost at thousands of docs; (c) whether per-`(peerId)`
  run chunking maps cleanly onto Loro's `updates_in_range` export for the §10 envelope, or
  needs custom framing.

## 15. Decision log

- **No-hand-rolled-security rule dropped** — no audited turnkey E2EE-for-CRDT exists, so a
  proven *design* must be implemented by hand regardless. "Proven design" is retained at the
  design level; the code is research-grade and reviewed before sensitive use.
- **Loro over Automerge (validated, not just asserted)** — since the security envelope is
  hand-rolled on either substrate, Automerge's Beelay-import edge is moot *at the design
  level*; Loro wins on performance, DX, and native types (`LoroMovableList`, `LoroText`) for
  Linear-grade devex, which is the plan's foundation. Confirmed cost: Loro has no
  content-addressed changes (ops are `(peerId, counter)`), so the blind-relay/compaction
  primitive Automerge/Beelay give for free is rebuilt once, over ciphertext chunks (§10),
  and shaped now so no earlier phase is retrofitted.
- **Catalog-first sync** — an authoritative Catalog doc carrying each issue's head collapses
  multi-doc discovery into one Loro VV-diff; per-doc diffs multiplex behind it; RIBLT is the
  large-scale escape hatch, not P1 work (§8). This replaces the single-doc sync §7 of the
  earlier draft implied.
- **Index = local cache, not synced projection** — board order is authoritative in the
  Catalog movable list; board-row fields are recomputed locally from issue docs (issue-doc
  wins), eliminating the two-sources-of-truth hazard of a replicated `ProjectIndex` (§9).
- **Two compactions separated** — local shallow-snapshot GC (determinism not required) vs.
  the seed's ciphertext-chunk sedimentree (deterministic via ciphertext-hash boundaries,
  operates without decrypting) (§10).
- **Git = durable local store; genesis-in-the-ticket = trust root** — git never transports
  and is not a shared central truth; the membership graph syncs over iroh and is merely
  persisted in git, authenticated back to the genesis keys carried by the invite (§6). Not
  git-bug; issues are Loro docs propagated over iroh.
- **Seed is a promotable client role, not a server** — the seed is the portable `lait`
  binary run headless; any client can be one. It *roots* cold clients (ticket-advertised
  bootstrap + genesis/ACL/history backfill) so a new node needs only a ticket, while trust
  stays anchored in the genesis keys, never in the seed. Its always-on availability is what
  two rarely-co-online peers converge through, so it lands at P1; only its *encrypted*
  blind-relay duties defer to P2 (§10).
- **Portable transport substrate** — iroh stays, but the package's portability is preserved
  by keeping non-iroh plumbing cross-platform: the daemon control channel is a Unix socket on
  unix / a named pipe on Windows (via `interprocess`), the single-instance guard is a
  cross-platform advisory lock (`fs2`, not raw `flock(2)`), and TLS is the portable `ring`
  rustls backend (never `aws-lc-rs`). CI builds + tests on Linux, macOS, and Windows to keep
  it that way.
- **Functionality-first sequencing** — prove the DX-critical core (data model + catalog +
  TUI + git-backed store) before networking, and networking before the hard, research-grade
  security layer.
- **Not browser/WebRTC, not DXOS, not Matrix** — see prior analysis (topology + maturity).

**Sources for the sync/catalog/compaction design:**
[Beelay protocol](https://github.com/automerge/beelay/blob/main/docs/protocol.md) ·
[Beelay sedimentree](https://github.com/automerge/beelay/blob/main/docs/sedimentree.md) ·
[Keyhive/Beelay notebook](https://www.inkandswitch.com/keyhive/notebook/05/) ·
[Loro LoroDoc API](https://docs.rs/loro/latest/loro/struct.LoroDoc.html) ·
[Loro encoding/export modes](https://www.loro.dev/docs/tutorial/encoding) ·
[automerge-repo architecture](https://deepwiki.com/automerge/automerge-repo).
