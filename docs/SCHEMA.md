# Schema — groupchat data shapes

> **Status:** design draft, pre-build. Companion to [`ARCHITECTURE.md`](./ARCHITECTURE.md);
> section refs like (A§5) point there. Defines the concrete data shapes across three
> layers and — more importantly — **what authority each field carries** and **which tool
> enforces which invariant**. Where a shape is still a live decision it is flagged
> **[DECISION]** with the chosen default in bold; flip any of them without reshaping the
> rest.

## 1. Scope & the three-layer rule

There are three schemas in this system. They describe the *same* issues but serve
different masters, and the project's correctness depends on **not letting them leak into
each other**.

| Layer | What it is | Types are… | Authority |
|---|---|---|---|
| **A. Storage / CRDT** | data *inside* Loro docs | Loro containers (`LoroMap`, `LoroText`, `LoroMovableList`, `LoroList`, leaf values) | **The truth.** All merge semantics live here. |
| **B. Control protocol** | `Request`/`Response`/`IssueEvent` over the socket | plain serde structs | **Ephemeral.** Commands + snapshot projections. Never a source of truth. |
| **C. Wire / sync** | what crosses iroh | opaque Loro `export()` bytes + framing headers (+ P2/P3 ciphertext envelope) | **Transport.** Mostly opaque. |

**The rule:** Layer B is a **stable, versioned, hand-maintained projection** of Layer A —
never a 1:1 dump of it. The moment agents and scripts scrape `Response` JSON (B§7), the
DTOs become a public contract; if they mirror the Loro layout automatically, a storage
refactor breaks every consumer. Paying to maintain B by hand buys refactor-freedom under
the CRDT. Layer C is opaque bytes plus the minimum framing needed to route them; it never
re-encodes domain fields (that would be a fourth schema to keep in sync).

## 2. Identifiers

The ID zoo is a frequent source of confusion; every identifier below is exactly one kind
of thing with one stability guarantee.

| Id | Shape | Stable? | Notes |
|---|---|---|---|
| `WorkspaceId` | `ws_<ULID>` | forever | minted at `workspace init`; part of the genesis (A§6). |
| `DocId` | `iss_<ULID>` | forever | app-minted, content-independent (A§5). Key in `Catalog.docs`, filename in git, routing key on the wire. **Not** a Loro `peerId`. |
| `ProjectId` | `prj_<ULID>` | forever | in `Catalog.projects`. |
| `LabelId` | `lbl_<ULID>` | forever | in `Catalog.labels`. |
| `UserId` | ed25519 public key | forever | **a member *is* a key.** Same bytes as the iroh `EndpointId`. Key of `assignees`, signer of ACL ops. |
| iroh `EndpointId` | ed25519 public key | per identity | the node's transport identity; equals its `UserId`. |
| Loro `PeerId` | `u64` | **per session** | internal to Loro's op addressing `(peerId, counter)`. **Never surfaced** as a user- or app-level id. A node may present many peerIds over its life. |
| log `seq` | `u64` | per node, monotonic | ring-buffer cursor for `activity`/`wait`/`watch` (B§7). **Display/notification ordering only.** |
| Lamport / `Frontiers` | Loro op ids | causal | authoritative *merge* ordering. Distinct from `seq`. |
| `KEY-n` alias | e.g. `ENG-142` | advisory | human handle; Catalog-assigned, **may collide and disambiguate** (§5.4). |

**Two orderings, never fused.** Merge and conflict reasoning use Lamport/`Frontiers`
(causal, authoritative). Display, the activity feed, and notifications use wall-clock `ts`
and the per-node `seq` (advisory). Any code that sorts issues for *merge* by wall-clock is
a bug; any code that renders the feed by Lamport is unreadable.

**Identity is one key for P0. [DECISION]** A member is a single ed25519 key. This is
simplest but means one human's laptop + phone + agent-VM are three members, so
"assigned to me" won't span devices. **Default: single-key.** Account-aggregates-devices
is deferred (it changes `assignees`, the ACL graph, and ref resolution at once). See A§14.

## 3. The authority model (the spine)

Every field in the system is exactly one of three classes. This table is the center of
gravity of the whole schema; §4–§6 just fill it in.

| Class | Examples | Written by | On conflict / on missing |
|---|---|---|---|
| **Authoritative** | issue `title/status/priority/description/assignees/labels/comments`; Catalog `projects/labels/workflowStates`; board *ordering*; ACL ops | the owning Loro doc, via normal ops (ACL ops additionally signed) | Loro merge rules (§4–§5); ACL by replay (§6) |
| **Synced cache** | `DocMeta.{title,status,priority,assigneeSummary,head}` | recomputed locally from the issue doc, *transmitted* inside the Catalog | provisional until the issue doc arrives, then overwritten |
| **Local cache** | `KEY-n` alias table, search index, `ref→DocId` map | recomputed locally, never synced | rebuilt from Catalog on load |

### 3.1 The writer-direction invariant (most breakable thing in the system)

`DocMeta`'s row fields live **inside** the Catalog Loro doc, so they *do* propagate over
the wire — but their non-authority is enforced by **convention, not structure**. The
rules, which every writer must honor:

1. **The issue doc is always truth.** `DocMeta.{title,status,priority,assigneeSummary}`
   and `DocMeta.head` are a one-directional cache *derived from* the issue doc.
2. On **every local edit** and **every `import()`** of an issue doc, recompute that issue's
   Catalog row from the issue doc (use `get_changed_containers_in(...)` to scope the work).
3. A peer holding the Catalog but not yet the issue doc shows a **provisional** row; when
   the issue doc arrives the row **self-heals** (A§9). This is expected, not an error.
4. **Nothing writes a `DocMeta` row field as if it were authoritative.** Doing so
   reintroduces the two-sources-of-truth hazard the whole design removed (A§9, decision log).

### 3.2 `head` is a cache too, and the load-time invariant

`DocMeta.head` = an opaque hash of the issue doc's `Frontiers` — a *cache of the frontiers*,
not an independent fact. Because mirroring the head into the Catalog is a **second write to
a second doc** after the issue-doc commit (writes across two Loro docs are not atomic), a
crash between them leaves a stale head and that doc silently under-syncs.

> **Load-time invariant:** on startup, do **not** trust persisted `head` / row fields.
> Recompute every `head` from the actual issue-doc frontiers and reconcile rows before
> serving sync or reads.

## 4. Layer A — Catalog document

**One Loro document per workspace** (A§5). The authoritative registry of which docs exist,
project/label config, board ordering, and the signed ACL log. Container-by-container:

```
Catalog (root LoroMap)
  schemaVersion : value<u32>                         // §9 evolution gate
  workspaceId   : value<WorkspaceId>
  docs      : LoroMap<DocId, DocMeta>                // authoritative *existence* set
  projects  : LoroMap<ProjectId, Project>
  boards    : LoroMap<ProjectId, LoroMovableList<DocId>>   // native board ORDER only
  labels    : LoroMap<LabelId, Label>
  workflow  : LoroMovableList<WorkflowState>         // ordered status columns
  acl       : LoroList<SignedOp>                      // §6 — signed, validated by replay
  aliases   : LoroMap<ProjectId, value<u32>>         // per-project KEY-n high-water (§5.4)
```

| Container | Merge rule | Notes |
|---|---|---|
| `docs[DocId]` presence | grow-only set (+ tombstone flag) | syncing the Catalog conveys the entire DocId set — no crawl (A§7). |
| `DocMeta.*` row fields | see §3.1 | **synced cache**, not truth. |
| `projects[*]`, `labels[*]` | per-key LWW on each leaf | config; concurrent renames resolve LWW. |
| `boards[proj]` | movable-list (move op, no dup) | **ordering within a project only**, not membership (§5.5). |
| `workflow` | movable-list | status columns + their order. |
| `acl` | grow-only union of opaque signed ops | trust computed by replay (§6), *not* by Loro. |
| `aliases[proj]` | LWW counter view | advisory high-water for `KEY-n`; may race (§5.4). |

```
DocMeta {                       // one board row — renders without opening the issue
  projectId       : value<ProjectId>     // CACHE of Issue.projectId (§5.5)
  kind            : value<"issue">       // reserved for future doc kinds
  createdAt       : value<u64>           // advisory wall-clock
  tombstone       : value<bool?>         // deletion = tombstone, doc still exists (§5.6)
  seq             : value<u32?>          // the n in KEY-n, advisory (§5.4)
  // --- one-directional cache of the issue doc (§3.1) ---
  title           : value<string>
  status          : value<StatusId>
  priority        : value<Priority>
  assigneeSummary : value<string>        // e.g. "you +2" — rendered, not structural
  head            : value<bytes32>       // hash of issue-doc Frontiers (§3.2)
}

Project { id, workspaceId, name, key: string, color }   // key = the ENG in ENG-142
Label   { id, name, color }
WorkflowState { id: StatusId, name, category: "backlog"|"active"|"done", color }
```

## 5. Layer A — Issue document

**One Loro document per issue** (A§5), addressed by `DocId`. In Loro a "register" is **not a
primitive** — a single last-writer-wins value is just a key in a `LoroMap` resolved by
Lamport order. So the schema is really "which container, therefore which merge rule":

```
Issue (root LoroMap)
  id          : value<DocId>
  workspaceId : value<WorkspaceId>
  projectId   : value<ProjectId>     // §5.5 — SINGLE SOURCE of project membership
  title       : value<string>        // §5.1 [DECISION: LWW value]
  description : LoroText              // collaborative rich text
  status      : value<StatusId>      // LWW
  priority    : value<Priority>      // LWW
  assignees   : LoroMap<UserId, value<true>>   // §5.2 — present key = assigned
  labels      : LoroMap<LabelId, value<true>>  // §5.2
  comments    : LoroList<Comment>    // §5.3 [DECISION: immutable body for P0]
  createdBy   : value<UserId>        // advisory (A§ non-goal 6)
  createdAt   : value<u64>           // advisory wall-clock
  // activity feed + time-travel derived FREE from Loro op history — not stored
}
```

| Field | Container | Merge rule | Conflict handling |
|---|---|---|---|
| `title` | LWW value | last writer wins | **§5.1** + activity collision note |
| `description` | `LoroText` | RGA char-merge | co-edit; interleaves cleanly |
| `status`,`priority` | LWW value | last writer wins | silent LWW **+ non-blocking activity note** (A§9) |
| `assignees`,`labels` | `LoroMap<Id,true>` | per-key LWW | **§5.2** |
| `comments` | `LoroList` | insertion-order union | never LWW; each entry immutable (§5.3) |
| `createdBy/At` | LWW value | — | **advisory, not authenticated** (A§ non-goal 6) |

```
Comment { author: UserId, ts: u64, body: string }   // §5.3
```

### 5.1 `title` — LWW value [DECISION]
**Default: LWW value + collision note.** A `LoroText` title merges concurrent edits
*character-wise*, which for a one-line title produces interleaved garbage. LWW keeps the
title coherent and records the overwrite in the derived activity feed. Flip to `LoroText`
only if co-authored titles are truly wanted.

### 5.2 `assignees` / `labels` — present-key sets [DECISION]
Modeled as `LoroMap<Id, true>`: **presence of the key = member of the set.**
**Default: remove = delete the key.** Concurrent add-vs-remove of the same id then races to
a per-key LWW (Loro decides by Lamport) — acceptable and tombstone-free. The alternative
(store `false` to remove) makes intent explicit but accumulates tombstones and still LWWs.
These sets **do not conflict** across *different* ids (map-union), matching A§9.

### 5.3 `comments` — immutable for P0 [DECISION]
**Default: immutable body.** Each `Comment` is a value-map entry in the list; adds are an
insertion-order union that never conflicts. Making comments *editable* would require each
comment to be its own `LoroMap` with `body: LoroText` (its own container) so edits merge —
a real cost we defer. Deletion, if needed, is a per-comment `tombstone` flag, not removal.

### 5.4 `KEY-n` alias — advisory, may disambiguate
The human handle `ENG-142` is **not authoritative and cannot be gapless** — a dense
per-project counter needs a coordinator a local-first P2P system doesn't have. On mint the
node reads `Catalog.aliases[proj]`, assigns the next `seq`, and writes it back; two offline
nodes can assign the same `seq`. Collisions resolve exactly like a register collision
(A§9): the loser gets a suffix (`ENG-142b`) and an activity note. The **canonical** handle
remains a **short `DocId` (ULID) prefix** (git-style), which is collision-free by
construction; `KEY-n` is a friendly alias layered on top. (See the CLI ref-resolution
decision, A§14.)

### 5.5 Project membership has one source — `Issue.projectId`
Three candidates could each imply membership: `Issue.projectId`, `DocMeta.projectId`, and
*presence in* `Catalog.boards[proj]`. Concurrent "move A from ENG to OPS" on two nodes can
leave A in **two** board lists at once. Resolution:

> **`Issue.projectId` (LWW) is the single source of project membership.** `boards[proj]` is
> **ordering within a project only**; `DocMeta.projectId` is a **cache** of `Issue.projectId`.
> **Render rule:** a board shows issues whose `projectId == P`, in the order suggested by
> `boards[P]`, **deduplicated**, with belonging-but-unlisted issues appended and
> listed-but-no-longer-belonging entries ignored. Board lists thus self-heal into caches of
> membership too, never a second source.

Moving an issue = write `Issue.projectId` (truth) + fix both board lists + recompute the
row. Only the first write is authoritative; the rest are cache maintenance.

### 5.6 Deletion = tombstone, never removal
Loro retains history, so an issue doc is never truly deleted. Deletion sets
`DocMeta.tombstone` and removes the DocId from board lists; `ls`/`board` filter tombstoned
docs. The doc still exists for backfill and time-travel.

## 6. Membership / ACL — signed ops that ride in Loro, validated by replay

A§5 draws `members` inside the Catalog, but A§11 requires a **signed ed25519 op-graph**, and
Loro's merge does **not** verify signatures (A§ non-goal 6: in-doc data is self-asserted).
Reconciliation:

> Membership rides as `Catalog.acl : LoroList<SignedOp>`, each entry an **opaque
> `{op_bytes, sig, parents}` blob**. **Loro handles propagation and set-union merge** —
> a grow-only op set, exactly right for a CRDT ACL log. **Trust is computed by deterministic
> app-layer replay** from the genesis keys (A§6): walk the ops in causal order, verify each
> signature and each op's authority against the state its parents produced, apply
> **remove-wins** revocation. **Loro never adjudicates trust; it only moves bytes.**

```
SignedOp {
  op     : bytes,        // canonical-encoded AclOp
  sig    : bytes,        // ed25519 over op, by author
  parents: [OpHash],     // causal predecessors (hash-chain to genesis)
}
AclOp = AddMember { key: UserId, role: "admin"|"member" }
      | RemoveMember { key: UserId }         // remove-wins
      | SetRole { key: UserId, role }
Genesis { workspaceId, foundingAdmins: [UserId] }   // persisted in git, in the invite ticket
```

This unifies transport (rides the normal catalog-first sync path, A§8) with the security
posture: the ACL log is the **only** signed structure and is validated *outside* Loro,
which is precisely why in-issue attribution stays advisory (A§ non-goal 6) while membership
itself is not forgeable. E2EE, key distribution, and the ciphertext envelope are deferred
to P2/P3 (A§10–§11); only the shapes above exist at P0/P1.

## 7. Layer B — control protocol (`Request` / `Response` / `IssueEvent`)

Newline-delimited JSON over the Unix socket, same transport as today. This is an
**imperative façade over a declarative CRDT**; four consequences follow and are load-bearing.

```rust
// commands
enum Request {
  IssueNew  { title, project: Option<Ref>, assignees: Vec<UserRef>,
              priority: Option<Priority>, labels: Vec<Ref>, body: Option<String> },
  IssueEdit { reff: Ref, patch: IssuePatch },      // title/status/priority
  IssueMove { reff: Ref, project: Option<Ref>, pos: Option<BoardPos> },
  Assign    { reff: Ref, who: Vec<UserRef>, add: bool },
  Label     { reff: Ref, add: Vec<Ref>, remove: Vec<Ref> },
  Comment   { reff: Ref, body: String },
  IssueView { reff: Ref },                          // lazy-loads the issue doc
  List      { project: Option<Ref>, filter: Filter },   // served from Catalog cache only
  Board     { project: Ref },
  History   { reff: Ref },                           // derived from Loro op history
  ProjectNew{ name, key }, ProjectList, LabelNew{ name, color }, LabelList,
  Activity  { since: u64 },                          // ex-Log
  Wait      { since: u64, timeout_ms: u64 },         // kept verbatim
  // P1+: Invite, Join, Connect, Peers, Sync   // P3: MemberAdd/Remove, KeyRotate
  Status, Stop,
}

// snapshot projections (stable, versioned — NOT a dump of Layer A)
enum Response {
  Ok { message: Option<String> },
  Ref { reff: String },                 // writes echo the resolved handle
  Issue(IssueView), List(Vec<Row>), Board(BoardView),
  Events { events: Vec<IssueEvent>, last: u64 },
  Error { message: String },
}
```

1. **One `Request` = one Loro commit = one activity entry.** Request granularity *defines*
   the activity-feed granularity: `IssueEdit { title, status, priority }` as one Request is
   one "edited" row; three Requests are three. Draw commit boundaries at the Request layer
   deliberately — it is how the "free" derived history (A§5) stays readable.
2. **No compare-and-swap.** A `Response` is a snapshot at a version with no cursor back into
   the doc; by the time you `edit`, the doc has moved — and that's fine, edits merge. But
   "close only if still open" is inexpressible; there is **no CAS token**. Accepted CRDT
   limitation, stated so nobody bolts on optimistic concurrency later.
3. **`Response --json` is a public, versioned contract** and simultaneously the shape MCP
   tools return (A§12). Define the DTOs once and **generate/check MCP tool schemas against
   them.** This is the concrete reason B must not track Layer A automatically (§1).
4. **`IssueEvent` is a translation, not a passthrough.** The daemon translates Loro
   `subscribe` diff events into semantic transitions:
   ```
   IssueEvent { seq: u64, doc_id: DocId, reff: String,
                change: { field, from, to }, actor: UserId, ts: u64 }
   ```
   `seq` stays a per-node ring-buffer cursor (§2), **not** the CRDT version. The existing
   `wait`/`watch`/hook/desktop-notify apparatus consumes these unchanged.

`Ref` and `UserRef` are resolved daemon-side: a `Ref` accepts a short `DocId` prefix, a
`KEY-n` alias, or a project key; a `UserRef` accepts `@me`, a nick, or a key.

## 8. Layer C — git repo layout & iroh framing

**git = durable local store, never sync transport (A§6).** One repo per node:

```
<repo>/
  genesis.json                 // workspaceId + founding admin keys (public only)
  catalog.loro                 // export(Snapshot) + appended export(updates(...))
  docs/<DocId>.loro            // per-issue snapshot + updates, lazily loaded
  heads                        // DocId -> Frontiers table (cache; recomputed on load §3.2)
  acl.loro                     // persisted copy of the signed ACL log (§6)
```

Only **public keys, signed ops, and Loro snapshots/updates** — **never secrets** (A§6).
Commit boundaries are durability points, not sync units.

**iroh framing (P1+, A§8):**
- gossip announce / presence heartbeat: `{ workspaceId, catalogHead }` ("I have changes").
- sync over a direct QUIC stream on a custom ALPN, **catalog-first**: one Catalog VV-diff
  reveals the changed-head set, then per-doc VV-diffs multiplexed as **length-prefixed
  frames keyed by `DocId`**; cold-start docs arrive as `export(Snapshot)` blobs over
  iroh-blobs.
- **Forward-compat (A§10):** frames are already per-`(peerId,counter)`-range blobs keyed by
  `DocId`, so P2/P3 wrap the ciphertext-chunk sedimentree envelope *around* them without
  reshaping this protocol. The framing schema is fixed now; only the envelope defers.

## 9. Schema evolution discipline

A CRDT **retains every historical op**, so you cannot cleanly rename or retype a container
after it ships — the old ops live forever. Rules:

1. **Fields are add-only.** New fields default when absent; never repurpose a key.
2. **Container types are frozen once shipped.** A field cannot change from LWW value to
   `LoroText` (or vice-versa) in place; that is a new key + a migration op.
3. **`Catalog.schemaVersion` gates readers.** Bump on any additive change; readers tolerate
   unknown newer fields and supply defaults for missing older ones.
4. **Renames are migrations,** written as ops (new key populated from old, old tombstoned),
   never edits to history.

## 10. Open decisions (mirror of A§14)

- **§5.1** `title` — **LWW value** (default) vs `LoroText`.
- **§5.2** `assignees`/`labels` removal — **delete-key** (default) vs `false` tombstone.
- **§5.3** comments — **immutable P0** (default) vs editable (per-comment sub-containers now).
- **§2** member identity — **single key P0** (default) vs account-aggregates-devices.
- **§5.5** project membership source — **`Issue.projectId`** (agreed) with board lists +
  `DocMeta.projectId` as self-healing caches.
