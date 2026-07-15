# Schema — lait data shapes

> **Status:** implemented (v0.4.8, `schemaVersion = 1`); this is the design of record.
> Companion to [`ARCHITECTURE.md`](./ARCHITECTURE.md); section refs like (A§5) point
> there. Defines the concrete data shapes across three layers and — more importantly —
> **what authority each field carries** and **which tool enforces which invariant**.
> Shapes that were live decisions are flagged **[DECISION]** with the **shipped default**
> in bold; each is stated so it could be flipped without reshaping the rest.

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
| log `seq` | `u64` | **per daemon session**, monotonic | ring-buffer cursor for `activity`/`watch`/`subscribe` (B§7). **Display/notification ordering only.** **Not durable** — resets to 0 on daemon restart; clients rebaseline via a `Reset` doorbell (B§7.5), never persist it. |
| Lamport / `Frontiers` | Loro op ids | causal | authoritative *merge* ordering. Distinct from `seq`. |
| `KEY-n` alias | e.g. `ENG-142` | advisory | human handle; Catalog-assigned, **may collide and disambiguate** (§5.4). |

**Two orderings, never fused.** Merge and conflict reasoning use Lamport/`Frontiers`
(causal, authoritative). Display, the activity feed, and notifications use wall-clock `ts`
and the per-session `seq` (advisory). Any code that sorts issues for *merge* by wall-clock is
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
  name          : value<string>                      // display name — LWW, cosmetic (§4.1)
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
| `boards[proj]` | movable-list (move op, no dup) | **ordering within a project only**, not membership (§5.5); completed issues are removed from it and render via the append rule (§5.7). |
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

### 4.1 Workspace `name` — cosmetic, never network identity

The display name is a plain LWW register in the Catalog: set at founding (`lait init
--name`, default the directory name), renameable later, synced like any config field.
It carries **no authority and no network meaning** — the gossip topic derives from the
`WorkspaceId` (`topic_for_workspace`, a domain-separated blake3 of the id), so renaming
never re-topics a live workspace and never invalidates tickets. This deliberately
replaces the retired "room" string (a folder-seeded name that doubled as the topic and
could drift; see the decision log). A fresh joiner's catalog is empty until the
founder's ops arrive, so the name may legitimately read as empty pre-sync.

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

### 5.7 Completion vs. deletion — done issues leave the ordered list, not the traversal set
Completion and deletion are different operations with different effects on traversal.
Completion is only a `status` change to a `done`-category `WorkflowState` (LWW value, §5) —
the issue is **not** tombstoned and stays in `Catalog.docs` forever (history, time-travel,
backfill). But because the board movable list is **ordering, not membership** (§5.5), a
completed issue does not need to occupy a slot in it:

> **On completion, remove the `DocId` from `Catalog.boards[projectId]`** (keep it in `docs`,
> keep `Issue.projectId`). The issue still belongs to the project, so it renders on the
> **Done** view via §5.5's append rule (belonging-but-unlisted issues are appended).
> **On reopen, re-insert** the `DocId` into the ordered list (default: top of its status
> lane). Done-view display order is by wall-clock `ts` descending (advisory, §2), since the
> movable list no longer ranks it.

This keeps the active board's movable list **bounded to roughly the active set** instead of
growing without bound as issues close, while the full issue set remains reachable by
traversal (`docs` filtered by `projectId`). It falls straight out of the
membership-vs-ordering split (§5.5) and needs no new structure. Distinct from store GC
(A§10 shallow-snapshot), which trims op *history* and never changes what is in the traversal
set.

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

### 6.1 Invite pre-authorization (Pattern A) — a signed pass that auto-seals

Admission normally needs two admin actions around the joiner's `join` (issue the ticket,
then `members approve`). A **pass** collapses that to one: an admin signs a bearer
capability that any node can carry, and an admin receiver honors it by signing the same
`AddMember` op automatically — **no new trust primitive, no weakening of E2EE** (the seal
still happens key-side on an admin holding the workspace key).

```
InviteGrant {
  workspace  : WorkspaceId,   // binds the pass to one room
  nonce      : bytes[16],     // random id; a single-use pass is spent exactly once
  expires_at : u64,           // unix seconds; the redeemer checks freshness
  single_use : bool,          // one redemption vs. valid-until-expiry (a team link)
}
SignedInvite { issuer: PublicKey, grant: bytes(InviteGrant), sig }   // rides in the WorkspaceTicket
                                                                     // + the gossip JoinRequest
```

A redeeming node enforces, against **live** state, in this order: the issuer signature
(transport), `workspace` match + not `expires_at` (transport), the issuer ∈ current admins
and *we* are an admin able to seal (tracker), and — for `single_use` — the nonce is unspent.
Any failure is a **silent fallback** to the pending-request flow (§6), so a bad/expired/
foreign/spent pass never blocks a manual `members approve`.

The single-use guard is synced membership state — a new container alongside the ACL log:

```
membership doc (LoroDoc, synced unencrypted like the rest of §6):
  acl       : LoroList<SignedOp>            // the signed op-graph above
  keys      : Map<epoch, Map<UserId, sealed>>   // §11 key envelopes
  redeemed  : Map<nonce(hex), UserId>       // burned single-use passes (redeemer recorded)
```

The nonce is burned in the **same commit** as its `AddMember` op (atomic — no window where
a member is added but the pass stays live), and because it syncs, a second admin inherits the
same replay protection.

## 7. Layer B — control protocol (`Request` / `Response` / `IssueEvent`)

Newline-delimited JSON over the Unix socket, same transport as today. This is an
**imperative façade over a declarative CRDT**; five consequences follow and are load-bearing.

```rust
// commands
enum Request {
  IssueNew  { title, project: Option<Ref>, project_hint: Option<String>,
              assignees: Vec<UserRef>, priority: Option<Priority>,
              labels: Vec<Ref>, body: Option<String> },
  IssueEdit { reff: Ref, patch: IssuePatch },      // title/status/priority
  IssueStart{ reff: Ref }, IssueDone{ reff: Ref }, IssueStop{ reff: Ref },
                                                    // work-state verbs: one intent =
                                                    // ONE commit = one activity row;
                                                    // targets by workflow CATEGORY;
                                                    // return Response::Issue (the one
                                                    // writes-echo-Ref deviation)
  IssueMove { reff: Ref, project: Option<Ref>, pos: Option<BoardPos> },
  Assign    { reff: Ref, who: Vec<UserRef>, add: bool },
  Label     { reff: Ref, add: Vec<Ref>, remove: Vec<Ref> },
  Comment   { reff: Ref, body: String },
  IssueView { reff: Ref },                          // lazy-loads the issue doc
  IssueDelete { reff: Ref },                         // tombstone (§5.6)
  List      { project: Option<Ref>, filter: Filter },   // served from Catalog cache only
  Board     { project: Option<Ref>, project_hint: Option<String> },   // §7.6 chain
  History   { reff: Ref },                           // derived from Loro op history
  ProjectNew{ name, key }, ProjectList, LabelNew{ name, color }, LabelList,
  Activity  { since: u64 },                          // ex-Log; the feed is PULLED, §7.5
  Inbox     { clear: bool },                         // durable addressed-to-you (§8.1)
  Subscribe { since: u64 },                          // §7.5 — the one live channel (TUI + watch)
  Diagnose  { expected_workspace: Option<WorkspaceId> },   // guided-join verifier (GUIDED-JOIN.md)
  ConfigReload,                                      // transport-plane; re-read local settings
  // transport (P1): Invite, Join, Connect, Who, SeedAdd/List/Remove
  // membership (P3): MemberAdd/Remove, KeyRotate, Members, MemberRequests/Approve/Alias
  Status, Id, Stop,
}

// snapshot projections (stable, versioned — NOT a dump of Layer A)
enum Response {
  Ok { message: Option<String> },
  Ref { reff: String },                 // writes echo the resolved handle
  Issue(IssueView), List(Vec<Row>), Board(BoardView),
  Events { events: Vec<IssueEvent>, last: u64 },
  Error { message: String },
}

// streamed frame — the reply to `Subscribe`, written repeatedly (not a Response), §7.5
struct Doorbell {
  epoch: u64,                              // per-daemon-boot nonce; a change ⇒ restart ⇒ Reset
  seq:   u64,                              // per-session cursor (§2)
  reset: bool,                             // true ⇒ ignore the rest, rebaseline from a snapshot
  dirty_by_project: Map<ProjectId, Vec<DocId>>,   // issue-row plane — re-read these rows
  dirty_catalog:    Vec<CatalogScope>,     // structure plane: boards(proj)|projects|labels|workflow|acl
  activity_advanced: bool,                 // new feed rows exist — pull via Activity{since}
  presence_advanced: bool,                 // new presence/join rows exist — pull via Log{since}
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
4. **`IssueEvent` is a translation, not a passthrough** — and, for a live client, a
   **doorbell, not a delta.** The daemon translates Loro `subscribe`/`subscribe_root` diff
   events (local *and* imported, A§9) into semantic transitions:
   ```
   IssueEvent { seq: u64, doc_id: DocId, reff: String,
                changes: [{ field, from, to }], actor: UserId, ts: u64 }   // note: a LIST
   ```
   `changes` is a **list** so one Request = one commit = **one** activity row even when it
   moved several fields (§7.1). But an `IssueEvent` is used two ways, and only the first is a
   payload:
   - **Activity feed (payload).** The feed renders the `changes`/`actor`/`ts` — a transition
     you cannot reconstruct from current state. Pulled on demand via `Activity{since}` (never
     force-streamed; a bulk import would flood it).
   - **Live board model (doorbell).** A live client does **not** patch from `changes`. It
     treats the event as "this `doc_id` is dirty," re-reads the authoritative `DocMeta` row
     (§3.1 keeps it materialized and merge-correct), and repaints. No op-id, no embedded value
     — the row *is* the LWW winner. This is why reconciliation needs no correlation.

5. **Streaming (`Subscribe`) and `Reset`.** `Subscribe{since}` turns the one-shot control
   handler into a stream of `Doorbell` frames (above) until the client disconnects — the one
   live channel (TUI and CLI `watch`; the `Wait` long-poll it superseded is deleted). The
   `presence_advanced` plane rings on `EventLog` pushes (peer online/offline/join) independently
   of the tracker dirty-set, so `watch` wakes even when no doc moved. Doorbells are **batched and
   project-keyed**: the daemon coalesces a whole sync-import transaction (+ a short local-edit
   debounce) into one frame carrying a *dirty set*, so the ring buffer holds ~1000 *batches*,
   not individual changes, and a client filters by visibility (re-reading only on-screen
   projects). Project keying is free — every dirty doc's `projectId` is in hand during the
   §3.1 `DocMeta` recompute. Because `seq` is per-session (§2) and the ring is bounded, the
   daemon rings a **`Reset` doorbell** — as the first frame of every `Subscribe`, and whenever
   a client's `since` is stale or has fallen off the ring — meaning *rebaseline from a fresh
   `Board`/`List` snapshot*. A per-boot `epoch` lets a client detect a restart without a socket
   drop. This is also the fix for the pre-existing `watch` deafness across daemon
   restarts. The write path is **validate-then-commit**: a `Response::Error` is returned
   *before* any commit, so it guarantees nothing changed and no doorbell rang (there is no CAS,
   §7.2), which is what makes an optimistic client's rollback race-free.

`Ref` and `UserRef` are resolved daemon-side: a `Ref` accepts a short `DocId` prefix, a
`KEY-n` alias, or a project key; a `UserRef` accepts `@me`, a nick, or a key.

### 7.6 The choose-project chain (`new` / `board`)

Commands that need one *target/view* project resolve it daemon-side in a fixed
precedence, in `Tracker::choose_project`:

1. **explicit** `-p` / positional — a miss is a hard error ("user said X");
2. **`project_hint`** — the project KEY the CLI extracted from the git branch
   (`eng-142-fix` → `ENG`). Used **only if it resolves** to a real project;
   otherwise it falls through silently ("environment suggests X" must never
   break a command). MCP always sends `None` (agents have no branch);
3. **`project.default`** — the store-config key, read fresh per request (no
   boot cache, no reload protocol needed). Set-but-stale is a **hard error**
   naming the fix (a user-chosen setting must not silently rot);
4. **the sole project** when exactly one exists;
5. a teaching error listing the keys and the `lait config set project.default`
   one-liner.

The two hint-free commands are deliberate: `ls -p` is a **pure filter** (a
defaulted filter silently hides issues), and `move -p` is **explicit only**
(a silently-inferred membership write is data damage).

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

**Store creation is explicit.** A `<repo>` (a `.lait/` home) is born only in `lait init`
(founding: genesis minted here, first project seeded) or `lait join` (bootstrap from a
ticket: the ticket's genesis + **empty** catalog/membership docs, so importing the
founder's ops adopts identical container ids). Nothing else creates one; a command in a
store-less directory errors with guidance. `Tracker::open` on an uninitialized store is
an error, never a founding event.

### 8.1 Machine-level local files (not Layer A — never synced, never trusted)

Under the platform config root, beside the global `secret.key`:

```
workspaces.json    // the space registry: [{ workspace, name, path,
                   //   origin: "founded"|"joined", host_nick, last_opened,
                   //   projects: [{key,name}] }]
                   // written by init / join / every daemon open; pure navigation
                   // state (powers `lait spaces` + `-w`); advisory `name`/
                   // `projects` snapshots; corrupt/absent ⇒ "no known spaces"
config.json        // global settings layer (flat string map)
```

Inside each store home, beside `config.json`:

```
inbox.json         // the durable inbox: { read_up_to_ts,
                   //   entries: [{ ts, kind: assigned|comment|status, reff,
                   //     doc_id, title, detail, actor: Option<key> }] }
                   // ≤200 newest; never synced; corrupt/absent ⇒ empty
```

**Inbox derivation is attribution-honest.** Entries are derived at sync-import time
(`import_doc`) as *state transitions relevant to the viewer* — remote ops carry no
trusted actor (non-goal 6), so `assigned`/`status` entries render actor-unknown; only
`comment` entries carry an author (`actor` = the comment's in-doc key), whose display
nick the daemon resolves at READ time (petname > live presence > short key — never
persisted). Backfill is structurally bounded: a brand-new-to-this-node doc contributes
at most one `assigned` entry, never a comment/status flood. The activity ring stays
the per-session workspace firehose; the inbox is the durable, filtered, watermarked
"addressed to you" — two different questions, deliberately two structures.

Inside each store home: `config.json` — the store settings layer. `lait config` fronts
the two layers git-style (store wins). Closed key table: `user.nick` (global+store,
daemon-read → best-effort `ConfigReload` on set), `project.default` (store-only, read
lazily per request, §7.6), `tui.theme` (global+store, `dark|light|auto`, client-read),
`tui.tabs` (store-only, JSON `Vec<SavedTab>` — the TUI's saved view tabs, UI §5.2).
One **open prefix**: `tui.key.<action-id>` (global+store) rebinds one TUI action; the
config layer validates the prefix only, the TUI validates suffixes and warns (never
gates) on unknown ones. The `workspace.*` namespace is **reserved** for future settings
that sync through the Catalog. The old per-store `profile.json` is retired.

**Ticket (wire, base32):** `WorkspaceTicket { workspace, name, host, host_nick,
invite: Option<SignedInvite> }` — the topic is derived (`topic_for_workspace`), never
shipped; `name` is a cosmetic preview for the joiner.

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

## 10. Decisions — shipped defaults (mirror of A§14)

- **§5.1** `title` — **LWW value** (default) vs `LoroText`.
- **§5.2** `assignees`/`labels` removal — **delete-key** (default) vs `false` tombstone.
- **§5.3** comments — **immutable P0** (default) vs editable (per-comment sub-containers now).
- **§2** member identity — **single key P0** (default) vs account-aggregates-devices.
- **§5.5** project membership source — **`Issue.projectId`** (agreed) with board lists +
  `DocMeta.projectId` as self-healing caches.
- **§5.7** completion policy — **done issues leave `boards[proj]`, stay in `docs`** (agreed),
  rendering on the Done view via the append rule; bounded active board.
- **§7.4** live events are **doorbells, not deltas** (agreed) — a live client re-reads the
  materialized `DocMeta` row on a dirty-notice; `changes` is a list carried only for the
  pulled activity feed. See `UI.md` §4.2–§4.3.
- **§7.5** streaming `Subscribe` + batched, project-keyed doorbells + `Reset`/`epoch`
  rebaseline; `seq` per-session, not durable (§2) (all agreed). See `UI.md` §4.1–§4.2.
- **§4.1** network identity — **topic derives from `WorkspaceId`**; the "room" string
  (folder-seeded, drift-prone, three heal layers) is retired; display name is a synced LWW
  register (agreed, workspace re-architecture).
- **§8** workspace creation — **explicit only** (`init` founds + seeds a first project;
  `join` bootstraps from the ticket); lazy mint and join-time adoption are removed
  (agreed, workspace re-architecture).
- **§7.6** project defaulting — explicit > branch hint (resolve-or-skip) >
  `project.default` (resolve-or-error) > sole project > teaching error (agreed).
- **§7** work-state verbs — `start`/`done`/`stop` bundle the fields one human intent
  moves (status by workflow category + the viewer's assignment) into ONE commit; they
  return `Response::Issue` so the CLI can derive the git branch (agreed, DX phase).
- **§8.1** inbox — durable local `inbox.json` derived at import time,
  attribution-honest (comments only carry an author), beside — never replacing — the
  per-session activity ring (agreed, DX phase). Labels create on first use; project
  creation is key-first (`projects add KEY [NAME]`); the surface noun is **space**.
