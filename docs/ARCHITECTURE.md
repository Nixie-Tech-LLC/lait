# Architecture & Plan — groupchat: a P2P issue tracker

> **Status:** design draft, pre-build. Native Rust. Loro CRDT, git-backed store,
> iroh P2P propagation. Built **functionality-first** (see [§12](#12-phased-build-plan)).
> Supersedes the current chat-oriented `groupchat` code; keeps the name + iroh
> foundation.

## 1. What this is

`groupchat` becomes a **local-first, peer-to-peer issue tracker** — a decentralized,
rapid-feedback alternative to Linear that runs as a **native Rust node**. It is built in
layers, each provable on its own:

1. **Functionality (git-backed):** a Loro-CRDT issue model + a fast TUI, persisted in a
   local **git repo** that is both the durable store and the trust anchor. A useful,
   standalone tracker with **Linear-grade devex speed** — no network, no crypto yet.
2. **Propagation (iroh):** live peer-to-peer sync over iroh (QUIC + NAT traversal),
   making it reactive/real-time across nodes with no central server.
3. **Access control (E2EE):** encrypted, blind-relay sync with membership/revocation —
   adapting a proven *design* (not a turnkey library; see [§2](#2-substrate--security-posture)).

Git is the **store + trust anchor, never the sync transport.** This is *not* git-bug:
issues are Loro CRDT documents, propagated P2P over iroh; git holds each node's durable
store and the shared root of trust.

### Kept from today's groupchat
iroh endpoint + `EndpointId` (ed25519 identity) · iroh-gossip topic (→ per-workspace
announce/presence) · direct QUIC streams on a custom ALPN (→ pairwise Loro sync) ·
iroh-blobs (→ attachments/snapshots) · `SignedMessage` sign/verify primitive (→ signed
membership ops) · presence · daemon + control socket + CLI + `mcp` + agent registry.

### Dropped
- **groupchat's "access control"** — a room is an *open* gossip topic; messages are
  signed but unencrypted; "contacts/approval" only gate the *calls* feature (local,
  unauthenticated). No confidentiality, no real authz. Rebuilt from scratch ([§10](#10-access-control--e2ee-later)).
- **Chat domain**, **iroh's role as anything but transport**, and **any browser/WebRTC** idea.

## 2. Substrate & security posture

**CRDT = Loro** (not Automerge). Rationale, given the constraints we settled:
- There is **no audited, turnkey E2EE-for-CRDT library** (research proved this). So the
  "no hand-rolled security" rule can't hold literally — you implement a proven security
  *design* by hand on **either** substrate. That neutralizes Automerge's one decisive
  edge (Beelay as an importable precedent — it's a *design to copy*, not a crate).
- With the envelope hand-rolled regardless, **Loro wins on what's left: performance,
  DX, and richer native types** — which is what "Linear devex speeds" demands.

**Honest tradeoff (eyes open):** Loro identifies changes by logical `(peerId, counter)`,
not content hashes, so the blind-relay envelope (content-addressing changes so a relay
reconciles without decrypting) is more work to build; and Loro's shallow-snapshot
compaction is **not** documented as deterministic across peers (Automerge's sedimentree
was). We accept both — and the git anchor **recovers determinism** by holding the
**compaction policy** rather than relying on convergent hashing.

**Security = adapt a proven design, later.** Candidates (pick deferred to the security
phase): Automerge's **Beelay** blind-relay pattern ported to Loro; **Keyhive/BeeKEM**
CGKA for key agreement; Loro-native **%ELO / EloLoroAdaptor**. All are research-grade —
adopting the *design* is the goal; the code is unaudited and needs independent review
before sensitive-data use. This is the project's pacing dependency and is deliberately
sequenced last.

## 3. Non-goals & accepted limitations

1. **Security is built last and is research-grade whenever built.** No turnkey option
   exists; the E2EE layer needs independent review before it carries sensitive data.
2. **Revocation = lazy revocation** (gates future content only; no clawback of synced data).
3. **No forward secrecy over history** once E2EE lands (retained-history CRDT property).
4. **Metadata leakage by design** — a blind relay sees change/version metadata (sizes,
   timing, structure), not content. Accepted for a dev tool.
5. **Not for mutually-distrusting members** — all members of a workspace read all its
   issues; segmentation is by workspace.

## 4. Layered architecture

```
   ┌─ Node (human: TUI · agent: headless+MCP) ───────────────────────────┐
   │  Loro documents (issues/projects/config)  ← the data model          │
   │        │ optimistic local ops, instant render                        │
   │        ▼                                                             │
   │  git repo  = DURABLE STORE + TRUST ANCHOR   (NOT a sync transport)   │
   │   • persisted Loro snapshots/updates (versioned, inspectable)        │
   │   • workspace genesis, signed membership/ACL graph, compaction policy│
   └───────────────────────────┬─────────────────────────────────────────┘
                               │  iroh (QUIC P2P, NAT-traversed)   [P1+]
      ┌────────────────────────┼────────────────────────────────┐
      ▼                        ▼                                 ▼
   other nodes          Seed node (VM, headless)            other nodes
                        • holds full ENCRYPTED history        [P2+]
                        • blind relay (can't decrypt)
                        • backfill; git-anchored compaction
```

## 5. Data model

Hierarchy **Workspace → Projects → Issues.** Each **Issue is its own Loro document**.
Loro's native types are a DX win here:

```
Issue {                          // one Loro document
  id, workspaceId, projectId
  title:       LoroText | string  // LWW-ish register (or Text if co-edited)
  description: LoroText            // collaborative rich text
  status:      register           // LWW (+ collision noted in activity, §9)
  priority:    register           // LWW
  assignees:   LoroMap<UserId,bool>  // per-key add/remove (union-ish)
  labels:      LoroMap<LabelId,bool>
  rank:        LoroMovableList slot  // NATIVE movable ordering — no fractional-index hack
  comments:    LoroList<{author, ts, body}>
  createdBy, createdAt
  // activity feed + time-travel: derived FREE from Loro's op history
}

Project { id, workspaceId, name, key, color }        // in workspace config doc
WorkspaceConfig {                                     // one Loro document
  members:  <signed membership/ACL graph, anchored in git (§10)>
  projects: LoroMap<projectId, Project>
  labels:   LoroMap<labelId, {name, color}>
  workflowStates: [...]
}
```

- **Board ordering uses `LoroMovableList`** natively — a concrete Loro advantage over the
  fractional-index workaround Automerge would need.
- **Per-project index docs** (`ProjectIndex(projectId)`) remain the fast-lookup projection
  for lists/boards, updated alongside issue writes.

## 6. Git-backed store & trust anchor

One **git repo per node** serves two roles — and only these two:

- **Durable store:** the node persists its Loro state (snapshots via `export`, plus
  incremental updates) as files committed to the repo. Git gives durability, versioning,
  and inspectability for free. On start, load = import the latest snapshot + updates.
- **Trust anchor** (the one sanctioned "central truth," per "no single truth-holder
  *unless* it lives in the git repo"): the repo commits the **workspace genesis**
  (workspace id, founding admin public keys), the **signed membership/ACL graph** (each
  add/remove is a signed op — auditable via git history), and the **compaction policy**.
  **Public keys and signed ops only — no secrets in the repo.**

Git is **never the propagation mechanism** — that is iroh (P1+). A node works fully
standalone on its git-backed store with no network.

## 7. Propagation over iroh (P1+)

Two channels, reusing groupchat's patterns:
- **Announce + presence (gossip):** an `iroh-gossip` topic per workspace; nodes broadcast
  "I have new updates / here's my version vector" beacons + presence heartbeats.
- **Pairwise sync (direct QUIC stream on a custom ALPN):** Loro's version-vector diff
  (`export({mode:"update", from: peer_version})` → opaque bytes → `import`) runs over a
  direct stream. iroh-blobs carries bulk snapshots for cold-start.

## 8. Seed node (P2+)

Headless node on a VM. **Blind relay:** holds the full **encrypted** update history as
opaque blobs (can't decrypt), serves **cold-start backfill**, and applies the
**git-anchored compaction policy**. Multiple seeds are fine; **none is authoritative** —
they can neither read nor forge. This also mitigates the "offline across a compaction
boundary can't merge" risk (shared by Loro and Automerge): a full encrypted-history
replica is always reachable for backfill.

## 9. UI, reactivity, conflicts

- **UI = TUI first** — the rapid-feedback, git-companion surface; Linear-grade speed via
  optimistic local Loro ops + instant render. (Tauri/local-web is a later option.)
- **Reactivity:** the node observes Loro doc changes (local + incoming) and re-renders.
- **Conflict policy (decided):** silent LWW on single-value registers (`status`,
  `priority`) **plus** a non-blocking **activity-feed note** of the collision (Loro
  retains history, so it's nearly free). `assignees`/`labels`/`rank` don't conflict
  (map-union / movable-list).

## 10. Access control & E2EE (later)

**In open P2P gossip you cannot prevent observation, so encryption *is* the access
control.** Non-members can see ciphertext on the topic; the **membership graph gates who
holds the workspace key.** Built last, adapting a proven design:

- **Membership/ACL:** signed ed25519 op-graph, root anchored in the git repo (§6), roles
  `admin`/`member`; **remove-wins** revocation.
- **Keys:** one workspace symmetric key, distributed to members; rotated on removal
  (lazy revocation). Key agreement via an adopted design (Keyhive/BeeKEM, or simpler
  distribution) — chosen at this phase.
- **Blind relay:** content-address + encrypt Loro updates so the seed reconciles without
  decrypting (Beelay pattern ported, or Loro %ELO).
- **Two-protocol split:** sync the signed ACL graph → authenticate + derive the key →
  sync encrypted Loro updates.

## 11. Agent node & MCP (P4)

The same node, headless, as a workspace **member** exposing an **MCP server** — the
descendant of `groupchat mcp` — so agents file/update/watch/close issues natively. Agent
VMs double as durable seed peers.

## 12. Phased build plan

| Phase | Deliverable | Proves |
|---|---|---|
| **P0** | **Pure functionality, git-backed.** Loro Issue/Project/Index model + fast TUI + git-backed store + trust-anchor scaffolding (committed genesis). Single node, no network, no crypto. | Data model + **Linear-devex TUI** + durable git-backed store — a provably-working standalone tracker |
| **P1** | **iroh P2P live sync.** Loro-over-iroh (version-vector export/import + gossip announce/presence). | Real-time propagation, no central server |
| **P2** | **Seed + blind relay.** Encrypted-history seed, backfill, git-anchored compaction. | Availability without a data authority |
| **P3** | **E2EE access control.** Signed membership graph, key distribution/rotation, encrypted blind-relay sync — adopting a chosen proven design. | Confidentiality + membership/revocation |
| **P4** | **Agent node + MCP; hardening** (multi-seed, security review, UI polish). | Agent-native + production hardening |

## 13. Open decisions

- **Which security design** to adapt at P3 (Beelay-ported / Keyhive-BeeKEM / Loro %ELO) —
  deferred; all research-grade.
- **UI surface beyond TUI** (Tauri vs local-web) — decide before/at P4.
- **Naming** — "groupchat" is kept (fits a rapid-feedback tool).

## 14. Decision log

- **No-hand-rolled-security rule dropped** — no audited turnkey E2EE-for-CRDT exists, so a
  proven *design* must be implemented by hand regardless. "Proven design" is retained at
  the design level; the code is research-grade and reviewed before sensitive use.
- **Loro over Automerge** — since the security envelope is hand-rolled on either substrate,
  Automerge's Beelay-import edge is moot; Loro wins on performance, DX, and native types
  (`LoroMovableList`, `LoroText`) for Linear-grade devex. Cost: more envelope work + a
  git-anchored compaction policy to recover determinism. (Automerge/Beelay remains the
  reference design to copy.)
- **Git = store + trust anchor, never sync transport** — not git-bug; issues are Loro docs
  propagated over iroh. Satisfies "no single truth-holder unless it lives in the git repo."
- **Functionality-first sequencing** — prove the DX-critical core (data model + TUI +
  git-backed store) before networking, and networking before the hard, research-grade
  security layer.
- **Not browser/WebRTC, not DXOS, not Matrix** — see prior analysis (topology + maturity).
