# Data contract

This document defines LAIT's durable and replicated invariants. It describes
behavior rather than duplicating Rust types or byte layouts. Exact encodings and
versions are fixed by source, golden fixtures, schemas, and `PROTOCOL.md`.

## 1. Coordinates of a committed view

Every authorized World operation is evaluated at two explicit coordinates:

```text
(authority frontier, Manifest root)
```

The authority frontier selects historical Mechanics state. The Manifest root
selects the complete authenticated Body view. Runtime pins both before invoking
a World and compares both again inside the Station writer before committing.
Either coordinate changing causes the local operation to commit nothing.

A query is also pinned to both coordinates. Derived output must never combine
Bodies from one Manifest with policy or Bodies from another.

## 2. Durable stores and journals

Each Space participation has one orbital store. Its marker identifies the store
format before any mutable file is trusted. Unknown, foreign, truncated, or
unsupported formats fail closed; there is no legacy-store interpretation.

Durability uses immutable content-addressed objects plus an atomically replaced
manifest:

1. reserve and persist a strictly advancing sequence;
2. write a `Prepared` journal record;
3. write and sync temporary objects;
4. record `MaterialReady`, place objects, and sync their directory;
5. replace and sync the authoritative manifest last;
6. acknowledge, record completion where required, and remove the journal.

Sequence gaps are allowed; reuse is not. Recovery exposes the complete old
manifest or the complete new manifest. Corruption, a lagging/missing counter, or
an object whose bytes do not match its reference is an integrity error, never a
cache miss or an invitation to reconstruct guesses.

Mechanics and Fabric reuse the semantics-free journal mechanism but maintain
separate semantic manifests. A journal is not replicated product state.

## 3. Mechanics authority data

Mechanics stores signed effects, graph/index deltas, authority checkpoints, and
batch receipts. Signed effects remain the semantic source of truth; checkpoints
are verified materializations that accelerate exact historical evaluation.

An `AuthorityFrontier` contains only heads that may change ordinary authority:
actor/device history, ACL and scoped policy effects, and terminal
`SpaceAuthority` effects. Ceremony proposals, rounds, custody attestations, and
abort/completion traffic use `CeremonyMaterial` and a separate bounded cursor.
They never become ordinary authority heads.

An authority batch is all-or-nothing. Its receipt binds the Space, prior
frontier, resulting frontier, and ordered batch digest. A prefix of a rejected
batch cannot survive restart.

Historical evaluation never substitutes current authority. A grant, revoke,
device state, World implementation activation, or delegation is interpreted at
the exact referenced frontier.

## 4. Body transactions and Manifests

Replica is the authority for the protected Body graph. A signed Body transaction
binds:

- Space, World, author actor/device, and request identity;
- its parent Manifest root and authority frontier;
- World implementation and schema bindings;
- ordered Body descriptors and protected payload commitments;
- intent, operation, effect, demand, and authorization-receipt digests.

The transaction id identifies the complete signed envelope. Reusing a request
identity with identical bytes returns the original result; reusing it with
different content is a conflict.

A signed Manifest commits a complete Body set through canonical pages. Entries
are globally ordered. A Body may have multiple constituent transaction heads;
concurrent writes are retained rather than collapsed into a single transport
winner. Same-coordinate equivocation rejects.

Adopting a Manifest is atomic. Replica validates and stages every required
transaction, protected payload, authority dependency, schema binding, and quota
before one journal commit installs the complete replacement root. No accepted
prefix is externally visible when a later item fails.

Remote work may reference a verified historical or concurrent parent rather
than the receiver's current root. That exact parent's authenticated snapshot
must be reconstructable. Missing material returns a retryable
`ParentManifestUnavailable`; current state is never substituted.

## 5. Protected and opaque Bodies

Protected Body payloads are content-addressed and bound to their descriptor,
Space, schema, and encryption/key context. Plaintext never appears in a
Manifest or Contact framing metadata.

A legitimate Body whose World, schema, or key is unavailable remains opaque:

- retained byte-for-byte;
- counted against quotas;
- included in graph and Manifest completeness;
- unavailable to Fabric and World callbacks;
- forwardable to another legitimate participant.

Opaque retention does not grant authority and cannot bypass historical receipt
validation. Becoming interpretable later requires validation through the normal
Replica path.

## 6. Fabric representations

Fabric exposes two Body representation classes:

- atomic Bodies contain canonical application bytes and use Replica's explicit
  concurrent-head policy;
- collaborative Bodies use one Loro document per Body behind the generic Fabric
  interface.

The collaborative algebra includes:

- deterministic single-winner registers and map entries;
- stable-identity ordered lists;
- Unicode-scalar text splices;
- observed-remove, add-wins sets;
- per-peer PN-counters.

One path has one established type. Reusing it as another type is a transaction
error and changes nothing. A multi-operation Fabric batch is atomic.

Fabric convergence is mechanical, not semantic. A World selecting a register
accepts that concurrent values collapse to one deterministic projection. If the
product must preserve concurrent intent, require explicit predecessors,
immutable records, or revision heads built from generic Bodies. Application code
must not infer a different hidden winner after reading the merged primitive.

## 7. World schemas and containment

Every operation identifies its target World, Body, schema, schema version, and
mutation model. Runtime rejects:

- undeclared or inactive schemas;
- writes outside the Session's World;
- cross-World or cross-Space Body references;
- operation/model mismatch;
- incompatible duplicate declarations;
- excessive paths, operations, or bytes;
- reads or writes outside the callback's bounded view.

A World effect contains one non-empty canonical authorization demand. Runtime
does not supply an implicit write grant. Query projections likewise carry an
explicit read demand that Mechanics evaluates before returning data.

The authority-approved `WorldImplementationId` pins the descriptor, policy
table, schemas, and artifact identity that selected the demand. Remote adoption
validates the bound identity without executing the World.

## 8. IssuesWorld data

IssuesWorld is the canonical first-party World, not a privileged lower layer.
Its Catalog has one deterministic Body identity per `(SpaceId, WorldId)` and is
created atomically by `InitializeTracker`. Missing, wrong, or duplicate semantic
Catalog state is corruption; it is never synthesized during open.

Issue content currently uses one Body per issue. Product schema—not Fabric—defines
the meaning of each field. The canonical conflict contract is:

- title and priority may use explicit deterministic scalar winner semantics;
- project movement must keep issue membership and board projection consistent;
- workflow status is represented by predecessor-bound transition records;
  concurrent live heads are a typed conflict until an authorized successor
  resolves them;
- descriptions use collaborative text where interleaving is acceptable;
- assignees and labels use membership sets;
- semantic history uses immutable events, not the Loro oplog.

The merged implementation still represents status as a register and comments as
Issue-Body list/events. That is sufficient for deterministic scalar convergence
and immutable flat comments, but it does not preserve concurrent transition
branches or support addressable replies/reactions/revisions. Before those
features are claimed, comments become first-class Comment Bodies:

```text
Comment
  id, issue, author, created_at, immutable parent_comment?
  revision heads
  actor-keyed reaction memberships
  tombstone/moderation revisions
```

Concurrent comment creation and replies all survive. Comment edits name their
predecessor revision; concurrent edits remain multiple heads until resolved.
Reaction membership is keyed by reaction and ActorId so a repeated reaction is
idempotent and concurrent actors do not overwrite each other.

These product rules must not introduce comment, issue, workflow, or project
types into Mechanics, Fabric, Replica, Runtime, or Comms.

## 9. Scoped authorization data

Mechanics stores effective generic assignments over exact World resources and
capabilities. IssuesWorld stores product role and workflow definitions and
expands them before requesting an authority mutation.

A role-definition edit affects future expansion only. Existing assignments and
outstanding invitations retain their exact revision provenance and expansion.
Changing or deleting a Body projection cannot grant or revoke authority.

Every authorization receipt binds the principal, historical frontier, parent
Manifest, active World implementation, demand, policy witness, intent, complete
operations, and transaction core. Substitution of any bound coordinate or
digest rejects.

## 10. Contact and convergence

Contact is a bounded framing protocol. It transfers signed Mechanics material,
Manifest advertisements/pages, transactions, and protected Body material. A
transfer acknowledgment proves only framing receipt.

An initiator may declare the Body-head commitments it already holds. Holdings
are a canonical strictly increasing unique sequence. Zero entries require the
defined empty digest. The declaration is signed and bounded. The accepter still
advertises the full Manifest and omits only declared heads; the receiver adopts
nothing unless local plus transferred material reconstructs the complete root.

Received bytes remain staged and inert until:

```text
Mechanics validates authority material
  -> Replica validates transactions, receipts, parents, payloads, and quotas
  -> one durable Manifest adoption
  -> one convergence result and Observation publication
```

A false holdings declaration can prevent its claimant from completing a root;
it cannot cause partial or corrupt adoption.

## 11. Projections and caches

Projections are deterministic views of one committed Manifest and authority
frontier. They are not replicated truth.

Every derived cache entry is keyed by the exact Manifest root whose Bodies it
contains. Per-Body reuse across roots additionally requires a reader-issued
version stamp that proves byte-equivalent constituent heads. A zero or unknown
root is not cacheable. A root mismatch rebuilds or advances before serving.

Activity, inbox, boards, graphs, aliases, and policy views must be reconstructable
from canonical Bodies and Mechanics history. Observation frames are doorbells;
after a reset or overrun, clients re-query the projection.

Projection distinguishes valid, absent, unavailable, and corrupt data. It must
not turn an unavailable query into false zero counts or silently coerce malformed
stored values into valid DTOs.

## 12. Local-only state

Device private keys, actor recovery material, custody shares, local petnames,
configuration, route/backoff state, space navigation, and disposable projection
caches are local state. They are not product Bodies and do not gain authority by
being stored beside an Orbit.

Secrets are written with restrictive permissions and atomic replacement. They
must not appear in Debug output, logs, DTO examples, Fabric, Manifests, or Contact
frames except for an explicitly authenticated encrypted custody package.

## 13. Evolution

- Store, wire, schema, and signed formats carry explicit versions and reject
  unknown incompatible input.
- Semantic Rust names do not carry protocol-version suffixes.
- Stored keys, tags, and signed action meanings are never repurposed in place.
- Canonical ordering, exact decoding, bounds, hashes, domains, and winner rules
  are compatibility surface.
- A new product conflict rule is a World-schema decision and requires
  convergence tests under arrival-order permutations and restart.
- Backward compatibility exists only when explicitly specified; there is no
  legacy architecture fallback.

## 14. Known limitations

- Lazy revocation cannot erase plaintext or keys previously copied by a removed
  participant.
- Trusted native World implementations are not sandboxed or remotely attested.
- Ceremony, recovery, custody, and the composed protocol remain security-review
  sensitive despite using established primitives.
- Full reference performance measurement is scheduled/manual; PRs use the smoke
  corpus and structural complexity gates.
