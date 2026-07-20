# Architecture

This document describes the current implementation boundaries of lait. Product
behavior starts in [`README.md`](./README.md) and [`UI.md`](./UI.md). Storage and
wire invariants are defined by the data and protocol contracts.

## System shape

lait is a local-first issue tracker. Every participating device keeps a local
replica; peers exchange signed authority state and encrypted collaborative state
over iroh. Git is a local durability and inspection mechanism, never the sync
transport or a shared source of truth.

```text
CLI ───────┐
Web ───────┼─ local control protocol ─ daemon ─ iroh ─ peer daemon
MCP ───────┘                          │
                                      ├─ Loro documents
                                      ├─ signed authority planes
                                      └─ local Git-backed store
```

The daemon is the only process that owns live documents. Clients send typed
intents and receive versioned projections. A streaming subscription carries
dirty notifications, not state; clients re-read the affected projection.

## Crate boundaries

- `lait-kernel` contains pure identifiers, signatures, deterministic replay,
  actor identity, membership, content authority, policy compilation, recovery,
  custody, and cryptographic protocol logic. It does not own Loro documents or
  network connections.
- `lait-fabric` owns Loro containers, storage, history projection, and the
  plaintext membership document that transports signed kernel events and sealed
  key material.
- the application crate owns commands, the daemon, iroh transport, sync,
  configuration, local secrets, projections, and product surfaces.

This boundary is intentional. The kernel determines **legitimacy** — identity,
authority, custody, recovery, and which transitions are valid given signed
history. The fabric maintains the **shared world** — documents, persistence,
history, convergence, projection. They are separate crates because the
dependency edge is a correctness boundary: convergence cannot confer legitimacy.
Authority is a pure function of signed inputs; replication and persistence move
those inputs but do not decide whether they are trusted. The two ship, test, and
version together as lait's substrate.

## Identity

A device has an ed25519 key represented by `DeviceId`. A person or agent is an
`ActorId`, derived from the hash of an inception event. Actors are scoped to a
space and therefore do not provide a global cross-space identifier.

The actor plane is a signed, self-authorized hash DAG:

- `Incept` establishes the actor and its initial device set.
- `AddDevice` binds a consenting device.
- `RevokeDevice` removes a device; revocation wins over concurrent addition.
- `Recover` uses a precommitted offline recovery key to reset the device set;
  recovery supersedes concurrent device-authored events.

Other authority planes resolve a signing device to its claimed actor at the
actor-log frontier embedded in the signed operation. Current device membership
is never substituted for this at-position check.

## Authority planes

Lait has three distinct signed planes:

1. The actor plane determines which device keys may speak for an actor.
2. The membership plane determines which actors belong to the space and which
   grants they hold. `Admin` controls membership; `Write` controls content
   mutation; an empty grant set is view-only.
3. The content-authority plane carries authority-bearing content operations,
   such as deletion and restoration, that must not be accepted as ordinary
   unsigned CRDT values.

Each plane is a grow-only set of signed, content-addressed events. Replicas
converge by deterministic replay from the space genesis, rejecting invalid
signatures, invalid ancestry, unresolved actor claims, and unauthorized actions.
Loro transports the event sets but does not adjudicate them.

## Collaborative data

Issues and the catalog are Loro documents. Their merge rules are chosen per
field: LWW registers, text CRDTs, present-key sets, immutable list entries, and
movable-list ordering. The issue document is authoritative for issue content;
catalog rows are replicated caches recomputed from it after local edits, imports,
and load.

Malformed stored records are not laundered into valid DTOs or silently dropped.
Projection separates valid values from `CorruptRecord` diagnostics. This policy
currently covers comment projection and must be extended to the remaining read
sites listed in the roadmap.

## Encryption and key epochs

Collaborative payloads are encrypted with a space content key. Key epochs
are signed, content-addressed records; concurrent rotations coexist and the
active tip is selected deterministically. Ciphertext identifies its epoch so
older held keys remain usable.

Epoch keys are sealed to the device keys of current member actors. A key-holding
peer can heal missing envelopes for current devices, allowing newly added or
recovered devices to obtain access on later sync. Removing a member rotates the
content key to fence future content.

Revocation is lazy. A removed or compromised device may retain content and keys
it already possessed. Lait cannot claw back copied plaintext or old epoch keys.

If an active epoch exists but a node lacks its key, the node must not emit
locally available plaintext as a fallback. It serves no collaborative payload
until it can encrypt under the active epoch.

## Networking

Each device's iroh endpoint key is its `DeviceId`. Space identity comes
from a `SpaceId` and genesis, not a display name. Tickets carry the space
anchor, founder actor information, and optional invite authorization.

Signed gossip announces presence and changed heads. Direct QUIC protocols probe
liveness and perform catalog-first synchronization. Membership state is imported
before encrypted catalog and issue state so a newly authorized node can obtain
the keys required to decrypt later frames.

The exact compatibility contract is in [`PROTOCOL.md`](./PROTOCOL.md).

## Persistence and local state

Each space has a store containing genesis, Loro snapshots, signed authority
events, and sealed envelopes. Device secrets, actor recovery material, custody
shares, petnames, configuration, the inbox, and space navigation are local
machine state and are not synchronized as collaborative data.

Secrets do touch local disk. The security boundary is that plaintext secrets are
not committed to the synced Git repository or sent to an unauthorized peer.

## Security posture

The implementation uses established primitives but contains novel protocol and
composition work. Actor replay, group access, DKG, resharing, recovery, and
custody must be treated as unaudited until independent review says otherwise.
The supported claims and explicit non-goals are in
[`THREAT-MODEL.md`](./THREAT-MODEL.md).

## Evolution rules

- Stored and wire formats are versioned; incompatible readers fail closed.
- Signed domains and canonical encodings are protocol surface.
- Authority checks are deterministic and position-aware.
- New DTO fields are additive and defaultable where old clients must survive.
- Historical designs belong in local notes or the changelog, not this document.
- Exact APIs belong in source and rustdoc; this document owns boundaries and
  invariants.
