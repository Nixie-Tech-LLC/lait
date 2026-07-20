# Data contract

This document defines the durable and replicated data invariants of schema v2.
It describes behavior, not the exact Rust API.

## 1. Three convergence regimes

Every replicated value belongs to one regime.

### 1.1 CRDT values

Issue content and catalog structure use Loro containers. Convergence follows the
container's merge rule: LWW register, text sequence, present-key set, immutable
list, movable list, or grow-only map. Application code must not invent a second
conflict rule after merge.

### 1.2 Deterministic projection

Some visible state is derived from replicated inputs: catalog rows, board views,
activity, member lists, active key epochs, and corruption diagnostics. A
projection must be a deterministic function of its inputs and must not silently
discard malformed records.

### 1.3 Signed authority replay

Actor, membership, and content-authority state are computed from grow-only sets
of signed hash-DAG events. Transport convergence only guarantees that replicas
eventually hold the same inputs. Trust comes from deterministic replay against
genesis, signatures, causal ancestry, actor-at-position resolution, and standing.

## 2. Trust tiers

- **T0 collaborative:** ordinary issue content. CRDT semantics decide conflicts;
  attribution stored inside a document is not proof of device authorship.
- **T1 structural:** catalog membership, workflow, ordering, and caches. These
  values affect navigation but do not grant authority.
- **T2 authority-bearing:** actor bindings, membership grants, key epochs,
  deletion/restoration, and recovery transitions. These require signed replay.

Moving a fact from T0/T1 to T2 requires a signed operation and replay rule. A
boolean inside a Loro map cannot become authoritative merely because a client
labels it security-sensitive.

## 3. Issue documents

An issue document owns:

- stable identifiers and creation metadata;
- LWW title, status, priority, and project membership;
- collaborative description text;
- present-key sets of assignee `ActorId`s and label ids;
- immutable comments whose author is an `ActorId`;
- content-authority events relevant to that issue.

The issue document is the source of truth for issue fields. Catalog mirrors are
caches. Assignees and authors are actor identities so they remain stable across
device changes.

Comments whose author cannot be parsed are corrupt records, not comments with a
missing author. Reads return valid projections and corruption sidecars with a
locus, reason, and raw value.

## 4. Catalog document

The catalog owns space display metadata, the grow-only issue registry,
projects, labels, workflow states, and board ordering. `DocMeta` rows mirror
selected issue fields for fast lists and discovery.

Writer direction is one-way:

```text
issue document -> recomputed DocMeta -> catalog
```

Every local issue mutation, imported issue update, and store load recomputes the
row from the issue document. Catalog state never overwrites issue truth.

A board list determines order, not project membership or issue existence. The
issue's `projectId` determines membership; the catalog registry determines
existence. Projection removes duplicates and ignores stale ordering entries.

## 5. Membership document

The membership document is plaintext routing material required before encrypted
content can be opened. It transports:

- actor-plane signed events;
- actor-keyed ACL events;
- content-key epoch metadata and sealed device envelopes;
- ceremony, recovery, custody, and space-authority events.

It does not make those events valid. Kernel replay decides validity. Unknown,
malformed, or unauthorized signed inputs remain inert and auditable.

## 6. Commit boundary

One accepted Layer-B mutation is one logical commit. Validation completes before
the commit is applied. Rejected requests do not mutate a document, append
activity, or ring a dirty notification.

Commit metadata records enough semantic context to derive history without
guessing from final state. Wall-clock timestamps are advisory display data, not
merge authority.

## 7. Import boundary

Import is transactional from the client's perspective:

1. Import plaintext membership and authority inputs.
2. Replay authority and refresh the keyring.
3. Decrypt and import catalog state if the active epoch key is held.
4. Determine which issue documents are missing or stale.
5. Import issue updates.
6. Recompute affected catalog rows and derived local state.
7. Emit one coalesced dirty notification.

A node that cannot decrypt learns no collaborative content from that payload.

## 8. Projection honesty

Projection distinguishes three states:

- **known:** a valid typed value is present;
- **unknown:** absence is legitimate at this point, such as a provisional row;
- **corrupt:** stored data claims to be a value but violates its type.

Unknown must not be replaced by a sentinel. Corrupt must not be defaulted,
silently filtered, or serialized inside a collection typed as valid. DTOs carry
corruption beside healthy data when the surface supports it.

## 9. Persistence

The Git-backed store contains public genesis material, Loro state, signed events,
and sealed envelopes. It is local durability and inspectability, not replication.

Local machine state may include device private keys, offline actor recovery
material, encrypted custody shares, configuration, petnames, inbox state, and a
space registry. These files are outside replicated collaborative truth.

Atomic replacement protects individual durable writes. A Git commit is useful
history but is not a distributed transaction or authorization boundary.

## 10. Evolution

- Schema v2 is a clean actor-identity cutover. Pre-v2 stores reinitialize or
  rejoin; there is no compatibility interpretation that turns a device into an
  actor.
- Container meanings and signed action meanings are append-only within a
  version. Do not repurpose a stored key or enum variant.
- Additive DTO fields require defaults when older senders are supported.
- Signed encodings, domains, hashes, and tie-break rules require explicit
  protocol-version review.
- A migration must preserve the distinction between collaborative values,
  derived projections, and authority-bearing events.

## 11. Known liabilities

- Loro histories and signed event sets grow without a complete compaction story.
- Lazy revocation cannot erase previously copied plaintext or keys.
- Some read sites still default or drop malformed values instead of reporting
  corruption; those are bugs to migrate to the projection policy.
- Novel recovery and general-access protocols remain unaudited.
- Wall-clock activity and inbox ordering are advisory and can disagree between
  peers.
