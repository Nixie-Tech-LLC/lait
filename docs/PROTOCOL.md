# Protocol contract

This document defines LAIT's interoperability boundaries: signed bootstrap and
discovery packets, direct Contact, replicated authority and Body objects, and
the local daemon control channel. Rust type names are not wire specifications.

## 1. Identities and trust anchors

- `SpaceId` identifies one cryptographic and replication boundary.
- `ActorId` identifies a member within a Space.
- `DeviceId` identifies an actor device key.
- `StationId` identifies a device's active network endpoint.
- `WorldId` identifies a semantic World.
- `BodyId` is meaningful only with its World and Space.

Display names, petnames, filesystem paths, project keys, network routes, relay
addresses, and Loro peer ids confer no authority.

Space trust is established through signed genesis/Mechanics history. A node
validates authority at the frontier referenced by the received transaction; it
does not substitute current membership.

## 2. Versioning and canonicality

Compatibility is explicit at independent layers:

- store markers and manifests;
- signed packet protocol fields and domains;
- direct-protocol ALPNs;
- Contact frame grammar;
- external JSON DTO/schema versions;
- local daemon handshake versions.

Unknown incompatible versions fail closed. There is no fallback to legacy Space
tickets, legacy stores, old daemon routing, or historical document codecs.

Canonical encodings require exact decoding: no trailing bytes, duplicate map
keys, alternate enum spellings, unsorted set-like sequences, or non-minimal
representations. Identifiers, hashes, signatures, ordering, and bounds must be
reproducible by an independent implementation.

Semantic Rust types remain version-free. Numeric versions belong to encoded
envelopes, constants, domains, schemas, and fixtures.

## 3. Coordinates and admission

`SignedCoordinates` is the bootstrap object. Its payload binds the Space,
approach Station, canonical direct routes, and optionally an admission
capability. Routes are hints authenticated by the signer, not authority to
change the joiner's relay or discovery configuration.

The current Coordinates wire format is version 2. Direct IPv4 and IPv6 routes
are sorted and deduplicated canonically and reject unusable addresses, zero
ports, excess entries, and excess bytes.

Accepting valid Coordinates is the user approval boundary for joining. The
candidate durably records its signed acceptance proof before dialing. Contact
then transports the proof and authority material needed for Mechanics to redeem
the capability. Redemption verifies:

- Space, candidate actor/device, and capability binding;
- issuer authority at issuance;
- validity window and explicit revocation;
- single-use or bounded-reuse policy;
- the exact World assignment evidence and role provenance.

Membership and initial assignments commit atomically. There is no pending-member
approval queue or second approval command.

## 4. Beacon, presence, and gossip

Beacon is signed lossy news. Presence is authenticated directed liveness.
Gossip may disseminate reachability and change hints. None is durable authority
or proof that the sender may author a World mutation.

A freshness tracker accepts only a cryptographically verified Beacon. Replay,
wrong-Space, wrong-sender, expired-lease, malformed-route, and signature
substitution inputs do not update reachability state.

Presence uses distinct probe and acknowledgment messages. A successful exchange
proves the negotiated endpoint controls its key and is reachable at that moment;
Mechanics still determines actor/device standing.

Gossip is an optimization. Correctness cannot require every participant to join
one room, receive every announcement, or be online simultaneously. Direct
Contact plus persistent Neighbor retry state remains sufficient for eventual
exchange among reachable peers.

## 5. Contact handshake

Contact is a bounded direct transcript over the Contact ALPN. The signed Hello
binds at least:

- protocol version;
- Space and Contact id;
- initiator and responder Station identities;
- negotiated transport identity;
- nonce;
- canonical holdings count and digest.

The signed acknowledgment binds the exact Hello and a responder nonce. Both
sides bind the authenticated transport peer to the signed Station identity
before accepting transfer material.

The Contact protocol field is currently version 2. The ALPN and individual
domain strings have their own versioning and must not be inferred from that
field. A clean format break updates the affected bytes and fixtures atomically.

## 6. Holdings declarations and delta transfer

Before the acknowledgment, the initiator may stream its declared interpreted
Body heads as `(BodyKey, transaction commitment)` pairs. The declaration is:

- signed indirectly through the Hello's count and domain-separated digest;
- bounded in entries, bytes, chunks, and deadline;
- strictly increasing in canonical tuple order;
- duplicate-free;
- exactly decodable and exactly re-encodable;
- represented by count zero and the defined empty digest when empty.

Strict ordering/uniqueness and zero-count/empty-digest equivalence are canonical
requirements. The initial protocol-2 implementation signs and bounds holdings
but does not yet reject every alternate semantic encoding; that decoder gap must
be closed before independent interoperability is claimed.

Holdings frames are valid only in the pre-ack initiator-to-accepter window.
Wrong order, contact id, count, digest, bounds, or frame direction aborts the
transcript.

The accepter advertises its complete signed Manifest but may omit transaction
and Body material for declared heads. It stores no authoritative per-peer
holdings state. A false or stale declaration can starve only the claimant: the
receiver refuses the whole advertised root unless locally held plus transferred
material reconstructs it completely. A later truthful Contact can recover.

Opaque heads are not declared as interpreted holdings. This ensures material
that later becomes interpretable passes through validation again.

## 7. Contact transfer grammar

The transfer carries bounded frame families for:

1. ordered Mechanics authority records and their set commitment;
2. a signed Manifest-root offer;
3. requested canonical Manifest pages;
4. requested protected Body chunks and completion commitments;
5. transcript completion, acknowledgment, or typed abort.

Each frame binds its Contact id. Records, sets, pages, chunks, payloads, and the
transcript use distinct domain-separated commitments. Chunk assembly rejects
conflicting duplicates, overlap, gaps, empty illegal chunks, overflow, and a
final commitment mismatch. An abort discards staged transfer material.

`TransferAck` proves framing receipt only. It is not evidence that Mechanics or
Replica accepted the data.

## 8. Convergence and incorporation

Received material remains inert until the receiver performs the complete local
validation chain:

```text
Contact transcript
  -> staged material
  -> Mechanics authority incorporation and receipt
  -> Replica transaction/receipt/parent/payload/quota validation
  -> one atomic Manifest adoption
  -> convergence outcome
```

Remote validation does not invoke World code. It verifies the authority receipt
at the historical frontier and the authority-approved World implementation id
bound into the transaction. Unsupported legitimate Bodies may be retained and
forwarded opaquely.

Manifest adoption is root-atomic. A transfer containing only a prefix of the
advertised root cannot partially advance the visible Replica. Idempotent replay
changes nothing; same identity with different bytes is equivocation.

## 9. Replicated object families

The compatibility surface includes canonical encodings and fixtures for:

- Coordinates and admission evidence;
- Beacon and presence packets;
- Mechanics effects, checkpoints, and batch receipts;
- ceremony material and terminal SpaceAuthority effects;
- World actions and authorization receipts;
- Body transactions and descriptors;
- protected Body payloads;
- Manifest roots and pages;
- store markers/manifests and journal objects;
- external DTO identifiers, projections, observations, and errors.

Every signed family has a distinct purpose/domain. Ceremony material cannot
decode as terminal authority; a framing receipt cannot decode as an
authorization receipt; an authority-batch receipt cannot substitute for World
authorization.

## 10. Local control channel

CLI, web, and MCP clients speak one typed local protocol to the per-Space daemon.
A version handshake precedes requests. The production request classifier assigns
every request exactly one terminal owner; there is no wildcard product fallback.

Product mutations and queries reach IssuesWorld through a docked Session.
Membership, devices, custody, and ceremonies reach Mechanics. Neighbor and
Contact operations reach Station. Lifecycle operations reach Runtime/Orbit/
Station. Clients never open Replica or Fabric directly.

JSON responses are strict versioned DTOs rather than serialized internal
objects. Unknown fields reject where the schema says strict; decoded lengths and
identifier grammars remain enforced after JSON decoding.

`Subscribe` carries Observation doorbells with Station epoch, sequence, reset
semantics, committed frontier, and dirty scopes. Frames may be coalesced. They
are not state deltas; clients re-query after notification or reset.

## 11. Failure and resource behavior

Every protocol has explicit limits for frames, records, pages, chunks, payloads,
holdings, concurrency, and time. A peer cannot request unbounded buffering or
keep an untracked Station task alive indefinitely.

Dormancy rejects new work, terminates Sessions, cancels Contact/gossip, closes
Observations, drains tracked tasks within its deadline, persists required state,
and releases the store lock last.

An unreachable peer, interrupted join, or aborted Contact leaves a recoverable
Orbit and bounded retry state. It does not create membership, expose a partial
Manifest, or mutate guarded relay/discovery policy.

## 12. Conformance

An independent implementation must match:

- identifier grammar and canonical byte representation;
- signed preimages, domains, hashes, and signature verification;
- version and unknown-input rejection;
- bounds and abort classifications;
- Contact state-machine ordering and transcript commitments;
- historical authority evaluation;
- transaction and Manifest graph validation;
- protected/opaque Body behavior;
- deterministic collaborative convergence;
- local DTO schemas, errors, and Observation semantics.

Golden vectors must include positive encodings and negative substitution,
reordering, duplicate, truncation, trailing-byte, wrong-domain, wrong-Space,
wrong-peer, and over-limit cases. Round-tripping through one implementation is
not interoperability proof.
