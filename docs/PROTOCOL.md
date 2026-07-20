# Protocol contract

This document defines the compatibility boundary between lait implementations.
It covers network protocols and the local daemon control channel. Internal Rust
types are not themselves the wire specification.

## 1. Identities and trust anchors

- `SpaceId` identifies a space.
- `ActorId` identifies a member within that space.
- `DeviceId` is an ed25519 device key and equals the device's iroh endpoint id.
- Loro peer ids are internal operation-addressing values and are never user
  identities.
- Space tickets carry the genesis trust anchor and founding actor material.

Display names, nicknames, paths, project keys, and peer discovery do not confer
authority.

## 2. Versioning

Compatibility is explicit at several layers:

- schema version gates stored data and DTO projections;
- ALPN suffixes version direct network protocols;
- signed domains version signature purposes;
- serde/postcard shapes version encoded messages;
- the local `Hello` exchange distinguishes compatible daemons.

An implementation must fail closed when it cannot interpret an authority or
storage version. Unknown additive DTO fields may be ignored where the schema
contract permits it; unknown signed action semantics may not.

## 3. Signed domains

Signatures bind, at minimum, their protocol domain and space. Distinct uses
must not share a domain merely because they use the same key type. Current
domains include actor events, device-binding consent, ACL events, content
authority, gossip, invites, ceremonies, and space authority.

Canonical serialization is part of the signed protocol. A second implementation
must reproduce the same bytes, hashes, ids, parent ordering, and tie-breaks.

## 4. Discovery and presence

Peers discover each other through iroh gossip on a space-derived topic.
Signed gossip carries announce/presence data including the space, sender,
and presence state. Neighbor events contribute reachability but are not proof of
membership.

Presence is advisory and three-state at the product layer: online, away, or
offline. It must not be used as an authorization input.

## 5. Direct protocols

The device endpoint accepts versioned ALPNs for:

- a liveness/presence probe;
- catalog-first synchronization;
- invite and join handshakes as implemented by the current epoch.

Direct connection success proves reachability of a device key, not membership or
actor standing. Every authority-bearing payload is independently validated.

## 6. Catalog-first synchronization

A pull begins with plaintext membership material, then encrypted collaborative
state:

1. Exchange membership version information and import missing signed events and
   sealed envelopes.
2. Replay authority and refresh locally held epoch keys.
3. Exchange an encrypted catalog diff.
4. Compare catalog rows and version vectors to identify missing or stale issue
   documents.
5. Exchange encrypted per-document updates or snapshots.

Catalog heads are discovery hints. The issue document remains authoritative for
its fields, and the receiver recomputes catalog caches after import.

Malformed, undecryptable, unauthorized, or wrong-space frames are rejected.
Failure to hold the active epoch key never authorizes a plaintext fallback.

## 7. Encryption envelope

Encrypted collaborative payloads carry the content-addressed key-epoch id and an
AEAD ciphertext. The receiver selects a held epoch key by id and authenticates
the envelope before importing bytes.

Epoch metadata and per-device sealed keys travel in the plaintext membership
layer because they are required to bootstrap decryption. A sealed envelope is
accepted only when its key hashes to the commitment in an authorized epoch
record.

The current implementation provides encrypted peer synchronization. A complete
content-addressed blind-relay history and relay-side compaction protocol remains
future work and is not implied by this envelope.

## 8. Actor and membership carriage

Every authority operation that claims to speak for an actor includes the actor
and an actor-log frontier. Replay verifies that the signing device belonged to
that actor at that frontier.

Actor device consent is separately signed and nonce-bound. Invite authorization
is space-bound, expiring, and optionally single-use. Concurrent single-use
redemptions deterministically admit at most one actor for a nonce.

Names never appear in authority decisions. Petnames are local projections.

## 9. Local control channel

CLI, web, and MCP clients speak a typed request/response protocol to the daemon
over a local IPC channel. The protocol is newline-delimited JSON at the transport
boundary, with a version handshake before normal requests.

The daemon validates a mutation completely before applying it. Responses are
versioned projections, not serialized Loro documents. Errors have typed
classification so clients do not infer behavior from prose.

`Subscribe` is the streaming verb. Its frames contain:

- a per-daemon epoch;
- a per-session sequence number;
- reset/rebaseline indication;
- dirty scopes for affected projections.

Frames are doorbells, not deltas. They may be coalesced, duplicated, or replaced
by a reset without changing correctness because clients re-read state.

## 10. Conformance

A conforming implementation must match:

- identifier parsing and formatting;
- canonical serialization and signed payload construction;
- content hashes and domain separation;
- deterministic DAG replay and all precedence/tie-break rules;
- actor-at-frontier resolution;
- epoch selection and ciphertext framing;
- version rejection behavior;
- local DTO tags, defaults, and error classes advertised as stable;
- corruption reporting required by the data contract.

Interoperability tests and vectors are required before another implementation is
claimed compatible. Round-tripping through the same library is insufficient.
