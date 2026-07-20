# Threat model

This document states the security claims of the current implementation. It is
not an audit report. Novel protocol code remains unaudited.

## Assets

- collaborative issue content and history;
- membership and grant integrity;
- actor continuity across device changes;
- space and actor recovery authority;
- device private keys, recovery keys, and custody shares;
- attribution of signed authority actions;
- availability of enough replicas and recovery holders.

## Trust boundaries

The local process, operating-system account, and readable local secret files are
inside the device trust boundary. Iroh peers, gossip participants, replicated
bytes, relays, display names, clocks, and network paths are untrusted.

Genesis is the space trust anchor. Signed event validity is established by
domain-separated signatures, space binding, ancestry, deterministic replay,
actor-at-position resolution, and standing. Network identity alone does not
grant space authority.

## Adversaries considered

- an unauthenticated network observer or gossip participant;
- a peer sending malformed, replayed, reordered, or conflicting state;
- a former member retaining all data and keys previously received;
- a compromised current device acting with that device's legitimate keys;
- concurrent administrators making conflicting membership or key changes;
- a relay that stores and serves bytes but should not read collaborative data;
- a local unprivileged client attempting to cross space or identity boundaries;
- accidental corruption in durable Loro records or local state.

## Intended properties

- Unauthorized peers cannot decrypt encrypted collaborative payloads without a
  held epoch key.
- Signed authority events cannot be forged without an authorized signing key.
- A device action is attributed to an actor only when the device belonged to
  that actor at the frontier declared by the operation.
- Membership removal fences future content through key rotation.
- Concurrent replicas converge on the same actor, membership, authority, and
  active-epoch results when given the same inputs.
- Captured device-consent blobs cannot be replayed into a different inception or
  used repeatedly to resurrect a revoked device.
- Actor recovery can supersede events from compromised former devices when the
  offline recovery key remains secret.
- Malformed replicated input should be rejected or reported, not panic the
  process or silently become a valid value.
- A node lacking the active content key does not leak locally available
  plaintext as an encryption fallback.

## Explicit non-goals and residual risks

- **No clawback.** Revocation cannot erase plaintext, snapshots, or epoch keys a
  device already copied.
- **Endpoint compromise.** Malware running as the user can read local plaintext
  and usable keys and can act with the device's current authority.
- **Recovery-root compromise.** Possession of an actor or space recovery
  root may permit takeover within the authority that root controls.
- **Traffic analysis.** Encryption does not hide peer addresses, timing, sizes,
  space participation, or all membership metadata.
- **Availability.** Peers can withhold data, disappear, or refuse ceremony
  participation. Cryptography does not guarantee a quorum will be online.
- **Unsigned content attribution.** An actor id stored in ordinary CRDT content
  is an application field, not proof that actor signed the content mutation.
- **Clock truth.** Wall-clock timestamps, activity order, expiry evaluation, and
  presence are advisory and subject to skew.
- **Denial of service.** Bounds reduce amplification and malformed-input risk but
  do not make storage, replay, or network processing immune to resource attacks.
- **Formal verification.** The protocols are tested but not formally verified.

## Key compromise cases

### Device key

A compromised current device can sign as itself and exercise the grants of any
actor it validly represents. Revoke the device and rotate the space content
key. Previously received content remains exposed.

### Actor recovery key

The recovery key can reset the actor's device set. Keep it offline. Loss may make
actor recovery impossible; compromise may allow actor takeover. Co-signed actor
recovery is not part of actor protocol v1.

### Space recovery authority

Space recovery can re-root broader space authority. Threshold and
general-access arrangements reduce dependence on one device but add novel DKG,
resharing, custody, and transition code. Operators must not treat these paths as
independently audited.

## Local web surface

`lait serve` binds only to loopback and uses a per-run bearer token. Listing
spaces must not start every daemon, and attaching to a space must preserve the
selected local identity. Browser-origin and rebinding defenses protect the local
control capability; the browser is not a peer or space member.

## Security maintenance

Security claims must have tests at the boundary that enforces them. Protocol
changes require adversarial cases for malformed encodings, signature replay,
wrong-space substitution, concurrency, recovery precedence, and key absence.

Independent review should cover the actor protocol, ACL replay, epoch healing,
content authority, FROST integration, general-access signing, DKG, resharing,
refresh/repair, handover, custody, and recovery transitions.
