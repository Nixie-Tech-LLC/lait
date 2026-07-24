# Threat model

This document states the security claims and explicit limits of the current
orbital implementation. It is not an audit report. The composed protocol and
novel ceremony code remain unaudited.

## Assets

- protected World Body contents and semantic history;
- integrity and completeness of the Replica transaction/Manifest graph;
- actor, device, membership, scoped capability, and delegation history;
- authority-approved World implementation identity;
- admission capabilities and role-assignment evidence;
- device private keys, Body keys, recovery secrets, and custody shares;
- attribution of signed authority and Body transactions;
- availability of sufficient replicas, routes, and recovery participants.

## Trust boundaries

The LAIT process, operating-system account, trusted native World code, and
readable local secret files are inside the device trust boundary. Local CLI,
web, and MCP clients receive only the authority of the local control capability
and selected identity; they do not receive storage access.

Remote peers, gossip participants, Contacts, relays, discovery services,
replicated bytes, display names, clocks, routes, and network paths are untrusted.
Reachability or possession of ciphertext does not confer membership.

Signed Mechanics history is the Space authority anchor. Validity depends on
domain-separated signatures, Space binding, canonical encoding, causal history,
actor/device resolution, and authorization at the referenced historical
frontier. Current authority is never substituted for historical authority.

The active `WorldImplementationId` is a trust decision. It binds reviewed
in-process semantic code and its policy table; it is not remote attestation or a
sandbox guarantee.

## Adversaries considered

- an unauthenticated observer, relay, discovery peer, or gossip participant;
- a Contact peer sending malformed, reordered, duplicated, truncated,
  conflicting, oversized, or commitment-substituted frames;
- a peer lying about its holdings or withholding material;
- a peer presenting unauthorized transactions or an incomplete Manifest root;
- a former member retaining everything received before removal;
- a compromised current device acting with its legitimate keys and assignments;
- concurrent administrators, writers, or ceremony participants;
- a local unprivileged client attempting to cross Space, World, Body, Session,
  or identity boundaries;
- corruption or interruption at journal/object/manifest boundaries;
- a buggy or malicious registered World attempting cross-World operations,
  excessive resource use, insufficient demands, or mixed-root projections.

## Intended properties

- A peer lacking the required Body key cannot decrypt a protected Body merely by
  obtaining Replica or Contact material.
- Signed effects and transactions cannot be forged without the corresponding
  authorized signing key.
- Device authorship resolves to an actor only when the device was valid for that
  actor at the operation's referenced frontier.
- Removal and key rotation fence future content, subject to lazy-revocation
  limits.
- Authorization receipts bind principal, historical authority, parent Manifest,
  active World implementation, demand, intent, and complete operations.
- Remote adoption invokes no World callback and cannot replace historical state
  with the receiver's current state.
- Manifest adoption is all-or-nothing; incomplete or corrupted roots do not
  partially advance the visible Replica.
- Unsupported legitimate protected material can be retained and forwarded
  without becoming readable or executable.
- A false Contact holdings declaration can starve only the claimant; complete-root
  validation prevents it from making an incomplete root valid. Strict rejection
  of every noncanonical holdings ordering/duplicate is still an implementation gap.
- Ceremony traffic cannot enlarge ordinary authority frontiers. Ordinary World
  transactions load no FROST shares or transcript state.
- A World cannot write another World, undeclared schema, or Body outside its
  bounded callback view.
- A derived cache cannot serve Bodies from a Manifest other than the exact root
  that keyed the projection.
- Malformed or corrupt input rejects or surfaces as typed corruption rather than
  becoming a valid value or panicking the Station.

## Explicit non-goals and residual risks

- **No clawback.** Removal cannot erase plaintext, snapshots, keys, or exported
  custody material already copied.
- **Endpoint compromise.** Malware running as the user can read local plaintext
  and keys and act with the device's current authority.
- **Trusted World compromise.** An authority-approved native World can select an
  insufficient demand or leak data available to its callback. Implementation-id
  activation is governance, not sandboxing.
- **Recovery compromise.** Possession of sufficient actor or Space recovery
  material may permit takeover within that recovery authority.
- **Traffic analysis.** Encryption does not hide endpoint addresses, timing,
  transfer sizes, Space participation, or all metadata.
- **Availability.** Peers can disappear, withhold data, lie about holdings, or
  refuse ceremony participation. Cryptography cannot guarantee an online quorum.
- **Clock truth.** Expiry uses bounded clock assumptions; display timestamps,
  activity ordering, and presence remain advisory.
- **Denial of service.** Bounds limit amplification but do not eliminate CPU,
  storage, or bandwidth exhaustion by authorized or reachable peers.
- **Native-loop preemption.** Runtime contains World panics but cannot preempt an
  arbitrary infinite loop in trusted native World code.
- **Formal verification.** The protocols are tested and fault-injected, not
  formally verified.

## Key compromise cases

### Device key

A compromised valid device can sign as itself and exercise the historically
effective assignments of its actor. Revoke the device and rotate relevant Body
keys. Previously received content remains exposed.

### Actor recovery material

Actor recovery can replace the valid device set. Keep recovery material offline.
Loss may make recovery impossible; compromise may permit actor takeover.

### Space recovery authority and custody

Space recovery can replace broader recovery authority. Threshold arrangements
reduce dependence on one device but add DKG, resharing, custody, and transition
risk. Public ceremony material is replicated; secret shares and nonces remain
encrypted local state and must never enter Fabric or product Bodies.

## Admission and delegation

Coordinates links may carry bearer admission capability. Anyone possessing a
valid unexpired capability can attempt its allowed redemption, subject to its
candidate binding, use policy, revocation state, and issuer authority. Send it
over an appropriately private channel.

Automatic redemption does not make a candidate authoritative before Mechanics
commits membership and exact expanded assignments. Product role provenance is
opaque to Mechanics; generic assignments and issuer delegation are verified.

## Contact, gossip, and relay exposure

Beacon, presence, and gossip are discovery hints, not authority. Contact binds
signed Station identities to the authenticated transport peer and validates all
authority-bearing material independently.

Holdings declarations reveal Body keys and transaction commitments already held
by the initiator to the contacted peer. They are metadata and may assist traffic
analysis. They do not contain plaintext and are bounded, signed, canonical, and
used only to omit redundant transfer.

A ciphertext-only relay or opaque peer may learn sizes, timing, identifiers,
and graph relationships. LAIT does not claim metadata-private replication.

## Product conflict integrity

CRDT convergence is not authorization and is not automatically a correct
product conflict policy. IssuesWorld must preserve causally meaningful
concurrent intent through transition/revision heads where required. Using an LWW
register is an explicit acceptance of a single deterministic winner.

Comments, replies, reactions, and workflow transitions must bind stable
identities and historical authorization. An actor id inside unsigned application
content is not cryptographic proof of authorship; signed Body transactions and
receipts provide the attribution boundary.

## Local web surface

`lait serve` binds to loopback and uses a per-run bearer capability with origin
and rebinding defenses. Listing local Spaces must not activate all Stations.
Attaching to a Space preserves the selected local identity. The browser is a
local client, not an iroh peer or Space member.

## Security maintenance

Security claims require executable tests at the enforcing boundary. Protocol
changes require malformed encodings, wrong-domain/Space/peer substitution,
historical-authority cases, concurrency permutations, restart/fault points,
resource bounds, and missing-key behavior.

Independent review should prioritize historical authority/checkpoints,
authorization receipt composition, Manifest/journal recovery, protected Body
encryption, admission/delegation, Contact state machines and holdings metadata,
World containment, FROST/DKG/resharing, custody, and recovery transitions.
