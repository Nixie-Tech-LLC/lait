//! The **actor identity plane** — the third signed hash-DAG plane
//! (`lait/actor/1`), beneath membership. Where the ACL ([`crate::acl`])
//! answers *which actors are here* and content authority ([`crate::authz`])
//! answers *which high-consequence actions were taken*, this plane answers
//! *which device keys speak for an actor* — and it is the only plane that is
//! **self-authorized**: an actor adds, revokes, and recovers its own devices;
//! no admin signs a device event.
//!
//! **The split this plane creates.** A `UserId` (ed25519 device key) *signs*;
//! an [`ActorId`] *is someone*. Every op on every plane is still signed by
//! exactly one device (the [`SignedNode`] envelope binds the author key into
//! both signature and content-address — that stays). Authority questions gain
//! one indirection: "is this author an admin" becomes "is the author device a
//! device of the claimed actor *at the declared frontier*, and is that actor
//! an admin at this op's causal position."
//!
//! **Self-certifying identity.** `ActorId = act_ + blake3-hash(Incept event)`.
//! No registry mints it and none can forge it: any replica holding the
//! `Incept` event validates the id by rehashing. The `Incept` payload binds
//! the workspace id + a nonce, so actors are **per-space** — the same human in
//! two workspaces is two unlinkable actors (cross-space linking is a local
//! address-book concern, never protocol state).
//!
//! **Consent bindings.** Every device in an actor's set consented: a
//! [`DeviceBinding`] carries the device's own signature over the binding
//! context (`lait/devbind/1`) plus a fresh per-binding nonce, so no actor can
//! claim a key it does not control and no consent can be replayed.
//! - For an `Incept` the actor id does not exist yet (it *is* the event's
//!   hash), so consent binds the **whole inception core**: `(workspace ‖
//!   binding nonce ‖ incept nonce ‖ sorted device keys ‖ recovery commit)`.
//!   Binding the full core is what stops a device's consent being replayed
//!   into a *different* inception (different device set or recovery commitment)
//!   that reuses the incept nonce.
//! - For `AddDevice`/`Recover` consent binds `(workspace ‖ binding nonce ‖
//!   actor id)`, and replay enforces the nonce is **single-use per actor**, so
//!   an old consent cannot be replayed to re-add a device after its revocation.
//!
//! **Recovery (pre-rotation, KERI-shaped).** An `Incept` may commit to
//! `blake3(recovery pubkey)` — the key itself stays offline. A `Recover`
//! event is *authored by the recovery key* (mechanically just another ed25519
//! key in the envelope), must hash to the standing commitment, wholesale
//! resets the device set, and commits to the next recovery key (or burns
//! recovery with `None`). Because a compromised device never holds the
//! recovery key, only the true owner can produce a valid `Recover`.
//!
//! **Deterministic replay, two passes — the [`crate::acl`] shape.** Pass 1
//! authorizes events at their causal position in deterministic topo order
//! ([`sigdag::topo_order`]). Pass 2 applies the safety overrides:
//! **revoke-wins** (a revoke not causally succeeded by a re-add evicts the
//! device even against a concurrent add — remove-wins, pointed at the same
//! safe side as membership) and **recovery-wins** (device-authored events
//! *concurrent with* a valid `Recover` are struck: the compromised branch
//! cannot race the recovery). Replay is a pure function of the event set —
//! never a current-state gate — so every replica converges (the
//! [`crate::authz`] doctrine, one layer down).
//!
//! **Recovery supremacy.** Recovery-wins is applied *before* revoke-wins by
//! striking every device-authored event (adds *and* revokes) concurrent with a
//! commitment-valid `Recover`, so a struck concurrent revoke can never override
//! a device the recovery reinstated. A `Recover` is "valid" only if commitment-
//! valid — envelope-signed by the recovery key (which *is* the author: there is
//! no separate `recovery_pub` field to mismatch) whose `blake3` equals the
//! standing commitment — so a signature-valid-but-commitment-invalid `Recover`
//! has zero effect and never triggers the strike.
//!
//! **The accepted residual** is the same class the authz plane names: a still-
//! bound device can author ops embedding a pre-revocation frontier until the
//! revocation propagates — bounded by concurrency, remediated by an explicit
//! counter-op. Not a new risk class.
//!
//! **Accepted limitation — recovery-key compromise is unrecoverable takeover.**
//! Two commitment-valid concurrent `Recover`s (only possible if the recovery
//! *private* key leaked) are resolved by the deterministic topo tie-break,
//! which an attacker can grind. This is the identity analogue of losing a root
//! secret: guard the recovery key offline. A co-signed-recovery upgrade
//! (recovery + a surviving device) is future work, not v1.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::ids::{ActorId, UserId, WorkspaceId};
use crate::sigdag::{self, SignedNode};

/// The signing domain for actor key-events (see [`crate::sigdag`]).
pub const ACTOR_DOMAIN: &[u8] = b"lait/actor/1";

/// The signing domain for device-consent bindings (a plain signature, not a
/// DAG node — it rides *inside* an event).
pub const CONSENT_DOMAIN: &[u8] = b"lait/devbind/1";

/// Cap on the `actor_asof` frontier other planes embed when resolving a
/// device→actor binding at position (cf. [`crate::authz::MAX_ASOF`]).
pub const MAX_ACTOR_ASOF: usize = 16;

/// A signed actor key-event — the shared envelope under this plane's domain.
pub type SignedEvent = SignedNode;

/// A device key plus a fresh nonce and the device's own consent signature over
/// the binding context (module docs). The nonce makes each consent single-use
/// (replay tracks consumed `(actor, device, nonce)` triples), so a captured
/// consent cannot re-add a device after revocation; and the nonce is inside the
/// signed preimage so it cannot be swapped on a captured consent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBinding {
    pub device: UserId,
    pub nonce: [u8; 16],
    pub consent: Vec<u8>,
}

/// An actor key-event (this plane's op). Variants are **append-only**
/// (postcard discriminants are positional). Every non-`Incept` event names its
/// actor explicitly — the declared-claim shape that lets replay partition the
/// flat event set into per-actor logs without a reachability crawl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorOp {
    /// Establish an actor. The event's content-address IS the [`ActorId`].
    /// The author device must be among `devices`; the workspace + nonce make
    /// identical device sets yield distinct ids per space and per inception.
    Incept {
        workspace: String,
        nonce: [u8; 16],
        devices: Vec<DeviceBinding>,
        /// `blake3(recovery ed25519 pubkey)` — pre-rotation commitment.
        /// `None` forgoes recovery (e.g. agents).
        recovery_commit: Option<[u8; 32]>,
    },
    /// Bind another device to `actor`. Author must be a current device.
    AddDevice {
        actor: ActorId,
        binding: DeviceBinding,
    },
    /// Unbind a device from `actor`. Author must be a current device (a
    /// device may revoke itself). Revoke-wins over concurrent adds.
    RevokeDevice { actor: ActorId, device: UserId },
    /// Recovery: authored by the **recovery key** (the envelope author), which
    /// must hash to the standing commitment. Wholesale-resets the device set
    /// and rolls the commitment. Recovery-wins over concurrent device events.
    Recover {
        actor: ActorId,
        devices: Vec<DeviceBinding>,
        /// The next pre-rotation commitment; `None` burns recovery.
        next_commit: Option<[u8; 32]>,
    },
}

impl ActorOp {
    /// The actor this event belongs to. `None` for `Incept` (it defines one —
    /// the id is the event's own hash, known only at the envelope layer).
    pub fn actor(&self) -> Option<&ActorId> {
        match self {
            ActorOp::Incept { .. } => None,
            ActorOp::AddDevice { actor, .. }
            | ActorOp::RevokeDevice { actor, .. }
            | ActorOp::Recover { actor, .. } => Some(actor),
        }
    }
    fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode actor op")
    }
}

/// Sign an [`ActorOp`] with the author's ed25519 seed (a device key — or, for
/// `Recover`, the recovery key), given the actor log's current heads as
/// parents. Same envelope bindings as every plane (op ‖ author ‖
/// sorted(parents) ‖ workspace id under the plane domain).
pub fn sign_event(
    seed: &[u8; 32],
    op: &ActorOp,
    parents: Vec<String>,
    workspace_id: &WorkspaceId,
) -> SignedEvent {
    sigdag::sign_node(
        ACTOR_DOMAIN,
        seed,
        op.encode(),
        parents,
        workspace_id.as_str(),
    )
}

/// The context a device's consent signature covers.
pub enum ConsentCtx<'a> {
    /// Consent to appear in an `Incept`: the actor id does not exist yet, so
    /// bind the **whole inception core** — a consent minted for one device set
    /// and recovery commitment cannot be replayed into a different inception,
    /// even when it reuses the incept nonce.
    Incept {
        incept_nonce: &'a [u8; 16],
        /// The inception's device keys (any order — hashed sorted).
        devices: &'a [UserId],
        recovery_commit: &'a Option<[u8; 32]>,
    },
    /// Consent to join an existing actor (`AddDevice` / `Recover`). Freshness
    /// comes from the per-binding nonce, enforced single-use in replay.
    Member { actor: &'a ActorId },
}

fn consent_payload(
    workspace: &str,
    device: &UserId,
    binding_nonce: &[u8; 16],
    ctx: &ConsentCtx,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CONSENT_DOMAIN);
    h.update(workspace.as_bytes());
    h.update(device.as_str().as_bytes());
    h.update(&binding_nonce[..]);
    match ctx {
        ConsentCtx::Incept {
            incept_nonce,
            devices,
            recovery_commit,
        } => {
            h.update(b"incept");
            h.update(&incept_nonce[..]);
            let mut keys: Vec<&str> = devices.iter().map(|d| d.as_str()).collect();
            keys.sort_unstable();
            for k in keys {
                h.update(k.as_bytes());
            }
            match recovery_commit {
                Some(c) => {
                    h.update(b"rc");
                    h.update(&c[..]);
                }
                None => {
                    h.update(b"norc");
                }
            }
        }
        ConsentCtx::Member { actor } => {
            h.update(b"member");
            h.update(actor.as_str().as_bytes());
        }
    }
    *h.finalize().as_bytes()
}

/// Produce a device's consent for a binding (run on the device that owns
/// `device_seed`). `binding_nonce` should be fresh per binding.
pub fn consent_sign(
    device_seed: &[u8; 32],
    workspace: &str,
    binding_nonce: [u8; 16],
    ctx: &ConsentCtx,
) -> DeviceBinding {
    let sk = SigningKey::from_bytes(device_seed);
    let device =
        UserId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()));
    let payload = consent_payload(workspace, &device, &binding_nonce, ctx);
    let sig: Signature = sk.sign(&payload);
    DeviceBinding {
        device,
        nonce: binding_nonce,
        consent: sig.to_bytes().to_vec(),
    }
}

/// Verify a binding's consent signature under `ctx`.
pub fn consent_verify(workspace: &str, binding: &DeviceBinding, ctx: &ConsentCtx) -> bool {
    let Some(pk) = hex_key(binding.device.as_str()) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&binding.consent) else {
        return false;
    };
    let payload = consent_payload(workspace, &binding.device, &binding.nonce, ctx);
    vk.verify(&payload, &sig).is_ok()
}

fn hex_key(s: &str) -> Option<[u8; 32]> {
    // Reject any non-hex byte BEFORE slicing: a `UserId` is a bare validated-
    // nowhere String, so `s` is attacker-controlled UTF-8. Without this guard a
    // 64-*byte* string containing a multibyte char slices inside a char boundary
    // and panics — and because replay is a pure function every replica runs over
    // the synced event set, one poison event would crash the whole workspace.
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The blake3 hash of an ed25519 public key (the pre-rotation commitment
/// shape): `blake3(raw 32 key bytes)`.
pub fn recovery_commitment(recovery_pub: &UserId) -> Option<[u8; 32]> {
    let raw = hex_key(recovery_pub.as_str())?;
    Some(*blake3::hash(&raw).as_bytes())
}

/// Incept a **single-device** actor (the founding/joining shape): the device
/// that owns `device_seed` is the sole initial device. Returns the signed
/// inception event and the [`ActorId`] it establishes (the event's hash). Pass
/// `recovery_commit = Some(recovery_commitment(&recovery_pub))` to enable
/// recovery; `None` forgoes it (agents).
pub fn incept_single(
    device_seed: &[u8; 32],
    workspace: &WorkspaceId,
    nonce: [u8; 16],
    binding_nonce: [u8; 16],
    recovery_commit: Option<[u8; 32]>,
) -> (SignedEvent, ActorId) {
    let sk = SigningKey::from_bytes(device_seed);
    let device =
        UserId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()));
    let keys = [device];
    let binding = consent_sign(
        device_seed,
        workspace.as_str(),
        binding_nonce,
        &ConsentCtx::Incept {
            incept_nonce: &nonce,
            devices: &keys,
            recovery_commit: &recovery_commit,
        },
    );
    let op = ActorOp::Incept {
        workspace: workspace.as_str().to_string(),
        nonce,
        devices: vec![binding],
        recovery_commit,
    };
    let ev = sign_event(device_seed, &op, vec![], workspace);
    let id = ActorId::from_incept_hash(&ev.hash());
    (ev, id)
}

/// The materialized state of one actor after replay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActorState {
    pub devices: BTreeSet<UserId>,
    pub recovery_commit: Option<[u8; 32]>,
    /// Whether recovery has ever fired (renders as a visible identity event).
    pub recovered: bool,
}

/// The materialized actor plane: every validly-incepted actor and its current
/// device set. Pure function of `(workspace id, event set)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActorPlane {
    actors: BTreeMap<ActorId, ActorState>,
}

impl ActorPlane {
    pub fn state(&self, actor: &ActorId) -> Option<&ActorState> {
        self.actors.get(actor)
    }
    pub fn exists(&self, actor: &ActorId) -> bool {
        self.actors.contains_key(actor)
    }
    /// Whether `device` currently speaks for `actor`.
    pub fn is_device_of(&self, actor: &ActorId, device: &UserId) -> bool {
        self.actors
            .get(actor)
            .is_some_and(|s| s.devices.contains(device))
    }
    pub fn devices_of(&self, actor: &ActorId) -> Vec<UserId> {
        self.actors
            .get(actor)
            .map(|s| s.devices.iter().cloned().collect())
            .unwrap_or_default()
    }
    /// The unique live actor a device belongs to — `None` when unbound OR
    /// bound ambiguously (a device that consented into two actors forfeits
    /// attribution; authorization is unaffected because ops declare their
    /// actor explicitly).
    pub fn actor_of_device(&self, device: &UserId) -> Option<&ActorId> {
        let mut found = None;
        for (id, st) in &self.actors {
            if st.devices.contains(device) {
                if found.is_some() {
                    return None;
                }
                found = Some(id);
            }
        }
        found
    }
    pub fn actors(&self) -> impl Iterator<Item = (&ActorId, &ActorState)> {
        self.actors.iter()
    }
}

/// Replay the full event set. See module docs for the two-pass rules.
pub fn replay(workspace_id: &WorkspaceId, events: &[SignedEvent]) -> ActorPlane {
    replay_inner(workspace_id, events, None)
}

/// Replay restricted to the causal past of `frontier` (event hashes): the
/// **at-position** resolution other planes use to validate a device→actor
/// claim against the frontier its author declared (`actor_asof`). Events not
/// in the frontier's ancestor closure are excluded, so two replicas that both
/// hold the frontier resolve identically regardless of what else they hold.
/// An oversized frontier (> [`MAX_ACTOR_ASOF`]) resolves to nothing — a
/// malformed claim never authorizes.
pub fn replay_at(
    workspace_id: &WorkspaceId,
    events: &[SignedEvent],
    frontier: &[String],
) -> ActorPlane {
    if frontier.len() > MAX_ACTOR_ASOF {
        return ActorPlane::default();
    }
    replay_inner(workspace_id, events, Some(frontier))
}

fn replay_inner(
    workspace_id: &WorkspaceId,
    events: &[SignedEvent],
    frontier: Option<&[String]>,
) -> ActorPlane {
    let ws = workspace_id.as_str();

    // Index signature-valid events by hash; undecodable ops stay as opaque DAG
    // nodes (ancestry, no state) — the forward-compat rule shared with acl.rs.
    let mut nodes: HashMap<String, &SignedEvent> = HashMap::new();
    let mut decoded: HashMap<String, Option<ActorOp>> = HashMap::new();
    for ev in events {
        if !ev.verify_sig(ACTOR_DOMAIN, ws) {
            continue;
        }
        let h = ev.hash();
        decoded.insert(h.clone(), postcard::from_bytes(&ev.op).ok());
        nodes.insert(h, ev);
    }

    // At-position restriction: keep only the frontier's ancestor closure
    // (frontier events included). A frontier hash we don't hold contributes
    // nothing — the caller decides whether that means defer or reject.
    if let Some(front) = frontier {
        let ancestors = sigdag::compute_ancestors(&nodes);
        let mut keep: HashSet<String> = HashSet::new();
        for f in front {
            if nodes.contains_key(f) {
                keep.insert(f.clone());
                if let Some(anc) = ancestors.get(f) {
                    keep.extend(anc.iter().cloned());
                }
            }
        }
        nodes.retain(|h, _| keep.contains(h));
        decoded.retain(|h, _| nodes.contains_key(h));
    }

    let ancestors = sigdag::compute_ancestors(&nodes);
    let order = sigdag::topo_order(&nodes);

    // Partition into per-actor logs by declared claim; inceptions define.
    // An Incept is valid only if: workspace matches, the author device is in
    // its device set, and every binding's consent verifies.
    let mut incepts: BTreeMap<ActorId, String> = BTreeMap::new();
    for (h, op) in &decoded {
        if let Some(ActorOp::Incept {
            workspace,
            nonce,
            devices,
            recovery_commit,
        }) = op
        {
            if workspace != ws {
                continue;
            }
            // An Incept must be a DAG root (no parents), so its causal closure
            // is exactly itself and every other op belongs to the unique root
            // Incept in its closure — the op→actor partition is well-defined.
            if !nodes[h].parents.is_empty() {
                continue;
            }
            let author = &nodes[h].author;
            let keys: Vec<UserId> = devices.iter().map(|b| b.device.clone()).collect();
            if !keys.iter().any(|k| k == author) {
                continue;
            }
            let ctx = ConsentCtx::Incept {
                incept_nonce: nonce,
                devices: &keys,
                recovery_commit,
            };
            if !devices.iter().all(|b| consent_verify(ws, b, &ctx)) {
                continue;
            }
            incepts.insert(ActorId::from_incept_hash(h), h.clone());
        }
    }

    // Whether op `h` causally descends from `actor`'s inception (so it belongs
    // to that actor's log). The inception itself trivially "belongs".
    let belongs_to = |h: &str, actor: &ActorId| -> bool {
        match incepts.get(actor) {
            Some(incept_h) => {
                incept_h == h
                    || ancestors
                        .get(h)
                        .map(|a| a.contains(incept_h))
                        .unwrap_or(false)
            }
            None => false,
        }
    };

    // ---- pass 1 (topo): authorize events, tracking device sets + commitments
    // as they evolve. `strikes` is filled by the recovery-wins pre-scan below.
    let valid_recovers = |strikes: &HashSet<String>| -> Vec<(String, ActorId)> {
        // Recover validity is independent of device-event striking (commitment
        // evolution flows only through Incept + prior Recovers), so a single
        // authorization scan over Recover events suffices and is deterministic.
        let mut commits: BTreeMap<ActorId, Option<[u8; 32]>> = BTreeMap::new();
        for (actor, h) in &incepts {
            if let Some(ActorOp::Incept {
                recovery_commit, ..
            }) = &decoded[h]
            {
                commits.insert(actor.clone(), *recovery_commit);
            }
        }
        let mut out = Vec::new();
        for h in &order {
            if strikes.contains(h) {
                continue;
            }
            let Some(ActorOp::Recover {
                actor,
                devices,
                next_commit,
            }) = &decoded[h]
            else {
                continue;
            };
            // The Recover must descend from its actor's inception.
            let Some(incept_h) = incepts.get(actor).cloned() else {
                continue;
            };
            let descends = ancestors
                .get(h)
                .map(|a| a.contains(&incept_h))
                .unwrap_or(false);
            if !descends {
                continue;
            }
            let Some(Some(commit)) = commits.get(actor) else {
                continue; // no (or burned) recovery
            };
            let author = &nodes[h].author;
            if recovery_commitment(author) != Some(*commit) {
                continue;
            }
            let ctx = ConsentCtx::Member { actor };
            if !devices.iter().all(|b| consent_verify(ws, b, &ctx)) {
                continue;
            }
            commits.insert(actor.clone(), *next_commit);
            out.push((h.clone(), actor.clone()));
        }
        out
    };

    // ---- recovery-wins pre-scan: strike device-authored events concurrent
    // with a valid Recover of their actor (the compromised branch cannot race
    // the recovery). Recover events themselves are never struck.
    let recovers = valid_recovers(&HashSet::new());
    let mut strikes: HashSet<String> = HashSet::new();
    for (rh, r_actor) in &recovers {
        for h in &order {
            if h == rh {
                continue;
            }
            let Some(op) = &decoded[h] else { continue };
            let belongs = match op {
                ActorOp::Incept { .. } => incepts.get(r_actor) == Some(h),
                _ => op.actor() == Some(r_actor),
            };
            let is_device_event = !matches!(op, ActorOp::Recover { .. });
            if !belongs || !is_device_event {
                continue;
            }
            if incepts.get(r_actor) == Some(h) {
                continue; // the inception is by construction an ancestor
            }
            let h_before_r = ancestors.get(rh).map(|a| a.contains(h)).unwrap_or(false);
            let r_before_h = ancestors.get(h).map(|a| a.contains(rh)).unwrap_or(false);
            if !h_before_r && !r_before_h {
                strikes.insert(h.clone());
            }
        }
    }

    // ---- pass 1 proper: evolve per-actor state in topo order.
    let mut states: BTreeMap<ActorId, ActorState> = BTreeMap::new();
    // Track authorized add/revoke events per (actor, device) for revoke-wins.
    let mut adds: Vec<(ActorId, UserId, String)> = Vec::new();
    let mut revokes: Vec<(ActorId, UserId, String)> = Vec::new();
    // Single-use consent nonces per actor — a consent may authorize a binding
    // exactly once, so an old consent cannot re-add a device after revocation.
    let mut consumed: BTreeSet<(ActorId, UserId, [u8; 16])> = BTreeSet::new();

    for h in &order {
        if strikes.contains(h) {
            continue;
        }
        let Some(op) = &decoded[h] else { continue };
        match op {
            ActorOp::Incept {
                devices,
                recovery_commit,
                ..
            } => {
                let id = ActorId::from_incept_hash(h);
                if incepts.get(&id) != Some(h) {
                    continue; // failed inception validity above
                }
                let st = ActorState {
                    devices: devices.iter().map(|b| b.device.clone()).collect(),
                    recovery_commit: *recovery_commit,
                    recovered: false,
                };
                for b in devices {
                    consumed.insert((id.clone(), b.device.clone(), b.nonce));
                    adds.push((id.clone(), b.device.clone(), h.clone()));
                }
                states.insert(id, st);
            }
            ActorOp::AddDevice { actor, binding } => {
                if !belongs_to(h, actor) {
                    continue; // not in this actor's log (bridge/cross-actor)
                }
                let author = &nodes[h].author;
                let Some(st) = states.get_mut(actor) else {
                    continue;
                };
                if !st.devices.contains(author) {
                    continue; // author not a current device at position
                }
                let ctx = ConsentCtx::Member { actor };
                if !consent_verify(ws, binding, &ctx) {
                    continue;
                }
                // Freshness: a consent nonce is single-use per actor.
                let token = (actor.clone(), binding.device.clone(), binding.nonce);
                if consumed.contains(&token) {
                    continue;
                }
                consumed.insert(token);
                st.devices.insert(binding.device.clone());
                adds.push((actor.clone(), binding.device.clone(), h.clone()));
            }
            ActorOp::RevokeDevice { actor, device } => {
                if !belongs_to(h, actor) {
                    continue;
                }
                let author = &nodes[h].author;
                let Some(st) = states.get_mut(actor) else {
                    continue;
                };
                if !st.devices.contains(author) {
                    continue;
                }
                st.devices.remove(device);
                revokes.push((actor.clone(), device.clone(), h.clone()));
            }
            ActorOp::Recover {
                actor,
                devices,
                next_commit,
            } => {
                if !recovers.iter().any(|(rh, _)| rh == h) {
                    continue; // failed recovery validity above
                }
                let Some(st) = states.get_mut(actor) else {
                    continue;
                };
                st.devices = devices.iter().map(|b| b.device.clone()).collect();
                st.recovery_commit = *next_commit;
                st.recovered = true;
                for b in devices {
                    consumed.insert((actor.clone(), b.device.clone(), b.nonce));
                    adds.push((actor.clone(), b.device.clone(), h.clone()));
                }
            }
        }
    }

    // ---- pass 2: revoke-wins override. A revoke of (actor, device) not
    // causally succeeded by an authorized re-add evicts the device even if a
    // concurrent add appeared later in topo order. A Recover listing the
    // device counts as a re-add (it is recorded in `adds`).
    for (actor, device, rh) in &revokes {
        let readded = adds.iter().any(|(a, d, ah)| {
            a == actor
                && d == device
                && ancestors
                    .get(ah)
                    .map(|anc| anc.contains(rh))
                    .unwrap_or(false)
        });
        if !readded {
            if let Some(st) = states.get_mut(actor) {
                st.devices.remove(device);
            }
        }
    }

    ActorPlane { actors: states }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::SystemUlidSource;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn device(n: u8) -> UserId {
        let pk = SigningKey::from_bytes(&seed(n)).verifying_key();
        UserId::from_key_string(data_encoding::HEXLOWER.encode(pk.as_bytes()))
    }
    fn ws() -> WorkspaceId {
        WorkspaceId::mint(&SystemUlidSource)
    }

    /// A member-consent binding for seed `s` into `actor`, nonce `bn`.
    fn member_binding(s: u8, bn: u8, actor: &ActorId, w: &WorkspaceId) -> DeviceBinding {
        consent_sign(
            &seed(s),
            w.as_str(),
            [bn; 16],
            &ConsentCtx::Member { actor },
        )
    }

    fn recovery_commit(r: u8) -> [u8; 32] {
        let pk = SigningKey::from_bytes(&seed(r)).verifying_key();
        *blake3::hash(pk.as_bytes()).as_bytes()
    }

    /// Incept a single-device actor for seed `n`; returns (event, id).
    fn incept(n: u8, w: &WorkspaceId, recovery: Option<u8>) -> (SignedEvent, ActorId) {
        let nonce = [n; 16];
        let commit = recovery.map(recovery_commit);
        let keys = vec![device(n)];
        let binding = consent_sign(
            &seed(n),
            w.as_str(),
            [n.wrapping_add(100); 16],
            &ConsentCtx::Incept {
                incept_nonce: &nonce,
                devices: &keys,
                recovery_commit: &commit,
            },
        );
        let op = ActorOp::Incept {
            workspace: w.as_str().to_string(),
            nonce,
            devices: vec![binding],
            recovery_commit: commit,
        };
        let ev = sign_event(&seed(n), &op, vec![], w);
        let id = ActorId::from_incept_hash(&ev.hash());
        (ev, id)
    }

    /// AddDevice `new_seed` (consent nonce `bn`) to `actor`, authored by
    /// `author_seed`.
    fn add_device(
        author_seed: u8,
        new_seed: u8,
        bn: u8,
        actor: &ActorId,
        parents: Vec<String>,
        w: &WorkspaceId,
    ) -> SignedEvent {
        let binding = member_binding(new_seed, bn, actor, w);
        sign_event(
            &seed(author_seed),
            &ActorOp::AddDevice {
                actor: actor.clone(),
                binding,
            },
            parents,
            w,
        )
    }

    #[test]
    fn incept_defines_a_single_device_actor() {
        let w = ws();
        let (ev, id) = incept(1, &w, None);
        let plane = replay(&w, &[ev]);
        assert!(plane.exists(&id));
        assert!(plane.is_device_of(&id, &device(1)));
        assert_eq!(plane.devices_of(&id), vec![device(1)]);
        assert_eq!(plane.actor_of_device(&device(1)), Some(&id));
    }

    #[test]
    fn incept_for_wrong_workspace_or_unconsented_device_is_void() {
        let w = ws();
        let other = WorkspaceId::mint(&SystemUlidSource);
        // Signed for `w` but claims `other` in the payload: void in both.
        let (ev, _) = incept(1, &other, None);
        // Re-sign the SAME op under w's envelope — the payload workspace `other`
        // must still void it.
        let op: ActorOp = postcard::from_bytes(&ev.op).unwrap();
        let ev = sign_event(&seed(1), &op, vec![], &w);
        let plane = replay(&w, &[ev]);
        assert_eq!(plane.actors().count(), 0, "cross-workspace incept is void");

        // Claiming a device without its consent: void.
        let nonce2 = [8u8; 16];
        let keys = vec![device(1), device(2)];
        let mine = consent_sign(
            &seed(1),
            w.as_str(),
            [11u8; 16],
            &ConsentCtx::Incept {
                incept_nonce: &nonce2,
                devices: &keys,
                recovery_commit: &None,
            },
        );
        let forged = DeviceBinding {
            device: device(2),
            nonce: [12u8; 16],
            consent: vec![0u8; 64],
        };
        let op = ActorOp::Incept {
            workspace: w.as_str().to_string(),
            nonce: nonce2,
            devices: vec![mine, forged],
            recovery_commit: None,
        };
        let ev = sign_event(&seed(1), &op, vec![], &w);
        let plane = replay(&w, &[ev]);
        assert_eq!(
            plane.actors().count(),
            0,
            "an incept claiming an unconsenting device is void"
        );
    }

    #[test]
    fn incept_consent_not_replayable_into_a_different_device_set() {
        // Device 2's consent to the {1,2} inception must not verify in an
        // attacker's inception with a different device set, even when it reuses
        // the same inception nonce.
        let w = ws();
        let nonce = [5u8; 16];
        let victim_keys = vec![device(1), device(2)];
        let victim_consent = consent_sign(
            &seed(2),
            w.as_str(),
            [20u8; 16],
            &ConsentCtx::Incept {
                incept_nonce: &nonce,
                devices: &victim_keys,
                recovery_commit: &None,
            },
        );
        // Attacker: same nonce, device set {3,2}, replays victim's binding.
        let attacker_keys = vec![device(3), device(2)];
        let attacker_binding = consent_sign(
            &seed(3),
            w.as_str(),
            [21u8; 16],
            &ConsentCtx::Incept {
                incept_nonce: &nonce,
                devices: &attacker_keys,
                recovery_commit: &None,
            },
        );
        let op = ActorOp::Incept {
            workspace: w.as_str().to_string(),
            nonce,
            devices: vec![attacker_binding, victim_consent],
            recovery_commit: None,
        };
        let ev = sign_event(&seed(3), &op, vec![], &w);
        let plane = replay(&w, &[ev]);
        assert_eq!(
            plane.actors().count(),
            0,
            "a consent bound to the {{1,2}} core must not verify in a {{3,2}} inception"
        );
    }

    #[test]
    fn malformed_device_key_does_not_panic() {
        // Regression: a 64-*byte* non-ASCII device string (3-byte '€' + 61 ASCII)
        // must not slice inside a char boundary and panic — a poison event would
        // otherwise crash every replica's replay permanently.
        let w = ws();
        let poison = DeviceBinding {
            device: UserId::from_key_string(format!("\u{20AC}{}", "a".repeat(61))),
            nonce: [1u8; 16],
            consent: vec![0u8; 64],
        };
        assert_eq!(poison.device.as_str().len(), 64);
        let nonce = [3u8; 16];
        let keys = vec![device(1), poison.device.clone()];
        let mine = consent_sign(
            &seed(1),
            w.as_str(),
            [2u8; 16],
            &ConsentCtx::Incept {
                incept_nonce: &nonce,
                devices: &keys,
                recovery_commit: &None,
            },
        );
        let op = ActorOp::Incept {
            workspace: w.as_str().to_string(),
            nonce,
            devices: vec![mine, poison],
            recovery_commit: None,
        };
        let ev = sign_event(&seed(1), &op, vec![], &w);
        // Must not panic; the poison binding fails hex parse → consent → void.
        let plane = replay(&w, &[ev]);
        assert_eq!(plane.actors().count(), 0);
    }

    #[test]
    fn incept_with_parents_is_void() {
        // An Incept must be a DAG root, so every op has a unique inception in
        // its causal closure (a well-defined op→actor partition).
        let w = ws();
        let (root, _) = incept(1, &w, None);
        let nonce = [7u8; 16];
        let keys = vec![device(2)];
        let binding = consent_sign(
            &seed(2),
            w.as_str(),
            [30u8; 16],
            &ConsentCtx::Incept {
                incept_nonce: &nonce,
                devices: &keys,
                recovery_commit: &None,
            },
        );
        let op = ActorOp::Incept {
            workspace: w.as_str().to_string(),
            nonce,
            devices: vec![binding],
            recovery_commit: None,
        };
        let parented = sign_event(&seed(2), &op, vec![root.hash()], &w);
        let plane = replay(&w, &[root, parented]);
        assert_eq!(plane.actors().count(), 1, "a parented incept is void");
    }

    #[test]
    fn add_and_revoke_at_position() {
        let w = ws();
        let (ev0, id) = incept(1, &w, None);
        let ev1 = add_device(1, 2, 2, &id, vec![ev0.hash()], &w);
        let plane = replay(&w, &[ev0.clone(), ev1.clone()]);
        assert!(plane.is_device_of(&id, &device(2)));

        // A stranger (never a device) cannot add devices.
        let forged = add_device(9, 3, 3, &id, vec![ev1.hash()], &w);
        let plane = replay(&w, &[ev0.clone(), ev1.clone(), forged]);
        assert!(!plane.is_device_of(&id, &device(3)));

        // Device 2 revokes device 1 (any current device may revoke).
        let rev = sign_event(
            &seed(2),
            &ActorOp::RevokeDevice {
                actor: id.clone(),
                device: device(1),
            },
            vec![ev1.hash()],
            &w,
        );
        let plane = replay(&w, &[ev0, ev1, rev]);
        assert!(!plane.is_device_of(&id, &device(1)));
        assert!(plane.is_device_of(&id, &device(2)));
    }

    #[test]
    fn revoke_wins_over_a_concurrent_add() {
        let w = ws();
        let (ev0, id) = incept(1, &w, None);
        let add2 = add_device(1, 2, 2, &id, vec![ev0.hash()], &w);
        // add3a (parent add2), revoke3 (parent add3a), then a CONCURRENT re-add
        // of d3 (parent add2, not seeing the revoke) — distinct consent nonces.
        let add3a = add_device(1, 3, 30, &id, vec![add2.hash()], &w);
        let rev3 = sign_event(
            &seed(2),
            &ActorOp::RevokeDevice {
                actor: id.clone(),
                device: device(3),
            },
            vec![add3a.hash()],
            &w,
        );
        let add3b = add_device(1, 3, 31, &id, vec![add2.hash()], &w);
        let plane = replay(&w, &[ev0, add2, add3a, rev3, add3b]);
        assert!(
            !plane.is_device_of(&id, &device(3)),
            "revoke-wins: a concurrent add must not resurrect the device"
        );
    }

    #[test]
    fn readd_causally_after_revoke_restores() {
        let w = ws();
        let (ev0, id) = incept(1, &w, None);
        let add2 = add_device(1, 2, 2, &id, vec![ev0.hash()], &w);
        let rev2 = sign_event(
            &seed(1),
            &ActorOp::RevokeDevice {
                actor: id.clone(),
                device: device(2),
            },
            vec![add2.hash()],
            &w,
        );
        // Re-add with a FRESH consent nonce (single-use freshness).
        let readd = add_device(1, 2, 99, &id, vec![rev2.hash()], &w);
        let plane = replay(&w, &[ev0, add2, rev2, readd]);
        assert!(
            plane.is_device_of(&id, &device(2)),
            "a re-add with fresh consent that causally saw the revoke restores"
        );
    }

    #[test]
    fn stale_consent_cannot_readd_a_revoked_device() {
        // Freshness regression: an old consent (nonce reused) cannot re-add a
        // device after its revocation.
        let w = ws();
        let (ev0, id) = incept(1, &w, None);
        let add2 = add_device(1, 2, 2, &id, vec![ev0.hash()], &w);
        let rev2 = sign_event(
            &seed(1),
            &ActorOp::RevokeDevice {
                actor: id.clone(),
                device: device(2),
            },
            vec![add2.hash()],
            &w,
        );
        // A compromised in-set device replays device 2's ORIGINAL binding
        // (same nonce 2) parented after the revoke.
        let replayed_binding = member_binding(2, 2, &id, &w);
        let stale_readd = sign_event(
            &seed(1),
            &ActorOp::AddDevice {
                actor: id.clone(),
                binding: replayed_binding,
            },
            vec![rev2.hash()],
            &w,
        );
        let plane = replay(&w, &[ev0, add2, rev2, stale_readd]);
        assert!(
            !plane.is_device_of(&id, &device(2)),
            "a single-use consent nonce cannot re-add a revoked device"
        );
    }

    #[test]
    fn recover_resets_devices_and_requires_the_committed_key() {
        let w = ws();
        let (ev0, id) = incept(1, &w, Some(9));
        let add2 = add_device(1, 2, 2, &id, vec![ev0.hash()], &w);

        // A forged recover by a random key: void.
        let forged_binding = member_binding(5, 50, &id, &w);
        let forged = sign_event(
            &seed(5),
            &ActorOp::Recover {
                actor: id.clone(),
                devices: vec![forged_binding],
                next_commit: None,
            },
            vec![add2.hash()],
            &w,
        );
        let plane = replay(&w, &[ev0.clone(), add2.clone(), forged]);
        assert!(
            plane.is_device_of(&id, &device(1)) && plane.is_device_of(&id, &device(2)),
            "a recover not matching the commitment must be void"
        );

        // The real recovery key resets the set to a fresh device (seed 4).
        let fresh = member_binding(4, 40, &id, &w);
        let recover = sign_event(
            &seed(9),
            &ActorOp::Recover {
                actor: id.clone(),
                devices: vec![fresh],
                next_commit: None,
            },
            vec![add2.hash()],
            &w,
        );
        let plane = replay(&w, &[ev0, add2, recover]);
        assert!(!plane.is_device_of(&id, &device(1)));
        assert!(!plane.is_device_of(&id, &device(2)));
        assert!(plane.is_device_of(&id, &device(4)));
        assert!(plane.state(&id).unwrap().recovered);
        assert_eq!(
            plane.state(&id).unwrap().recovery_commit,
            None,
            "recovery burned"
        );
    }

    #[test]
    fn recovery_wins_over_concurrent_device_events() {
        let w = ws();
        let (ev0, id) = incept(1, &w, Some(9));
        // Compromised device 1 adds attacker device 6, and CONCURRENTLY revokes
        // the fresh device — both concurrent with the recovery (branch from I).
        let attacker_add = add_device(1, 6, 60, &id, vec![ev0.hash()], &w);
        let concurrent_revoke = sign_event(
            &seed(1),
            &ActorOp::RevokeDevice {
                actor: id.clone(),
                device: device(4),
            },
            vec![ev0.hash()],
            &w,
        );
        let fresh = member_binding(4, 40, &id, &w);
        let recover = sign_event(
            &seed(9),
            &ActorOp::Recover {
                actor: id.clone(),
                devices: vec![fresh],
                next_commit: None,
            },
            vec![ev0.hash()],
            &w,
        );
        // Order of arrival must not matter.
        let p1 = replay(
            &w,
            &[
                ev0.clone(),
                attacker_add.clone(),
                concurrent_revoke.clone(),
                recover.clone(),
            ],
        );
        let p2 = replay(&w, &[recover, concurrent_revoke, attacker_add, ev0]);
        for plane in [&p1, &p2] {
            assert!(
                !plane.is_device_of(&id, &device(6)),
                "an add concurrent with recovery must be struck"
            );
            assert!(!plane.is_device_of(&id, &device(1)));
            assert!(
                plane.is_device_of(&id, &device(4)),
                "recovery-supremacy: a concurrent revoke cannot strip the reinstated device"
            );
        }
        assert_eq!(p1, p2, "replay must be order-independent");
    }

    #[test]
    fn post_recovery_compromised_device_is_powerless() {
        let w = ws();
        let (ev0, id) = incept(1, &w, Some(9));
        let fresh = member_binding(4, 40, &id, &w);
        let recover = sign_event(
            &seed(9),
            &ActorOp::Recover {
                actor: id.clone(),
                devices: vec![fresh],
                next_commit: None,
            },
            vec![ev0.hash()],
            &w,
        );
        // Device 1, causally AFTER the recovery, tries to re-add itself.
        let sneak = add_device(1, 1, 10, &id, vec![recover.hash()], &w);
        let plane = replay(&w, &[ev0, recover, sneak]);
        assert!(
            !plane.is_device_of(&id, &device(1)),
            "a recovered-away device holds no standing afterwards"
        );
    }

    #[test]
    fn replay_at_frontier_excludes_later_events() {
        let w = ws();
        let (ev0, id) = incept(1, &w, None);
        let add2 = add_device(1, 2, 2, &id, vec![ev0.hash()], &w);
        let all = [ev0.clone(), add2.clone()];
        // At the inception frontier, device 2 is not yet bound.
        let at0 = replay_at(&w, &all, &[ev0.hash()]);
        assert!(at0.is_device_of(&id, &device(1)));
        assert!(!at0.is_device_of(&id, &device(2)));
        // At the add frontier, it is.
        let at1 = replay_at(&w, &all, &[add2.hash()]);
        assert!(at1.is_device_of(&id, &device(2)));
        // An unknown frontier hash contributes nothing.
        let missing = replay_at(&w, &all, &["deadbeef".into()]);
        assert!(!missing.exists(&id));
        // An oversized frontier authorizes nothing.
        let oversized: Vec<String> = (0..=MAX_ACTOR_ASOF).map(|i| format!("{i:064x}")).collect();
        assert!(!replay_at(&w, &all, &oversized).exists(&id));
    }

    #[test]
    fn two_actors_one_device_forfeits_attribution_not_authorization() {
        let w = ws();
        let (ev_a, id_a) = incept(1, &w, None);
        let (ev_b, id_b) = incept(2, &w, None);
        // Device 3 consents into BOTH actors (self-inflicted).
        let add_to_a = add_device(1, 3, 30, &id_a, vec![ev_a.hash()], &w);
        let add_to_b = add_device(2, 3, 31, &id_b, vec![ev_b.hash()], &w);
        let plane = replay(&w, &[ev_a, ev_b, add_to_a, add_to_b]);
        assert!(plane.is_device_of(&id_a, &device(3)));
        assert!(plane.is_device_of(&id_b, &device(3)));
        assert_eq!(
            plane.actor_of_device(&device(3)),
            None,
            "ambiguous binding forfeits attribution"
        );
    }
}
