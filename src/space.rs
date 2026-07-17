//! `lait/space/1` — the **self-certifying workspace** and its **root lifecycle**.
//!
//! Membership made *identity* self-certifying (`ActorId = H(inception)`); this
//! does the same for the **workspace** one layer up, and then gives its trust
//! root a **break-glass recovery** path (W5).
//!
//! # Self-certifying id
//!
//! ```text
//! workspace_id = ws_<crockford128( blake3("lait/space/1" ‖ device ‖ salt ‖ recovery_root) )>
//! ```
//!
//! The founding device key + a random salt + the recovery commitment are hashed
//! into the id *before* the founding actor is incepted (an inception is scoped to
//! a workspace id, so the id cannot depend on it). The signed inception is then
//! the "Found" artifact: `ws_id` commits to the device, the inception commits to
//! `ws_id`, and `founder_actor = H(inception)`. A joiner given
//! `{ws_id, salt, recovery_root, founder_inception}` verifies the chain offline.
//!
//! # Root lifecycle (W5)
//!
//! `genesis.founding_actors` is only the *bootstrap* root: it seeds `acl::replay`.
//! Ordinary governance (add/remove admins) already rides the ACL. What the ACL
//! cannot do is re-root when the live admin set is **lost or compromised** — that
//! is the break-glass [`Recover`](SpaceOp::Recover), authorized not by any current
//! admin but by proving a **threshold K-of-N** of the pre-committed recovery keys.
//!
//! `recovery_root = H("…/recovery" ‖ K ‖ sorted[H(recovery_pubkey_i)])` is fixed in
//! the id at birth, so it is unforgeable. It is rotatable **only** by a `Recover`
//! (never by a current admin), so a compromised root cannot lock out recovery. A
//! `Recover` **replaces** the acl seed with `new_root` (a clean-slate re-root; the
//! recovered admin re-adds the legit team and re-keys, fencing the old root), and
//! its `gen` is strictly monotone so an old recovery cannot be replayed.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::actor::{self, SignedEvent};
use crate::ids::{ActorId, UserId, WorkspaceId};
use crate::sigdag::{self, SignedNode};
use crate::store::Genesis;

/// Domain separator for the workspace-id derivation.
const SPACE_DOMAIN: &[u8] = b"lait/space/1";
/// Domain separator for the recovery-set commitment.
const RECOVERY_DOMAIN: &[u8] = b"lait/space/1/recovery";
/// Signing domain for the space-event plane (recovery).
pub const SPACE_EVENT_DOMAIN: &[u8] = b"lait/space/1/event";

/// A signed space-plane event — the shared hash-DAG envelope under this domain.
pub type SignedSpaceEvent = SignedNode;

/// The set of break-glass recovery keys and the threshold needed to recover.
/// `key_hashes` are `blake3(recovery_pubkey)` (never the keys themselves). The
/// workspace commits to `root()` at birth; a `Recover` reveals this preimage so a
/// replica can check it against the committed root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySet {
    pub threshold: u32,
    pub key_hashes: Vec<[u8; 32]>,
}

impl RecoverySet {
    /// The commitment folded into the workspace id — canonical over a sorted key
    /// set, so the same set always yields the same root regardless of order.
    pub fn root(&self) -> [u8; 32] {
        let mut sorted = self.key_hashes.clone();
        sorted.sort_unstable();
        let mut h = blake3::Hasher::new();
        h.update(RECOVERY_DOMAIN);
        h.update(&self.threshold.to_le_bytes());
        for kh in &sorted {
            h.update(kh);
        }
        *h.finalize().as_bytes()
    }
    /// Whether the set is well-formed: `1 ≤ threshold ≤ N`, no duplicate keys.
    fn well_formed(&self) -> bool {
        let distinct: BTreeSet<[u8; 32]> = self.key_hashes.iter().copied().collect();
        distinct.len() == self.key_hashes.len()
            && self.threshold >= 1
            && (self.threshold as usize) <= self.key_hashes.len()
    }
}

/// The `blake3` commitment to a single recovery public key.
pub fn recovery_key_hash(recovery_pub: &UserId) -> Option<[u8; 32]> {
    let raw = hex32(recovery_pub.as_str())?;
    Some(*blake3::hash(&raw).as_bytes())
}

/// The recovery public key (device id) a seed produces.
pub fn recovery_pub_of(seed: &[u8; 32]) -> UserId {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    UserId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()))
}

/// Mint a fresh `k`-of-`n` recovery set: the public [`RecoverySet`] (commit it in
/// the id) and the `n` secret seeds (store each offline with a distinct holder).
pub fn mint_recovery_set(n: usize, k: u32) -> (RecoverySet, Vec<[u8; 32]>) {
    let secrets: Vec<[u8; 32]> = (0..n)
        .map(|_| {
            let mut s = [0u8; 32];
            getrandom::fill(&mut s).expect("getrandom");
            s
        })
        .collect();
    let key_hashes = secrets
        .iter()
        .map(|s| recovery_key_hash(&recovery_pub_of(s)).expect("valid recovery pubkey"))
        .collect();
    (
        RecoverySet {
            threshold: k,
            key_hashes,
        },
        secrets,
    )
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let v = data_encoding::HEXLOWER_PERMISSIVE
        .decode(s.as_bytes())
        .ok()?;
    v.as_slice().try_into().ok()
}

/// A workspace-plane op. Only [`Recover`](SpaceOp::Recover) exists in v1: planned
/// root governance rides the ACL; the space plane is the break-glass path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaceOp {
    /// Re-root the workspace under threshold authority. Each of `set.threshold`
    /// distinct recovery keys signs an **identical** `Recover` payload; replay
    /// counts distinct committed signers and applies once the threshold is met.
    Recover {
        /// The new bootstrap root that will seed `acl::replay` (non-empty).
        new_root: Vec<ActorId>,
        /// Preimage of the recovery commitment being satisfied (must hash to the
        /// current `recovery_root`).
        set: RecoverySet,
        /// The recovery commitment installed for the *next* recovery. May rotate
        /// the break-glass keys, but v1's driver keeps it equal to the current
        /// commitment (rotating the set in a distributed K-of-N needs custody
        /// coordination — a deliberate follow-up); `gen` alone fences replay.
        next_recovery_root: [u8; 32],
        /// Strictly `current_gen + 1` — monotone, so an old recovery can't replay.
        gen: u32,
    },
}

impl SpaceOp {
    fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode space op")
    }
}

/// Sign a [`SpaceOp`] with a recovery key's seed (its author is the recovery
/// public key). Each threshold signer calls this over the identical op.
pub fn sign_op(
    recovery_seed: &[u8; 32],
    op: &SpaceOp,
    parents: Vec<String>,
    workspace_id: &WorkspaceId,
) -> SignedSpaceEvent {
    sigdag::sign_node(
        SPACE_EVENT_DOMAIN,
        recovery_seed,
        op.encode(),
        parents,
        workspace_id.as_str(),
    )
}

/// The materialized root after replaying the space plane over genesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootState {
    /// The effective bootstrap root — what seeds `acl::replay`.
    pub root: Vec<ActorId>,
    /// The current recovery commitment (rotated by each applied `Recover`).
    pub recovery_root: [u8; 32],
    /// Generation of the last applied recovery (0 at birth).
    pub gen: u32,
    /// Whether any recovery has been applied.
    pub recovered: bool,
}

/// Derive the self-certifying workspace id from the founding device, salt, and
/// recovery commitment. Pure and deterministic.
pub fn derive_workspace_id(
    founding_device: &UserId,
    salt: &[u8; 16],
    recovery_root: &[u8; 32],
) -> WorkspaceId {
    let mut h = blake3::Hasher::new();
    h.update(SPACE_DOMAIN);
    h.update(founding_device.as_str().as_bytes());
    h.update(salt);
    h.update(recovery_root);
    let digest = h.finalize();
    let mut d16 = [0u8; 16];
    d16.copy_from_slice(&digest.as_bytes()[..16]);
    WorkspaceId::from_digest(d16)
}

/// Verify a workspace's founding commitment and return the **verified** founding
/// actor to root genesis on. Checks, all offline:
/// 1. `ws_id` commits to the inception's signing device + `salt` + `recovery_root`;
/// 2. the inception is a valid, `ws_id`-scoped founding key-event.
pub fn verify_founding(
    ws_id: &WorkspaceId,
    salt: &[u8; 16],
    recovery_root: &[u8; 32],
    founder_inception: &SignedEvent,
) -> Result<ActorId> {
    if derive_workspace_id(&founder_inception.author, salt, recovery_root) != *ws_id {
        bail!("workspace id does not commit to this founder — ticket is forged or corrupt");
    }
    let founder_actor = ActorId::from_incept_hash(&founder_inception.hash());
    let plane = actor::replay(ws_id, std::slice::from_ref(founder_inception));
    if !plane.exists(&founder_actor) {
        bail!("founding inception is not valid for this workspace");
    }
    Ok(founder_actor)
}

/// Replay the space plane over genesis to the current root. Seeds from
/// `genesis.founding_actors` / `genesis.recovery_root`, then applies each
/// threshold-satisfied `Recover` in generation order. Deterministic and
/// convergent: same events → same `RootState` on every replica.
pub fn replay(genesis: &Genesis, ws_id: &WorkspaceId, events: &[SignedSpaceEvent]) -> RootState {
    let mut state = RootState {
        root: genesis.founding_actors.clone(),
        recovery_root: genesis.recovery_root,
        gen: 0,
        recovered: false,
    };

    // Gather valid Recover events: signature checks, the signer is a committed key
    // of the set it presents, and the set is well-formed. Group identical payloads
    // and tally the distinct committed signers behind each.
    let mut tally: BTreeMap<Vec<u8>, (SpaceOp, BTreeSet<[u8; 32]>)> = BTreeMap::new();
    for ev in events {
        if !ev.verify_sig(SPACE_EVENT_DOMAIN, ws_id.as_str()) {
            continue;
        }
        let Ok(op) = postcard::from_bytes::<SpaceOp>(&ev.op) else {
            continue;
        };
        let SpaceOp::Recover { set, new_root, .. } = &op;
        if !set.well_formed() || new_root.is_empty() {
            continue;
        }
        let Some(signer) = recovery_key_hash(&ev.author) else {
            continue;
        };
        if !set.key_hashes.contains(&signer) {
            continue; // signer is not a committed recovery key of the set it claims
        }
        tally
            .entry(ev.op.clone())
            .or_insert_with(|| (op.clone(), BTreeSet::new()))
            .1
            .insert(signer);
    }

    // Apply recoveries in generation order. Each must satisfy the CURRENT
    // recovery commitment, meet its threshold, and be the next generation. Ties
    // at a generation are broken by payload bytes (deterministic).
    let mut candidates: Vec<(SpaceOp, BTreeSet<[u8; 32]>, Vec<u8>)> = tally
        .into_iter()
        .map(|(bytes, (op, signers))| (op, signers, bytes))
        .collect();
    candidates.sort_by(|a, b| {
        let (SpaceOp::Recover { gen: ga, .. }, SpaceOp::Recover { gen: gb, .. }) = (&a.0, &b.0);
        ga.cmp(gb).then_with(|| a.2.cmp(&b.2))
    });

    loop {
        let mut applied = false;
        for (op, signers, _) in &candidates {
            let SpaceOp::Recover {
                new_root,
                set,
                next_recovery_root,
                gen,
            } = op;
            if *gen != state.gen + 1 {
                continue;
            }
            if set.root() != state.recovery_root {
                continue;
            }
            if (signers.len() as u32) < set.threshold {
                continue;
            }
            state.root = new_root.clone();
            state.recovery_root = *next_recovery_root;
            state.gen = *gen;
            state.recovered = true;
            applied = true;
            break;
        }
        if !applied {
            break;
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::incept_single;
    use ed25519_dalek::SigningKey;

    fn device_of(seed: &[u8; 32]) -> UserId {
        let sk = SigningKey::from_bytes(seed);
        UserId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()))
    }

    fn set_of(seeds: &[[u8; 32]], threshold: u32) -> RecoverySet {
        RecoverySet {
            threshold,
            key_hashes: seeds
                .iter()
                .map(|s| recovery_key_hash(&device_of(s)).unwrap())
                .collect(),
        }
    }

    fn founding(
        seed: [u8; 32],
        salt: [u8; 16],
        recovery_root: [u8; 32],
    ) -> (WorkspaceId, SignedEvent, ActorId) {
        let ws = derive_workspace_id(&device_of(&seed), &salt, &recovery_root);
        let (incept, actor) = incept_single(&seed, &ws, [1u8; 16], [2u8; 16], None);
        (ws, incept, actor)
    }

    fn genesis_with(ws: &WorkspaceId, founder: &ActorId, salt: [u8; 16], rr: [u8; 32]) -> Genesis {
        Genesis {
            workspace_id: ws.clone(),
            founding_actors: vec![founder.clone()],
            salt,
            recovery_root: rr,
        }
    }

    fn a_new_actor(seed: [u8; 32], ws: &WorkspaceId) -> ActorId {
        incept_single(&seed, ws, [7u8; 16], [8u8; 16], None).1
    }

    #[test]
    fn a_valid_founding_verifies_to_its_actor() {
        let rr = set_of(&[[20u8; 32]], 1).root();
        let (ws, incept, actor) = founding([7u8; 32], [9u8; 16], rr);
        assert_eq!(
            verify_founding(&ws, &[9u8; 16], &rr, &incept).unwrap(),
            actor
        );
        assert!(WorkspaceId::parse(ws.as_str()).is_some());
    }

    #[test]
    fn a_tampered_recovery_root_is_rejected() {
        let rr = set_of(&[[20u8; 32]], 1).root();
        let (ws, incept, _) = founding([7u8; 32], [9u8; 16], rr);
        // A different recovery root no longer reproduces the id.
        assert!(verify_founding(&ws, &[9u8; 16], &[0xEE; 32], &incept).is_err());
    }

    #[test]
    fn threshold_recovery_re_roots_only_when_enough_keys_sign() {
        // 2-of-3 recovery. Two committed keys sign an identical Recover → applies.
        let rseeds = [[21u8; 32], [22u8; 32], [23u8; 32]];
        let set = set_of(&rseeds, 2);
        let rr = set.root();
        let (ws, _incept, founder) = founding([7u8; 32], [9u8; 16], rr);
        let genesis = genesis_with(&ws, &founder, [9u8; 16], rr);
        let new_root = vec![a_new_actor([50u8; 32], &ws)];
        let next_rr = set_of(&[[31u8; 32]], 1).root();
        let op = SpaceOp::Recover {
            new_root: new_root.clone(),
            set: set.clone(),
            next_recovery_root: next_rr,
            gen: 1,
        };

        // One signature — below threshold: no re-root.
        let one = vec![sign_op(&rseeds[0], &op, vec![], &ws)];
        let st = replay(&genesis, &ws, &one);
        assert_eq!(st.root, vec![founder.clone()], "1 of 2 does not recover");
        assert!(!st.recovered);

        // Two distinct committed signatures — threshold met: re-roots and rotates.
        let two = vec![
            sign_op(&rseeds[0], &op, vec![], &ws),
            sign_op(&rseeds[1], &op, vec![], &ws),
        ];
        let st = replay(&genesis, &ws, &two);
        assert_eq!(st.root, new_root, "2 of 3 re-roots the workspace");
        assert!(st.recovered);
        assert_eq!(st.recovery_root, next_rr, "the recovery set is rotated");
        assert_eq!(st.gen, 1);
    }

    #[test]
    fn a_non_committed_signer_does_not_count_toward_threshold() {
        let rseeds = [[21u8; 32], [22u8; 32]];
        let set = set_of(&rseeds, 2);
        let rr = set.root();
        let (ws, _i, founder) = founding([7u8; 32], [9u8; 16], rr);
        let genesis = genesis_with(&ws, &founder, [9u8; 16], rr);
        let op = SpaceOp::Recover {
            new_root: vec![a_new_actor([50u8; 32], &ws)],
            set: set.clone(),
            next_recovery_root: [0u8; 32],
            gen: 1,
        };
        // One committed signer + one OUTSIDER (not in the set) — still below 2.
        let evs = vec![
            sign_op(&rseeds[0], &op, vec![], &ws),
            sign_op(&[99u8; 32], &op, vec![], &ws),
        ];
        let st = replay(&genesis, &ws, &evs);
        assert!(!st.recovered, "an outsider's signature is not counted");
        assert_eq!(st.root, vec![founder]);
    }

    #[test]
    fn a_stale_generation_recovery_cannot_replay() {
        let rseeds = [[21u8; 32]];
        let set = set_of(&rseeds, 1);
        let rr = set.root();
        let (ws, _i, founder) = founding([7u8; 32], [9u8; 16], rr);
        let genesis = genesis_with(&ws, &founder, [9u8; 16], rr);
        // A gen-2 recovery with no gen-1 before it: not next-in-sequence, skipped.
        let op = SpaceOp::Recover {
            new_root: vec![a_new_actor([50u8; 32], &ws)],
            set,
            next_recovery_root: [0u8; 32],
            gen: 2,
        };
        let st = replay(&genesis, &ws, &[sign_op(&rseeds[0], &op, vec![], &ws)]);
        assert!(!st.recovered, "a non-monotone generation is ignored");
        assert_eq!(st.root, vec![founder]);
    }
}
