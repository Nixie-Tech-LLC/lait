//! `lait/space/1` — the **self-certifying space** and its **root lifecycle**.
//!
//! Membership made *identity* self-certifying (`ActorId = H(inception)`); this
//! does the same for the **space** one layer up, and gives its trust root a
//! **break-glass recovery** path.
//!
//! # Self-certifying id
//!
//! ```text
//! space_id = ws_<crockford128( blake3("lait/space/1" ‖ device ‖ salt ‖ recovery_commit) )>
//! ```
//!
//! The founding device key + a random salt + the recovery commitment are hashed
//! into the id *before* the founding actor is incepted (an inception is scoped to
//! a space id, so the id cannot depend on it). The signed inception is then
//! the "Found" artifact: `ws_id` commits to the device, the inception commits to
//! `ws_id`, and `founder_actor = H(inception)`. A joiner given
//! `{ws_id, salt, recovery_commit, founder_inception}` verifies the chain offline.
//!
//! # Root lifecycle — a single rotating recovery authority
//!
//! `genesis.founding_actors` is only the *bootstrap* root: it seeds `acl::replay`.
//! Ordinary governance (add/remove admins) rides the ACL. What the ACL cannot do
//! is re-root when the live admin set is **lost or compromised** — that is the
//! break-glass [`Recover`](SpaceOp::Recover).
//!
//! Recovery authority is **one public key** — the same shape whether it is a plain
//! solo key or a **FROST threshold group key** produced by K-of-N holders (a group
//! signature verifies as a plain Ed25519 signature, so the plane never sees the
//! threshold; it lives entirely in the off-plane signing ceremony). The space
//! commits to `recovery_commit = blake3(recovery_pubkey)` in its id at birth
//! (mirroring actor recovery's pre-rotation commitment): a `Recover`/`Rotate` is
//! authorized when its author hashes to the current commitment.
//!
//! [`Rotate`](SpaceOp::Rotate) installs a *new* recovery key — signed by the
//! *current* one — so authority can be **elevated** (found solo, then rotate to a
//! DKG group key as co-founders come online) without ever touching `ws_id`. `gen`
//! is strictly monotone, so an old op cannot be replayed.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::actor::{self, SignedEvent};
use crate::authority::AuthorityConfigurationId;
use crate::genesis::Genesis;
use crate::ids::{ActorId, DeviceId, SpaceId};
use crate::sigdag::{self, SignedNode};

/// Domain separator for the space-id derivation.
const SPACE_DOMAIN: &[u8] = b"lait/space/1";
/// Signing domain for the space-event plane (recovery).
pub const SPACE_EVENT_DOMAIN: &[u8] = b"lait/space/1/event";

/// A signed space-plane event — the shared hash-DAG envelope under this domain.
/// For a threshold group, the `author` is the FROST group public key and `sig` is
/// the aggregated group signature; the envelope is otherwise unchanged.
pub type SignedSpaceEvent = SignedNode;

/// The commitment to a recovery public key: `blake3(pubkey bytes)`. This is what
/// the space id binds at birth and what a `Rotate` installs for the next key.
pub fn recovery_commit(recovery_pub: &DeviceId) -> Option<[u8; 32]> {
    let raw = hex32(recovery_pub.as_str())?;
    Some(*blake3::hash(&raw).as_bytes())
}

/// The recovery public key a seed produces (for a plain solo recovery key).
pub fn recovery_pub_of(seed: &[u8; 32]) -> DeviceId {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    DeviceId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()))
}

/// Mint a fresh solo (1-of-1) recovery keypair: returns `(pubkey, secret seed)`.
/// The secret is stored offline; a threshold group key is instead produced by a
/// FROST DKG among the holders and installed via [`SpaceOp::Rotate`].
pub fn mint_recovery_key() -> (DeviceId, [u8; 32]) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom");
    (recovery_pub_of(&seed), seed)
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

/// A space-plane op. All are signed by the **current recovery key** (a solo
/// key or a FROST group key); planned admin governance rides the ACL.
///
/// # Standing-authority commitment
///
/// The plane commits to the **complete** standing authority: its public key
/// (via `recovery_commit`) and the *arrangement operating it* (via an opaque
/// [`AuthorityConfigurationId`]). The plane never decodes the configuration — it
/// carries a 32-byte commitment and stays blind to signing topology, exactly as
/// it is blind to the threshold behind a group key. What the commitment buys is
/// that **every replica, holder or not, learns the standing arrangement by
/// replay** rather than by holding a share.
///
/// A configuration id on a `Rotate`/`Reshare` is an *attestation by the current
/// authority* about the next arrangement. The plane cannot verify it is truthful
/// — but the current recovery authority already has unlimited power to rotate to
/// any key it controls, so a false configuration id grants nothing new; it only
/// guarantees a single, signed, replayable view that cannot differ between
/// replicas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaceOp {
    /// Break-glass re-root: replace the bootstrap root that seeds `acl::replay`.
    /// Leaves the recovery authority (key and arrangement) untouched.
    Recover {
        /// The new root (non-empty); the recovered admin re-adds the team + re-keys.
        new_root: Vec<ActorId>,
        /// Strictly `current_gen + 1` — monotone, so an old op can't replay.
        gen: u32,
    },
    /// Rotate the recovery authority to a **new key** (e.g. elevate a solo key to
    /// a DKG group key). Signed by the current key; the new key's commitment
    /// becomes the authority for the next op.
    Rotate {
        new_recovery_key: DeviceId,
        gen: u32,
        /// The arrangement operating the new key. **Required.**
        ///
        /// Postcard is positional and non-self-describing: a missing field does
        /// not default, it fails to decode. There is no wire migration from the
        /// earlier two-field `Rotate` — and none is needed, because no `Rotate`
        /// event is deployed. The only producer of a `Rotate` is the FROST
        /// elevation install path (unreleased ceremony/2); solo spaces carry
        /// no space events beyond genesis, and genesis is `Single` by
        /// construction. An old two-field `Rotate`, were one to exist, would fail
        /// to decode and be skipped in replay — never silently mis-read as a
        /// valid rotate with a bogus configuration (pinned by
        /// `an_old_two_field_rotate_does_not_misdecode`).
        next_configuration: AuthorityConfigurationId,
    },
    /// Reshare the **same key** under a new arrangement — the standing key is
    /// unchanged, only the configuration operating it changes.
    ///
    /// Defined here so replay can *represent* a same-key transition; the
    /// off-plane authorization refuses to author one until proactive
    /// resharing protocol exists (mirroring `ProposedTransition::Reshare`, which
    /// round-trips but is refused). The plane applying it is not the same as the
    /// product performing it.
    Reshare {
        next_configuration: AuthorityConfigurationId,
        gen: u32,
    },
}

impl SpaceOp {
    fn gen(&self) -> u32 {
        match self {
            SpaceOp::Recover { gen, .. }
            | SpaceOp::Rotate { gen, .. }
            | SpaceOp::Reshare { gen, .. } => *gen,
        }
    }
    fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode space op")
    }
}

/// Sign a [`SpaceOp`] with the recovery key's seed (its author is the recovery
/// public key). A threshold group instead produces the signature via a FROST
/// signing ceremony and assembles the same [`SignedSpaceEvent`] with the group
/// key as `author`.
pub fn sign_op(
    recovery_seed: &[u8; 32],
    op: &SpaceOp,
    parents: Vec<String>,
    space_id: &SpaceId,
) -> SignedSpaceEvent {
    sigdag::sign_node(
        SPACE_EVENT_DOMAIN,
        recovery_seed,
        op.encode(),
        parents,
        space_id.as_str(),
    )
}

/// The materialized root after replaying the space plane over genesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootState {
    /// The effective bootstrap root — what seeds `acl::replay`.
    pub root: Vec<ActorId>,
    /// The commitment to the current recovery key (rotated by each `Rotate`).
    pub recovery_commit: [u8; 32],
    /// The **standing arrangement** operating the recovery key. Genesis is
    /// [`AuthorityConfigurationId::single`]; each `Rotate`/`Reshare` sets it. The
    /// plane never decodes it — it is the opaque commitment other layers read to
    /// learn the authority's topology without holding a share.
    pub configuration: AuthorityConfigurationId,
    /// Generation of the last applied op (0 at birth).
    pub gen: u32,
    /// Whether any break-glass `Recover` has been applied.
    pub recovered: bool,
}

/// Derive the self-certifying space id from the founding device, salt, and
/// recovery commitment. Pure and deterministic.
pub fn derive_space_id(
    founding_device: &DeviceId,
    salt: &[u8; 16],
    recovery_commit: &[u8; 32],
) -> SpaceId {
    let mut h = blake3::Hasher::new();
    h.update(SPACE_DOMAIN);
    h.update(founding_device.as_str().as_bytes());
    h.update(salt);
    h.update(recovery_commit);
    let digest = h.finalize();
    let mut d16 = [0u8; 16];
    d16.copy_from_slice(&digest.as_bytes()[..16]);
    SpaceId::from_digest(d16)
}

/// Verify a space's founding commitment and return the **verified** founding
/// actor to root genesis on. Checks, all offline:
/// 1. `ws_id` commits to the inception's signing device + `salt` + `recovery_commit`;
/// 2. the inception is a valid, `ws_id`-scoped founding key-event.
pub fn verify_founding(
    ws_id: &SpaceId,
    salt: &[u8; 16],
    recovery_commit: &[u8; 32],
    founder_inception: &SignedEvent,
) -> Result<ActorId> {
    if derive_space_id(&founder_inception.author, salt, recovery_commit) != *ws_id {
        bail!("space id does not commit to this founder — ticket is forged or corrupt");
    }
    let founder_actor = ActorId::from_incept_hash(&founder_inception.hash());
    let plane = actor::replay(ws_id, std::slice::from_ref(founder_inception));
    if !plane.exists(&founder_actor) {
        bail!("founding inception is not valid for this space");
    }
    Ok(founder_actor)
}

/// Replay the space plane over genesis to the current root. Seeds from
/// `genesis.founding_actors` / `genesis.recovery_root`, then applies each op —
/// authored by the current recovery key — in generation order. Deterministic and
/// convergent: same events → same `RootState` on every replica, order-independent.
pub fn replay(genesis: &Genesis, ws_id: &SpaceId, events: &[SignedSpaceEvent]) -> RootState {
    let mut state = RootState {
        root: genesis.founding_actors.clone(),
        recovery_commit: genesis.recovery_root,
        // Every space is born a solo authority; a `Rotate`/`Reshare` moves it.
        configuration: AuthorityConfigurationId::single(),
        gen: 0,
        recovered: false,
    };

    // Decode + signature-verify every op up front; carry the op bytes for a
    // deterministic tie-break among same-generation ops.
    let mut ops: Vec<(u32, Vec<u8>, SpaceOp, DeviceId)> = events
        .iter()
        .filter_map(|ev| {
            if !ev.verify_sig(SPACE_EVENT_DOMAIN, ws_id.as_str()) {
                return None;
            }
            let op = postcard::from_bytes::<SpaceOp>(&ev.op).ok()?;
            Some((op.gen(), ev.op.clone(), op, ev.author.clone()))
        })
        .collect();
    ops.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    // Apply the next-generation op whose author is the current recovery authority.
    loop {
        let mut applied = false;
        for (gen, _, op, author) in &ops {
            if *gen != state.gen + 1 {
                continue;
            }
            if recovery_commit(author) != Some(state.recovery_commit) {
                continue; // not signed by the current recovery key
            }
            match op {
                SpaceOp::Recover { new_root, .. } => {
                    if new_root.is_empty() {
                        continue;
                    }
                    state.root = new_root.clone();
                    state.recovered = true;
                }
                SpaceOp::Rotate {
                    new_recovery_key,
                    next_configuration,
                    ..
                } => {
                    let Some(c) = recovery_commit(new_recovery_key) else {
                        continue;
                    };
                    state.recovery_commit = c;
                    state.configuration = *next_configuration;
                }
                SpaceOp::Reshare {
                    next_configuration, ..
                } => {
                    // Same key, new arrangement. Key commitment untouched.
                    state.configuration = *next_configuration;
                }
            }
            state.gen = *gen;
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

    fn device_of(seed: &[u8; 32]) -> DeviceId {
        recovery_pub_of(seed)
    }

    fn founding(
        seed: [u8; 32],
        salt: [u8; 16],
        recovery_commit: [u8; 32],
    ) -> (SpaceId, SignedEvent, ActorId) {
        let ws = derive_space_id(&device_of(&seed), &salt, &recovery_commit);
        let (incept, actor) = incept_single(&seed, &ws, [1u8; 16], [2u8; 16], None);
        (ws, incept, actor)
    }

    fn genesis_with(ws: &SpaceId, founder: &ActorId, salt: [u8; 16], rc: [u8; 32]) -> Genesis {
        Genesis {
            space_id: ws.clone(),
            founding_actors: vec![founder.clone()],
            salt,
            recovery_root: rc,
        }
    }

    fn a_new_actor(seed: [u8; 32], ws: &SpaceId) -> ActorId {
        incept_single(&seed, ws, [7u8; 16], [8u8; 16], None).1
    }

    #[test]
    fn a_valid_founding_verifies_to_its_actor() {
        let rc = recovery_commit(&recovery_pub_of(&[20u8; 32])).unwrap();
        let (ws, incept, actor) = founding([7u8; 32], [9u8; 16], rc);
        assert_eq!(
            verify_founding(&ws, &[9u8; 16], &rc, &incept).unwrap(),
            actor
        );
        assert!(SpaceId::parse(ws.as_str()).is_some());
    }

    #[test]
    fn a_tampered_recovery_commit_is_rejected() {
        let rc = recovery_commit(&recovery_pub_of(&[20u8; 32])).unwrap();
        let (ws, incept, _) = founding([7u8; 32], [9u8; 16], rc);
        assert!(verify_founding(&ws, &[9u8; 16], &[0xEE; 32], &incept).is_err());
    }

    #[test]
    fn only_the_committed_recovery_key_can_re_root() {
        // Birth commits to recovery key R. A Recover signed by R re-roots; one
        // signed by an unrelated key is inert.
        let r_seed = [21u8; 32];
        let rc = recovery_commit(&recovery_pub_of(&r_seed)).unwrap();
        let (ws, _i, founder) = founding([7u8; 32], [9u8; 16], rc);
        let genesis = genesis_with(&ws, &founder, [9u8; 16], rc);
        let new_root = vec![a_new_actor([50u8; 32], &ws)];
        let op = SpaceOp::Recover {
            new_root: new_root.clone(),
            gen: 1,
        };

        // Wrong key: not authorized.
        let evil = vec![sign_op(&[99u8; 32], &op, vec![], &ws)];
        assert!(!replay(&genesis, &ws, &evil).recovered);

        // The committed key: re-roots.
        let good = vec![sign_op(&r_seed, &op, vec![], &ws)];
        let st = replay(&genesis, &ws, &good);
        assert!(st.recovered);
        assert_eq!(st.root, new_root);
        assert_eq!(st.gen, 1);
    }

    #[test]
    fn rotate_elevates_the_recovery_key_then_only_the_new_one_recovers() {
        // Solo key R1 elevates authority to R2 (a stand-in for a DKG group key);
        // thereafter only R2 can recover, and R1 is spent.
        let r1 = [21u8; 32];
        let r2 = [22u8; 32];
        let rc1 = recovery_commit(&recovery_pub_of(&r1)).unwrap();
        let (ws, _i, founder) = founding([7u8; 32], [9u8; 16], rc1);
        let genesis = genesis_with(&ws, &founder, [9u8; 16], rc1);

        // Solo→solo rotate: the new key is another solo key, so Single.
        let rotate = SpaceOp::Rotate {
            new_recovery_key: recovery_pub_of(&r2),
            next_configuration: AuthorityConfigurationId::single(),
            gen: 1,
        };
        let recover = SpaceOp::Recover {
            new_root: vec![a_new_actor([50u8; 32], &ws)],
            gen: 2,
        };

        // R1 rotates to R2; R2 then recovers.
        let events = vec![
            sign_op(&r1, &rotate, vec![], &ws),
            sign_op(&r2, &recover, vec![], &ws),
        ];
        let st = replay(&genesis, &ws, &events);
        assert!(
            st.recovered && st.gen == 2,
            "R2 recovers after the rotation"
        );

        // R1 attempting the gen-2 recover after rotation is inert (no longer the key).
        let r1_recover = sign_op(&r1, &recover, vec![], &ws);
        let events2 = vec![sign_op(&r1, &rotate, vec![], &ws), r1_recover];
        assert!(
            !replay(&genesis, &ws, &events2).recovered,
            "the spent key cannot recover"
        );
    }

    #[test]
    fn genesis_is_a_solo_authority_and_a_configured_rotate_moves_it() {
        use crate::authority::{
            AuthorityConfiguration, AuthorityConfigurationId, FrostThresholdConfig, PrincipalId,
        };
        let r1 = [21u8; 32];
        let r2 = [22u8; 32];
        let rc1 = recovery_commit(&recovery_pub_of(&r1)).unwrap();
        let (ws, _i, founder) = founding([7u8; 32], [9u8; 16], rc1);
        let genesis = genesis_with(&ws, &founder, [9u8; 16], rc1);

        // Born solo.
        assert_eq!(
            replay(&genesis, &ws, &[]).configuration,
            AuthorityConfigurationId::single()
        );

        // A rotate that names a 2-of-3 group arrangement moves the standing
        // configuration to it — visible to any replayer, holder or not.
        let mut members: Vec<PrincipalId> = (30..33u8)
            .map(|n| PrincipalId::of_device(&recovery_pub_of(&[n; 32])))
            .collect();
        members.sort();
        let cfg = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 2,
            participants: members,
        });
        let rotate = SpaceOp::Rotate {
            new_recovery_key: recovery_pub_of(&r2),
            next_configuration: cfg.id(),
            gen: 1,
        };
        let st = replay(&genesis, &ws, &[sign_op(&r1, &rotate, vec![], &ws)]);
        assert_eq!(
            st.configuration,
            cfg.id(),
            "the arrangement is on-plane now"
        );
        assert_eq!(
            st.recovery_commit,
            recovery_commit(&recovery_pub_of(&r2)).unwrap()
        );
    }

    /// The earlier `Rotate` encoding had two fields `{new_recovery_key, gen}`. Postcard is
    /// positional and non-self-describing, so a field cannot be added compatibly
    /// — this pins that an old two-field encoding fails to decode as the new
    /// three-field `Rotate` rather than silently mis-reading `gen`'s bytes as a
    /// configuration id. (No such events are deployed; this guards the claim.)
    #[test]
    fn an_old_two_field_rotate_does_not_misdecode() {
        #[derive(serde::Serialize)]
        enum OldSpaceOp {
            #[allow(dead_code)]
            Recover { new_root: Vec<ActorId>, gen: u32 },
            Rotate {
                new_recovery_key: DeviceId,
                gen: u32,
            },
        }
        let old = OldSpaceOp::Rotate {
            new_recovery_key: recovery_pub_of(&[5u8; 32]),
            gen: 1,
        };
        let bytes = postcard::to_stdvec(&old).unwrap();
        match postcard::from_bytes::<SpaceOp>(&bytes) {
            Err(_) => {}
            Ok(SpaceOp::Rotate { .. }) => {
                panic!("old two-field bytes silently mis-decoded into a new Rotate")
            }
            Ok(_) => {}
        }
    }

    #[test]
    fn a_reshare_changes_the_arrangement_without_changing_the_key() {
        use crate::authority::{
            AuthorityConfiguration, AuthorityConfigurationId, FrostThresholdConfig, PrincipalId,
        };
        let r = [21u8; 32];
        let rc = recovery_commit(&recovery_pub_of(&r)).unwrap();
        let (ws, _i, founder) = founding([7u8; 32], [9u8; 16], rc);
        let genesis = genesis_with(&ws, &founder, [9u8; 16], rc);

        let mut members: Vec<PrincipalId> = (30..33u8)
            .map(|n| PrincipalId::of_device(&recovery_pub_of(&[n; 32])))
            .collect();
        members.sort();
        let cfg = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 2,
            participants: members,
        });
        let reshare = SpaceOp::Reshare {
            next_configuration: cfg.id(),
            gen: 1,
        };
        let st = replay(&genesis, &ws, &[sign_op(&r, &reshare, vec![], &ws)]);
        assert_eq!(st.configuration, cfg.id(), "arrangement moved");
        assert_eq!(st.recovery_commit, rc, "but the KEY is unchanged");
        assert_ne!(
            st.configuration,
            AuthorityConfigurationId::single(),
            "no longer solo"
        );
    }

    #[test]
    fn a_stale_generation_op_cannot_replay() {
        let r = [21u8; 32];
        let rc = recovery_commit(&recovery_pub_of(&r)).unwrap();
        let (ws, _i, founder) = founding([7u8; 32], [9u8; 16], rc);
        let genesis = genesis_with(&ws, &founder, [9u8; 16], rc);
        // A gen-2 op with no gen-1 before it is not next-in-sequence.
        let op = SpaceOp::Recover {
            new_root: vec![a_new_actor([50u8; 32], &ws)],
            gen: 2,
        };
        assert!(!replay(&genesis, &ws, &[sign_op(&r, &op, vec![], &ws)]).recovered);
    }
}
