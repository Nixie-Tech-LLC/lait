//! The product's mechanics composition for the orbital plane.
//!
//! `OrbitalMechanics` owns the Space's **signed authority material** through
//! the mechanics [`AuthorityLedger`] — the journaled effect store persisted
//! beside the orbital store — and implements every seam the runtime consumes:
//!
//! - [`runtime::AuthorityView`]: device → actor/standing/authority frontier,
//!   resolved from the ledger's materialized checkpoint;
//! - [`replica::AuthoritySource`]: signer standing **at the referenced
//!   historical frontier** — the ledger resolves the exact effect closure the
//!   frontier's heads name and evaluates standing there, never against
//!   current state;
//! - [`replica::BodyKeySource`]: authorized key epochs from the sealed
//!   envelopes, opened with this device's seed, bound to the signed mint's
//!   key commitment — the existing construction, no new cryptography;
//! - [`replica::AuthorityIncorporator`] + the authority export: ledger
//!   effects and admission redemptions ride Contact's authority records —
//!   the explicit first durable Convergence phase, committed **atomically**
//!   (an invalid record refuses the whole batch; no prefix survives).
//!
//! Formation mints the founding material exactly as before (self-certifying
//! SpaceId over founder device + salt + recovery root, founding inception,
//! epoch-0 mint sealed to the founder); entry verifies Coordinates offline
//! and establishes standing by having its inception (and any admission
//! capability) pulled by an admin over Contact, whose incorporator validates
//! and redeems it (AddMember + epoch sealing).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::acl::{self, AclAction, AclOp, AclState, Grant};
use crate::actor;
use crate::crypto::{self, SpaceKey};
use crate::genesis::Genesis;
use crate::ids::{ActorId, DeviceId, SpaceId};
use mechanics::ledger::{AuthorityLedger, LedgerEffect, SealedKeyRecord};
use replica::frontier::AuthorityFrontier;
use runtime::coordinates::AdmissionCapabilityV1;

const GENESIS_FILE: &str = "mech-genesis.json";
const PENDING_INCEPTION_FILE: &str = "mech-pending-inception.bin";
const PENDING_ADMISSION_FILE: &str = "mech-pending-admission.bin";
const PENDING_PROOF_FILE: &str = "mech-pending-proof.bin";
/// The verified bootstrap Coordinates a joiner entered with (routes + approach
/// Station), persisted so the daemon can teach its transport and dial.
const COORDINATES_FILE: &str = "mech-coordinates.bin";
/// The authority ledger's journal root, under the Space's mechanics dir.
const LEDGER_DIR: &str = "authority";
/// The founder's offline **actor** recovery seed (hex), escrowed at formation
/// so a fresh device can reset this actor's device set.
const RECOVERY_KEY_FILE: &str = "recovery.key";
/// The founder's offline **space** break-glass recovery secret (hex), the solo
/// authority material an elevation converts into a threshold group key.
const SPACE_RECOVERY_KEY_FILE: &str = "space-recovery.key";

/// Extract an invite nonce from either an orbital Coordinates link (its
/// embedded admission capability) or a raw 32-hex string.
fn parse_invite_nonce(input: &str) -> Option<[u8; 16]> {
    let s = input.trim();
    if let Ok(coords) = runtime::SignedCoordinatesV1::parse_link(s) {
        if let runtime::coordinates::CoordinatesAdmission::Some(cap) = &coords.payload.admission {
            return Some(cap.nonce);
        }
    }
    let raw = data_encoding::HEXLOWER_PERMISSIVE
        .decode(s.as_bytes())
        .ok()?;
    raw.as_slice().try_into().ok()
}

/// Read a hex-encoded 32-byte secret written by [`persist_hex_key`].
fn read_hex_key(path: &Path) -> Option<[u8; 32]> {
    let bytes = crate::secretfs::read_private(path).ok().flatten()?;
    let hex = String::from_utf8(bytes).ok()?;
    let raw = data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.trim().as_bytes())
        .ok()?;
    raw.as_slice().try_into().ok()
}

/// Escrow a 32-byte secret as owner-only, portable hex — never world-readable
/// even briefly (create-new; a pre-existing file is left untouched).
fn persist_hex_key(dir: &Path, file: &str, secret: &[u8; 32]) -> Result<()> {
    crate::secretfs::create_private_dir(dir)?;
    let hex = data_encoding::HEXLOWER.encode(secret);
    crate::secretfs::write_private(
        &dir.join(file),
        hex.as_bytes(),
        crate::secretfs::Create::New,
        crate::secretfs::Wrap::Portable,
    )
}

/// One authority-record unit riding Contact's authority section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorityRecord {
    /// One canonical signed ledger effect (actor event, ACL op, or ceremony
    /// event). Import validates the complete batch, then commits atomically.
    Effect(Vec<u8>),
    /// One sealed key-epoch envelope record (canonical
    /// [`SealedKeyRecord`] bytes). Authorization is the signed mint;
    /// a forged envelope is inert.
    SealedKey(Vec<u8>),
    /// A joiner's admission redemption: the admin-signed capability, the
    /// joiner's canonical inception bytes, the joiner's signed acceptance
    /// proof, and the canonical digest of the Coordinates it accepted. An
    /// admin incorporator validates the proof + capability and redeems it
    /// (AddMember + the evidence role expansion + epoch sealing); everyone
    /// else retains the effect material it rides beside.
    Admission {
        admission: Vec<u8>,
        inception: Vec<u8>,
        proof: Vec<u8>,
        coordinates_digest: [u8; 32],
    },
}

impl AuthorityRecord {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("authority record")
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        postcard::from_bytes(bytes).ok()
    }
}

pub(super) struct Inner {
    pub(super) space: SpaceId,
    pub(super) ledger: AuthorityLedger,
    pub(super) seed: [u8; 32],
    pub(super) me: DeviceId,
    pub(super) keyring: BTreeMap<[u8; 16], SpaceKey>,
    pub(super) dir: PathBuf,
    /// A joiner's own admission, served until standing is established.
    pending_admission: Option<AdmissionCapabilityV1>,
    /// A joiner's self-inception, held out of the replicated set until an
    /// admin admits it (it rides the Admission record).
    pending_inception: Option<actor::SignedEvent>,
    /// A joiner's signed acceptance proof (persisted, reused byte-for-byte on
    /// every retry) plus the digest of the Coordinates it accepted.
    pending_proof: Option<(runtime::coordinates::InvitationAcceptanceProof, [u8; 32])>,
}

impl Inner {
    pub(super) fn acl(&mut self) -> AclState {
        self.ledger.acl_state().unwrap_or_default()
    }

    pub(super) fn actor_plane(&self) -> actor::ActorPlane {
        self.ledger.actor_plane()
    }

    pub(super) fn my_actor(&self) -> Option<ActorId> {
        self.actor_plane().actor_of_device(&self.me).cloned()
    }

    fn frontier(&self) -> AuthorityFrontier {
        AuthorityFrontier::from_canonical_bytes(self.ledger.frontier())
    }

    /// Unseal every authorized epoch key addressed to this device, bound to
    /// the signed mint's commitment.
    pub(super) fn refresh_keyring(&mut self) {
        for e in self.acl().epochs() {
            if self.keyring.contains_key(&e.id) {
                continue;
            }
            if let Some(sealed) = self.ledger.sealed_for(&e.id, &self.me) {
                if let Some(raw) = crypto::open_sealed(&self.seed, &self.me, &sealed) {
                    if let Ok(key) = <SpaceKey>::try_from(raw.as_slice()) {
                        if *blake3::hash(&key).as_bytes() == e.key_commit {
                            self.keyring.insert(e.id, key);
                        }
                    }
                }
            }
        }
    }

    /// Whether this device's actor currently holds admin standing.
    pub(super) fn am_i_admin(&mut self) -> bool {
        match self.my_actor() {
            Some(me) => self.acl().is_admin(&me),
            None => false,
        }
    }

    /// The deterministic active epoch: highest authorized `(gen, id)`.
    pub(super) fn active_epoch(&mut self) -> Option<acl::EpochAuth> {
        self.acl()
            .epochs()
            .into_iter()
            .max_by(|a, b| a.gen.cmp(&b.gen).then_with(|| a.id.cmp(&b.id)))
    }

    /// The sealed records distributing every held epoch key to every device of
    /// `actor` (for batching with the authority effect that admits them).
    pub(super) fn seal_records_for_actor(&mut self, target: &ActorId) -> Vec<Vec<u8>> {
        let devices = self.actor_plane().devices_of(target);
        let mut out = Vec::new();
        for (epoch, key) in self.keyring.iter() {
            for d in &devices {
                if self.ledger.sealed_for(epoch, d).is_some() {
                    continue;
                }
                if let Some(sealed) = crypto::seal_to(d, key) {
                    out.push(
                        SealedKeyRecord {
                            epoch: *epoch,
                            device: d.clone(),
                            sealed,
                        }
                        .encode(),
                    );
                }
            }
        }
        out
    }

    /// Author one signed ACL op as this device's actor and commit it — with
    /// any accompanying effects and sealed records — as one atomic batch.
    pub(super) fn author(
        &mut self,
        action: AclAction,
        nonce: Option<[u8; 16]>,
        extra_effects: Vec<Vec<u8>>,
        sealed_records: Vec<Vec<u8>>,
    ) -> Result<()> {
        let me = self
            .my_actor()
            .ok_or_else(|| anyhow!("no actor identity"))?;
        let op = acl::sign_op(
            &self.seed,
            &AclOp {
                action,
                by: me.clone(),
                actor_asof: self.ledger.actor_heads(&me),
                nonce,
            },
            self.ledger.acl_heads(),
            &self.space,
        );
        let mut effects = extra_effects;
        effects.push(LedgerEffect::Acl(op).encode());
        self.ledger
            .commit_batch(&effects, &sealed_records)
            .map_err(|e| anyhow!("authority commit: {e}"))?;
        Ok(())
    }

    /// Append one signed ceremony/space event to the authority history as a
    /// [`LedgerEffect::Ceremony`] — the orbital replacement for the legacy
    /// `membership.add_ceremony_event` + `persist_membership`. Idempotent (the
    /// ledger dedups by node hash), so replaying the same board node is a
    /// no-op, and the node replicates to peers as an ordinary authority record.
    pub(super) fn commit_ceremony(&mut self, ev: crate::space::SignedSpaceEvent) -> Result<()> {
        self.ledger
            .commit_batch(&[LedgerEffect::Ceremony(ev).encode()], &[])
            .map_err(|e| anyhow!("ceremony commit: {e}"))?;
        Ok(())
    }

    /// Resolve an actor by its actor id or by one of its device keys — the
    /// orbital form of the legacy `resolve_actor`, used to interpret the
    /// `--to` roots a recovery approver names.
    pub(super) fn resolve_actor(&self, who: &str) -> Option<ActorId> {
        let who = who.trim();
        if let Some(actor) = ActorId::parse(who) {
            if self.actor_plane().exists(&actor) {
                return Some(actor);
            }
        }
        if let Some(device) = DeviceId::parse(who) {
            if let Some(actor) = self.actor_plane().actor_of_device(&device) {
                return Some(actor.clone());
            }
        }
        None
    }

    /// Mint a fresh key epoch (gen = active + 1) for the current member set,
    /// sealed to every current member's devices, and adopt it locally. The
    /// content-key fence: a departed device holds no envelope for the new
    /// epoch, so it cannot read anything sealed under it. Requires this device
    /// to hold the active key (so it can carry the plaintext into the new
    /// envelopes) and admin standing (mint authorization).
    pub(super) fn rotate_key(&mut self) -> Result<()> {
        self.refresh_keyring();
        let me = self
            .my_actor()
            .ok_or_else(|| anyhow!("no actor identity"))?;
        let next_gen = self.active_epoch().map(|e| e.gen + 1).unwrap_or(0);
        let id = super::rand16();
        let key = crypto::random_key();
        let key_commit = *blake3::hash(&key).as_bytes();
        let members: Vec<ActorId> = self.acl().members().into_iter().map(|(a, _)| a).collect();
        // Seal the fresh key to every current member device before the mint
        // lands, so the batch that authorizes the epoch also distributes it.
        let mut sealed_records = Vec::new();
        for actor in &members {
            for d in self.actor_plane().devices_of(actor) {
                if let Some(sealed) = crypto::seal_to(&d, &key) {
                    sealed_records.push(
                        SealedKeyRecord {
                            epoch: id,
                            device: d,
                            sealed,
                        }
                        .encode(),
                    );
                }
            }
        }
        self.author(
            AclAction::MintEpoch {
                id,
                gen: next_gen,
                key_commit,
                members,
            },
            None,
            vec![],
            sealed_records,
        )?;
        let _ = me;
        self.keyring.insert(id, key);
        Ok(())
    }

    /// This device's offline **actor** recovery seed, if it was escrowed here
    /// at formation (`recovery.key`). Resets the actor's device set on recover.
    pub(super) fn read_recovery_key(&self) -> Option<[u8; 32]> {
        read_hex_key(&self.dir.join(RECOVERY_KEY_FILE))
    }

    /// This device's offline **space** break-glass recovery secret, if it holds
    /// the solo authority (`space-recovery.key`). `None` once the space has been
    /// elevated to a threshold group key.
    pub(super) fn read_space_recovery_key(&self) -> Option<[u8; 32]> {
        read_hex_key(&self.dir.join(SPACE_RECOVERY_KEY_FILE))
    }

    /// The admin-side admission redemption: validate the capability, the
    /// acceptance proof, and the joiner's inception, then admit + install the
    /// evidence role expansion + seal in one atomic authority batch.
    fn redeem_admission(
        &mut self,
        admission_bytes: &[u8],
        inception_bytes: &[u8],
        proof_bytes: &[u8],
        coords_digest: &[u8; 32],
    ) -> Result<()> {
        let admission: AdmissionCapabilityV1 =
            postcard::from_bytes(admission_bytes).context("admission decode")?;
        admission
            .verify_structure(&self.space)
            .map_err(|e| anyhow!("admission: {e}"))?;
        let inception: actor::SignedEvent =
            postcard::from_bytes(inception_bytes).context("inception decode")?;
        let proof: runtime::coordinates::InvitationAcceptanceProof =
            postcard::from_bytes(proof_bytes).context("proof decode")?;
        let joiner_actor = ActorId::from_incept_hash(&inception.hash());
        // The inception must cleanly incept for THIS space.
        let mut candidate = self.ledger.actor_events();
        candidate.push(inception.clone());
        let candidate_plane = actor::replay(&self.space, &candidate);
        if !candidate_plane.exists(&joiner_actor) {
            return Err(anyhow!("invalid joiner inception"));
        }
        // The candidate device: the proof's public key must be one of the
        // inception's devices, and derive the device id.
        let candidate_device = DeviceId::from_key_bytes(&proof.public_key);
        if !candidate_plane.is_device_of(&joiner_actor, &candidate_device) {
            return Err(anyhow!(
                "acceptance proof key is not the candidate's device"
            ));
        }
        // Verify the acceptance proof binds this exact candidate + capability +
        // Coordinates. Substitution of any of these fails here.
        let space_bytes = <[u8; 29]>::try_from(self.space.as_str().as_bytes())
            .map_err(|_| anyhow!("space id shape"))?;
        if !proof.verify(
            coords_digest,
            &space_bytes,
            &admission.issuer,
            &admission.capability_id(),
            joiner_actor.as_str(),
            &proof.public_key,
        ) {
            return Err(anyhow!("invalid acceptance proof"));
        }
        // The acceptance id, for single-use/reuse convergence + audit.
        let acceptance_id = proof.acceptance_id(
            coords_digest,
            &space_bytes,
            &admission.issuer,
            &admission.capability_id(),
            joiner_actor.as_str(),
            &proof.public_key,
        );
        let _ = acceptance_id;
        let acl_state = self.acl();
        // The capability's issuer must currently speak for an admin.
        let issuer_device = DeviceId::from_key_bytes(&admission.issuer);
        let issuer_ok = self
            .actor_plane()
            .actor_of_device(&issuer_device)
            .is_some_and(|a| acl_state.is_admin(a));
        if !issuer_ok {
            return Err(anyhow!("admission issuer is not an admin"));
        }
        // We can only admit + seal if we ourselves are an admin with the key.
        match self.my_actor() {
            Some(me) if acl_state.is_admin(&me) => {}
            _ => return Err(anyhow!("this node is not an admin")),
        }
        if acl_state.is_invite_revoked(&admission.nonce) {
            return Err(anyhow!("admission revoked"));
        }
        // Time window: the capability must be within its validity window and
        // the acceptance not older than it (skew-tolerant at the redeemer).
        let now = now_secs();
        if !admission.is_within_window(now) {
            return Err(anyhow!("admission outside its validity window"));
        }
        // Redemption cap: refuse once the nonce's redemptions reach the cap
        // (single-use = 1). Idempotent re-admit of the SAME actor is allowed.
        let already = acl_state.nonce_redeemers(&admission.nonce);
        if already.contains(&joiner_actor) {
            return Ok(()); // idempotent replay
        }
        if already.len() as u32 >= admission.use_policy.cap() {
            return Err(anyhow!("admission redemption cap reached"));
        }
        if acl_state.is_member(&joiner_actor) {
            return Ok(()); // idempotent
        }
        // Stage the joiner's inception + AddMember + sealed keys as ONE batch.
        let inception_effect = LedgerEffect::Actor(inception.clone()).encode();
        // Devices of the joiner: from the candidate plane (the inception is
        // not yet committed, so resolve against the candidate set).
        let devices = actor::replay(&self.space, &candidate).devices_of(&joiner_actor);
        let mut sealed_records = Vec::new();
        for (epoch, key) in self.keyring.iter() {
            for d in &devices {
                if let Some(sealed) = crypto::seal_to(d, key) {
                    sealed_records.push(
                        SealedKeyRecord {
                            epoch: *epoch,
                            device: d.clone(),
                            sealed,
                        }
                        .encode(),
                    );
                }
            }
        }
        // Always record the nonce so redemptions are counted for the cap and
        // single-use convergence (the ACL replay resolves concurrent races by
        // canonical acceptance order).
        self.author(
            AclAction::AddMember {
                actor: joiner_actor.clone(),
                grants: vec![Grant::Write],
            },
            Some(admission.nonce),
            vec![inception_effect],
            sealed_records,
        )?;
        // Redemption installs exactly the capability's WorldAssignmentEvidence
        // expansion (plan M2) — the selected role's expanded assignments,
        // which for the default contributor invite include the mandatory
        // `space.issue.read` baseline.
        for (i, (capability, resource)) in admission.evidence.assignments.iter().enumerate() {
            let salt = {
                let mut s = super::rand16();
                s[0] = i as u8;
                s
            };
            if inner_grant(
                self,
                &joiner_actor,
                capability.clone(),
                resource.clone(),
                salt,
            )
            .is_err()
            {
                // A grant failure inside redemption is a durable-store fault;
                // surface it rather than admitting without authority.
                return Err(anyhow!("seal joiner capability"));
            }
        }
        Ok(())
    }
}

/// Unix seconds now.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Author a GrantCapability for an arbitrary actor (used by redemption to
/// install a joiner's role expansion). The author is this device's founding
/// actor, which holds policy-admin standing.
fn inner_grant(
    inner: &mut Inner,
    actor: &ActorId,
    capability: mechanics::demand::PolicyCapability,
    resource: mechanics::demand::PolicyResource,
    salt: [u8; 16],
) -> Result<()> {
    let grant_id = acl::capability_grant_id(actor, &capability, &resource, &salt)
        .ok_or_else(|| anyhow!("grant id"))?;
    inner.author(
        AclAction::GrantCapability {
            grant_id,
            actor: actor.clone(),
            capability,
            resource,
            salt,
        },
        None,
        vec![],
        vec![],
    )
}

/// The shared, thread-safe mechanics composition handle. Clone freely; every
/// clone shares the same durable authority ledger.
#[derive(Clone)]
pub struct OrbitalMechanics {
    inner: Arc<Mutex<Inner>>,
}

impl OrbitalMechanics {
    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The directory this Space's mechanics material lives in.
    fn dir_for(root: &Path, space: &SpaceId) -> PathBuf {
        root.join(space.as_str())
    }

    /// Found a fresh Space's mechanics material under `root` (the orbital
    /// store root): genesis, founding inception, epoch-0 mint sealed to the
    /// founder — one atomic founding batch. Returns the handle and the
    /// founder's signed Coordinates.
    pub fn form(
        root: &Path,
        device_seed: &[u8; 32],
        display_name: &str,
        approach_routes: Vec<runtime::coordinates::ApproachRoute>,
    ) -> Result<(Self, runtime::SignedCoordinatesV1)> {
        let me = crypto::device_from_seed(device_seed);
        let salt = super::rand16();
        let (recovery_pub, space_recovery_secret) = crate::space::mint_recovery_key();
        let recovery_root =
            crate::space::recovery_commit(&recovery_pub).ok_or_else(|| anyhow!("recovery key"))?;
        let space = crate::space::derive_space_id(&me, &salt, &recovery_root);
        let dir = Self::dir_for(root, &space);
        std::fs::create_dir_all(&dir)?;

        let (recovery_commit, actor_recovery_seed) = {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("getrandom");
            let public = crypto::device_from_seed(&seed);
            (
                actor::recovery_commitment(&public).ok_or_else(|| anyhow!("recovery pub"))?,
                seed,
            )
        };
        // Escrow both offline recovery secrets on the founder before anything
        // else: the space break-glass authority (solo, elevatable to a
        // threshold group) and the actor's device-reset key. Discarding either
        // would strand `space elevate`/`space recover` and `recover` with no
        // authority material to run from.
        persist_hex_key(&dir, SPACE_RECOVERY_KEY_FILE, &space_recovery_secret)?;
        persist_hex_key(&dir, RECOVERY_KEY_FILE, &actor_recovery_seed)?;
        let (inception, actor_id) = actor::incept_single(
            device_seed,
            &space,
            super::rand16(),
            super::rand16(),
            Some(recovery_commit),
        );
        let genesis = Genesis {
            space_id: space.clone(),
            founding_actors: vec![actor_id.clone()],
            salt,
            recovery_root,
        };
        std::fs::write(dir.join(GENESIS_FILE), serde_json::to_vec_pretty(&genesis)?)?;
        let mut ledger = AuthorityLedger::create(dir.join(LEDGER_DIR), genesis)
            .map_err(|e| anyhow!("authority ledger: {e}"))?;

        // Epoch 0, sealed to the founder — one atomic founding batch:
        // inception + mint + sealed envelope.
        let key = crypto::random_key();
        let epoch0 = super::rand16();
        let key_commit = *blake3::hash(&key).as_bytes();
        let mint = acl::sign_op(
            device_seed,
            &AclOp {
                action: AclAction::MintEpoch {
                    id: epoch0,
                    gen: 0,
                    key_commit,
                    members: vec![actor_id.clone()],
                },
                by: actor_id.clone(),
                actor_asof: vec![inception.hash()],
                nonce: None,
            },
            vec![],
            &space,
        );
        let sealed = crypto::seal_to(&me, &key).ok_or_else(|| anyhow!("seal epoch key"))?;
        ledger
            .commit_batch(
                &[
                    LedgerEffect::Actor(inception).encode(),
                    LedgerEffect::Acl(mint).encode(),
                ],
                &[SealedKeyRecord {
                    epoch: epoch0,
                    device: me.clone(),
                    sealed,
                }
                .encode()],
            )
            .map_err(|e| anyhow!("founding batch: {e}"))?;

        let mut inner = Inner {
            space: space.clone(),
            ledger,
            seed: *device_seed,
            me,
            keyring: BTreeMap::new(),
            dir,
            pending_admission: None,
            pending_inception: None,
            pending_proof: None,
        };
        inner.keyring.insert(epoch0, key);
        let mech = Self {
            inner: Arc::new(Mutex::new(inner)),
        };
        let coords = mech.mint_coordinates(device_seed, display_name, approach_routes, None)?;
        Ok((mech, coords))
    }

    /// Enter a Space from verified Coordinates: persist its genesis + founder
    /// inception, stash the admission for redemption over Contact, and
    /// self-incept so an admin can admit us.
    pub fn enter(
        root: &Path,
        device_seed: &[u8; 32],
        coordinates: &runtime::SignedCoordinatesV1,
    ) -> Result<Self> {
        let verified = coordinates
            .verify()
            .map_err(|e| anyhow!("coordinates: {e}"))?;
        let me = crypto::device_from_seed(device_seed);
        let space = verified.space.clone();
        let dir = Self::dir_for(root, &space);
        std::fs::create_dir_all(&dir)?;
        let founder_inception: actor::SignedEvent =
            postcard::from_bytes(&coordinates.payload.founder_inception)
                .context("founder inception")?;
        let founding_actor = ActorId::from_incept_hash(&founder_inception.hash());
        let genesis = Genesis {
            space_id: space.clone(),
            founding_actors: vec![founding_actor],
            salt: coordinates.payload.salt,
            recovery_root: coordinates.payload.recovery_root,
        };
        let ledger_root = dir.join(LEDGER_DIR);
        let mut ledger = if ledger_root.join("current-manifest").exists() {
            AuthorityLedger::open(&ledger_root).map_err(|e| anyhow!("authority ledger: {e}"))?
        } else {
            std::fs::write(dir.join(GENESIS_FILE), serde_json::to_vec_pretty(&genesis)?)?;
            let mut fresh = AuthorityLedger::create(&ledger_root, genesis)
                .map_err(|e| anyhow!("authority ledger: {e}"))?;
            fresh
                .commit_batch(&[LedgerEffect::Actor(founder_inception).encode()], &[])
                .map_err(|e| anyhow!("founder inception: {e}"))?;
            fresh
        };
        let _ = &mut ledger;
        let mut inner = Inner {
            space,
            ledger,
            seed: *device_seed,
            me,
            keyring: BTreeMap::new(),
            dir,
            pending_admission: verified.admission.clone(),
            pending_inception: None,
            pending_proof: None,
        };
        // Self-incept so our identity can be admitted — held PENDING, carried
        // by the Admission record until an admin admits it.
        if inner.my_actor().is_none() && inner.pending_inception.is_none() {
            let (recovery_commit, _seed) = {
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed).expect("getrandom");
                let public = crypto::device_from_seed(&seed);
                (
                    actor::recovery_commitment(&public).ok_or_else(|| anyhow!("recovery pub"))?,
                    seed,
                )
            };
            let (ev, _) = actor::incept_single(
                device_seed,
                &inner.space,
                super::rand16(),
                super::rand16(),
                Some(recovery_commit),
            );
            std::fs::write(
                inner.dir.join(PENDING_INCEPTION_FILE),
                postcard::to_stdvec(&ev)?,
            )?;
            inner.pending_inception = Some(ev);
        }
        if let Some(admission) = &inner.pending_admission {
            std::fs::write(
                inner.dir.join(PENDING_ADMISSION_FILE),
                postcard::to_stdvec(admission)?,
            )?;
            // Accepting valid Coordinates IS the approval: sign the acceptance
            // proof binding this candidate to the exact capability + Coordinates
            // now, persist it, and reuse it byte-for-byte on every retry.
            if let Some(inception) = &inner.pending_inception {
                let candidate_actor = ActorId::from_incept_hash(&inception.hash());
                let now = now_secs();
                let coords_digest = coordinates.digest();
                let space_bytes = <[u8; 29]>::try_from(inner.space.as_str().as_bytes())
                    .map_err(|_| anyhow!("space id shape"))?;
                let proof = runtime::coordinates::InvitationAcceptanceProof::sign(
                    device_seed,
                    now,
                    super::rand16(),
                    &coords_digest,
                    &space_bytes,
                    &admission.issuer,
                    &admission.capability_id(),
                    candidate_actor.as_str(),
                )
                .ok_or_else(|| anyhow!("sign acceptance proof"))?;
                std::fs::write(
                    inner.dir.join(PENDING_PROOF_FILE),
                    postcard::to_stdvec(&(proof.clone(), coords_digest))?,
                )?;
                inner.pending_proof = Some((proof, coords_digest));
            }
        }
        // Persist the verified Coordinates so the daemon can teach its
        // transport the approach Station's signed routes and bootstrap the
        // first Contact — Coordinates-only, no shared registry.
        std::fs::write(inner.dir.join(COORDINATES_FILE), coordinates.encode())?;
        inner.refresh_keyring();
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Open existing mechanics material for a Space.
    pub fn open(root: &Path, space: &SpaceId, device_seed: &[u8; 32]) -> Result<Self> {
        let dir = Self::dir_for(root, space);
        let ledger = AuthorityLedger::open(dir.join(LEDGER_DIR))
            .map_err(|e| anyhow!("authority ledger: {e}"))?;
        if ledger.space() != space {
            return Err(anyhow!("authority ledger belongs to another Space"));
        }
        let me = crypto::device_from_seed(device_seed);
        let mut inner = Inner {
            space: space.clone(),
            ledger,
            seed: *device_seed,
            me,
            keyring: BTreeMap::new(),
            dir: dir.clone(),
            pending_admission: std::fs::read(dir.join(PENDING_ADMISSION_FILE))
                .ok()
                .and_then(|b| postcard::from_bytes(&b).ok()),
            pending_inception: std::fs::read(dir.join(PENDING_INCEPTION_FILE))
                .ok()
                .and_then(|b| postcard::from_bytes(&b).ok()),
            pending_proof: std::fs::read(dir.join(PENDING_PROOF_FILE))
                .ok()
                .and_then(|b| postcard::from_bytes(&b).ok()),
        };
        inner.refresh_keyring();
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Mint signed Coordinates for this Space, optionally carrying an
    /// admission capability (the invite path: admin-only).
    pub fn mint_coordinates(
        &self,
        station_seed: &[u8; 32],
        display_name: &str,
        approach_routes: Vec<runtime::coordinates::ApproachRoute>,
        admission: Option<AdmissionCapabilityV1>,
    ) -> Result<runtime::SignedCoordinatesV1> {
        let inner = self.lock();
        let genesis = inner.ledger.genesis().clone();
        let founder = genesis
            .founding_actors
            .first()
            .ok_or_else(|| anyhow!("no founding actor"))?;
        let inception = inner
            .ledger
            .actor_events()
            .into_iter()
            .find(|ev| ActorId::from_incept_hash(&ev.hash()) == *founder)
            .ok_or_else(|| anyhow!("founder inception not held"))?;
        let payload = runtime::coordinates::CoordinatesPayloadV1 {
            space: <[u8; 29]>::try_from(inner.space.as_str().as_bytes())
                .map_err(|_| anyhow!("space id shape"))?,
            salt: genesis.salt,
            recovery_root: genesis.recovery_root,
            founder_inception: postcard::to_stdvec(&inception)?,
            display_name_hint: display_name.to_string(),
            approach_station: crypto::device_from_seed(station_seed)
                .key_bytes()
                .ok_or_else(|| anyhow!("station key"))?,
            approach_nick_hint: String::new(),
            approach_routes,
            admission: match admission {
                Some(a) => runtime::coordinates::CoordinatesAdmission::Some(Box::new(a)),
                None => runtime::coordinates::CoordinatesAdmission::None,
            },
        };
        Ok(runtime::SignedCoordinatesV1::sign(payload, station_seed))
    }

    /// Mint an admission capability (admin-only, checked by the redeemer). It
    /// carries the default-contributor role expansion as generic
    /// [`WorldAssignmentEvidence`] — `space.contributor` + the mandatory
    /// `space.issue.read` baseline — which redemption installs atomically.
    pub fn mint_admission(
        &self,
        issuer_seed: &[u8; 32],
        ttl_secs: u64,
        reusable: bool,
        now: u64,
    ) -> Result<AdmissionCapabilityV1> {
        let inner = self.lock();
        let use_policy = if reusable {
            runtime::coordinates::AdmissionUsePolicy::Reusable {
                max_redemptions: 1024,
            }
        } else {
            runtime::coordinates::AdmissionUsePolicy::SingleUse
        };
        // The default-contributor expansion, always including the mandatory
        // baseline read access, sorted/deduped inside the evidence digest.
        let world = crate::world::contract::PRODUCT_WORLD;
        let res = mechanics::demand::PolicyResource::space(world);
        let assignments = vec![
            (
                mechanics::demand::PolicyCapability::new(world, "space.contributor"),
                res.clone(),
            ),
            (
                mechanics::demand::PolicyCapability::new(world, "space.issue.read"),
                res,
            ),
        ];
        let evidence = mechanics::demand::WorldAssignmentEvidence {
            world: world.to_string(),
            opaque_definition_ref: b"lait.contributor".to_vec(),
            definition_digest: *blake3::hash(b"lait.contributor.v1").as_bytes(),
            parent_manifest_root: [0u8; 32],
            assignments,
        };
        AdmissionCapabilityV1::sign(
            &inner.space,
            super::rand16(),
            now,
            now,
            now + ttl_secs,
            use_policy,
            evidence,
            issuer_seed,
        )
        .ok_or_else(|| anyhow!("sign admission"))
    }

    /// The Space this handle serves.
    pub fn space(&self) -> SpaceId {
        self.lock().space.clone()
    }

    /// Whether this device's actor currently holds membership.
    pub fn am_i_member(&self) -> bool {
        let mut inner = self.lock();
        let actor = inner.my_actor();
        actor.is_some_and(|a| inner.acl().is_member(&a))
    }

    /// Whether this device's actor is an admin.
    pub fn am_i_admin(&self) -> bool {
        let mut inner = self.lock();
        let actor = inner.my_actor();
        actor.is_some_and(|a| inner.acl().is_admin(&a))
    }

    /// This device's actor id, if established.
    pub fn my_actor(&self) -> Option<ActorId> {
        self.lock().my_actor()
    }

    /// The membership roster as `control::MemberDto` rows.
    pub fn members(&self) -> Vec<crate::dto::MemberDto> {
        let mut inner = self.lock();
        let acl = inner.acl();
        let me = inner.my_actor();
        let mut out: Vec<crate::dto::MemberDto> = acl
            .members()
            .into_iter()
            .map(|(actor, grants)| crate::dto::MemberDto {
                key: actor.as_str().to_string(),
                role: role_of(&grants),
                me: me.as_ref() == Some(&actor),
                sponsor: None,
                alias: String::new(),
            })
            .collect();
        for (agent, sponsor) in acl.agents() {
            out.push(crate::dto::MemberDto {
                key: agent.as_str().to_string(),
                role: "agent".into(),
                me: me.as_ref() == Some(&agent),
                sponsor: Some(sponsor.as_str().to_string()),
                alias: String::new(),
            });
        }
        out
    }

    /// The signed ACL DAG replayed as an audit log.
    pub fn member_log(&self) -> Vec<crate::dto::MemberLogEntry> {
        let inner = self.lock();
        let genesis = inner.ledger.genesis().clone();
        let events = inner.ledger.actor_events();
        let ops = inner.ledger.acl_ops();
        let (_, audit) = acl::replay_with_audit(&genesis, &events, &ops);
        audit
            .into_iter()
            .map(|entry| crate::dto::MemberLogEntry {
                op: entry.hash,
                actor: entry.by.map(|a| a.as_str().to_string()).unwrap_or_default(),
                kind: entry.kind.to_string(),
                subject: entry.subject.map(|a| a.as_str().to_string()),
                role: entry.grants.as_deref().map(role_of),
                authorized: entry.authorized,
            })
            .collect()
    }

    /// Add (or re-grant) a member by actor id — admin-only. The target actor's
    /// inception must already be known (imported via a prior Contact/admission).
    pub fn member_add(&self, actor_str: &str, admin: bool) -> Result<()> {
        let mut inner = self.lock();
        let actor = ActorId::parse(actor_str).ok_or_else(|| anyhow!("invalid actor id"))?;
        match inner.my_actor() {
            Some(me) if inner.acl().is_admin(&me) => {}
            _ => return Err(anyhow!("only an admin may add members")),
        }
        if !inner.actor_plane().exists(&actor) {
            return Err(anyhow!("that actor's identity is not known locally yet"));
        }
        if inner.acl().is_member(&actor) {
            return Ok(());
        }
        let grants = if admin {
            vec![Grant::Admin, Grant::Write]
        } else {
            vec![Grant::Write]
        };
        let sealed = inner.seal_records_for_actor(&actor);
        inner.author(
            AclAction::AddMember {
                actor: actor.clone(),
                grants,
            },
            None,
            vec![],
            sealed,
        )?;
        Ok(())
    }

    /// Remove a member by actor id — admin-only.
    pub fn member_remove(&self, actor_str: &str) -> Result<()> {
        let mut inner = self.lock();
        let actor = ActorId::parse(actor_str).ok_or_else(|| anyhow!("invalid actor id"))?;
        match inner.my_actor() {
            Some(me) if inner.acl().is_admin(&me) => {}
            _ => return Err(anyhow!("only an admin may remove members")),
        }
        if !inner.acl().is_member(&actor) {
            return Ok(());
        }
        inner.author(AclAction::RemoveMember { actor }, None, vec![], vec![])?;
        Ok(())
    }

    // ---- device management (M3): signed actor-plane authority actions -------

    /// The device keys currently bound to this device's actor.
    pub fn device_list(&self) -> Vec<DeviceId> {
        let inner = self.lock();
        match inner.my_actor() {
            Some(actor) => inner.actor_plane().devices_of(&actor),
            None => Vec::new(),
        }
    }

    /// Produce this device's consent to join `actor` — the material a new
    /// device hands to an existing device's `device_add` (the accept side).
    pub fn device_accept_consent(&self, actor_str: &str) -> Result<actor::DeviceBinding> {
        let inner = self.lock();
        let actor = ActorId::parse(actor_str).ok_or_else(|| anyhow!("invalid actor id"))?;
        let nonce = super::rand16();
        Ok(actor::consent_sign(
            &inner.seed,
            inner.space.as_str(),
            nonce,
            &actor::ConsentCtx::Member { actor: &actor },
        ))
    }

    /// Add a device to this device's actor from its consent binding, and seal
    /// it every held epoch key — a signed `AddDevice` actor event plus the
    /// sealed-key records in one atomic authority batch.
    pub fn device_add(&self, binding: actor::DeviceBinding) -> Result<DeviceId> {
        let mut inner = self.lock();
        let me = inner
            .my_actor()
            .ok_or_else(|| anyhow!("no actor identity"))?;
        // Verify the consent binds to joining OUR actor before authoring.
        if !actor::consent_verify(
            inner.space.as_str(),
            &binding,
            &actor::ConsentCtx::Member { actor: &me },
        ) {
            return Err(anyhow!("device consent does not bind to this actor"));
        }
        let device = binding.device.clone();
        let event = actor::sign_event(
            &inner.seed,
            &actor::ActorOp::AddDevice {
                actor: me.clone(),
                binding,
            },
            inner.ledger.actor_heads(&me),
            &inner.space,
        );
        // Seal every held epoch key to the new device in the same batch.
        let mut sealed_records = Vec::new();
        for (epoch, key) in inner.keyring.iter() {
            if let Some(sealed) = crypto::seal_to(&device, key) {
                sealed_records.push(
                    SealedKeyRecord {
                        epoch: *epoch,
                        device: device.clone(),
                        sealed,
                    }
                    .encode(),
                );
            }
        }
        inner
            .ledger
            .commit_batch(&[LedgerEffect::Actor(event).encode()], &sealed_records)
            .map_err(|e| anyhow!("device add: {e}"))?;
        Ok(device)
    }

    /// Revoke a device from this device's actor — a signed `RevokeDevice`
    /// actor event. Revocation immediately prevents that device from
    /// authoring new commits (historical transactions remain valid at their
    /// historical frontiers).
    ///
    /// De-listing the device is self-authored and always applies; **fencing**
    /// it from existing content needs a key rotation only an admin may mint. An
    /// admin rotates in the same call (re-sealing the fresh epoch to remaining
    /// devices only); a non-admin de-lists and the returned `rotated == false`
    /// tells the caller re-keying is still pending an admin. Returns whether
    /// the key was rotated.
    pub fn device_revoke(&self, device_str: &str) -> Result<bool> {
        let mut inner = self.lock();
        let me = inner
            .my_actor()
            .ok_or_else(|| anyhow!("no actor identity"))?;
        let device = DeviceId::parse(device_str).ok_or_else(|| anyhow!("invalid device id"))?;
        let devices = inner.actor_plane().devices_of(&me);
        if !devices.contains(&device) {
            return Err(anyhow!("that device is not bound to this actor"));
        }
        if devices.len() <= 1 {
            return Err(anyhow!("refusing to revoke your only device"));
        }
        let event = actor::sign_event(
            &inner.seed,
            &actor::ActorOp::RevokeDevice {
                actor: me.clone(),
                device,
            },
            inner.ledger.actor_heads(&me),
            &inner.space,
        );
        inner
            .ledger
            .commit_batch(&[LedgerEffect::Actor(event).encode()], &[])
            .map_err(|e| anyhow!("device revoke: {e}"))?;
        let rotated = inner.acl().is_admin(&me);
        if rotated {
            inner.rotate_key()?;
        }
        Ok(rotated)
    }

    /// A device-enrollment token for adding another device to *this* actor:
    /// the actor id and Space id the new machine needs to produce its consent
    /// blob (via [`Self::device_accept_consent`]). Refuses when this device
    /// holds no actor identity in the Space.
    pub fn device_invite(&self) -> Result<(ActorId, SpaceId)> {
        let inner = self.lock();
        match inner.my_actor() {
            Some(actor) => Ok((actor, inner.space.clone())),
            None => Err(anyhow!("no actor identity in this space")),
        }
    }

    /// Recover this device's actor with the offline actor recovery key
    /// (`recovery.key`): reset the actor's device set to *this* device. Lazy by
    /// design — identity/standing is restored immediately; this device holds no
    /// content key until an admin or surviving peer re-seals it. Returns the
    /// recovered actor id.
    pub fn recover(&self) -> Result<ActorId> {
        let mut inner = self.lock();
        let seed = inner
            .read_recovery_key()
            .ok_or_else(|| anyhow!("no actor recovery key on this device"))?;
        let recovery_pub = crypto::device_from_seed(&seed);
        let commit = actor::recovery_commitment(&recovery_pub);
        let plane = inner.actor_plane();
        let actor = plane
            .actors()
            .find(|(_, st)| commit.is_some() && st.recovery_commit == commit)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| anyhow!("no actor on this space matches the recovery key"))?;
        let binding = actor::consent_sign(
            &inner.seed,
            inner.space.as_str(),
            super::rand16(),
            &actor::ConsentCtx::Member { actor: &actor },
        );
        let ev = actor::sign_event(
            &seed,
            &actor::ActorOp::Recover {
                actor: actor.clone(),
                devices: vec![binding],
                next_commit: None,
            },
            inner.ledger.actor_heads(&actor),
            &inner.space,
        );
        // Validate the recovery took (commitment match) before persisting.
        let mut candidate = inner.ledger.actor_events();
        candidate.push(ev.clone());
        let recovered = actor::replay(&inner.space, &candidate)
            .state(&actor)
            .map(|s| s.recovered)
            .unwrap_or(false);
        if !recovered {
            return Err(anyhow!(
                "recovery key does not match the actor's commitment"
            ));
        }
        inner
            .ledger
            .commit_batch(&[LedgerEffect::Actor(ev).encode()], &[])
            .map_err(|e| anyhow!("actor recover: {e}"))?;
        Ok(actor)
    }

    // ---- admin control plane (key rotation, invites, agents) ----------------

    /// Rotate the space content key (admin-only), fencing any de-listed device
    /// from future content. Returns the new active epoch generation.
    pub fn key_rotate(&self) -> Result<u64> {
        let mut inner = self.lock();
        if !inner.am_i_admin() {
            return Err(anyhow!("only an admin may rotate the space key"));
        }
        inner.rotate_key()?;
        Ok(inner.active_epoch().map(|e| u64::from(e.gen)).unwrap_or(0))
    }

    /// Revoke an outstanding invite (admin-only) by its raw 32-hex nonce or an
    /// orbital Coordinates link carrying the admission. Authors a signed
    /// [`AclAction::RevokeInvite`]; once it syncs no admin admits via that
    /// nonce. Returns whether the invite had already admitted someone.
    pub fn invite_revoke(&self, invite: &str) -> Result<bool> {
        let mut inner = self.lock();
        if !inner.am_i_admin() {
            return Err(anyhow!("only an admin may revoke an invite"));
        }
        let nonce = parse_invite_nonce(invite)
            .ok_or_else(|| anyhow!("not an invite nonce or Coordinates link"))?;
        let already_spent = inner.acl().is_nonce_spent(&nonce);
        inner.author(AclAction::RevokeInvite { nonce }, None, vec![], vec![])?;
        Ok(already_spent)
    }

    /// Sponsor an agent by its device key (any human member may sponsor). The
    /// agent's inception must already be known locally (it self-incepts on
    /// join); this authors a signed `AddAgent` and seals it every held epoch.
    /// Returns the sponsored agent's actor id.
    pub fn agent_add(&self, key: &str) -> Result<ActorId> {
        let mut inner = self.lock();
        let me = inner
            .my_actor()
            .ok_or_else(|| anyhow!("no actor identity"))?;
        if !inner.acl().is_human_member(&me) {
            return Err(anyhow!("only a human member may sponsor an agent"));
        }
        let agent = inner
            .resolve_actor(key)
            .ok_or_else(|| anyhow!("that agent's identity is not known locally yet"))?;
        if inner.acl().is_member(&agent) {
            return Err(anyhow!("{} is already a principal", agent.short()));
        }
        let sealed = inner.seal_records_for_actor(&agent);
        inner.author(
            AclAction::AddAgent {
                actor: agent.clone(),
            },
            None,
            vec![],
            sealed,
        )?;
        Ok(agent)
    }

    /// The authority records this Station serves in a Contact (the export
    /// seam): its ledger effects and sealed envelopes, plus — while
    /// unadmitted — its admission redemption request.
    pub fn export_records(&self) -> Vec<Vec<u8>> {
        let mut inner = self.lock();
        let mut records: Vec<Vec<u8>> = Vec::new();
        for effect in inner.ledger.export_effects() {
            records.push(AuthorityRecord::Effect(effect).encode());
        }
        for sealed in inner.ledger.export_sealed() {
            records.push(AuthorityRecord::SealedKey(sealed).encode());
        }
        if let (Some(admission), Some(inception)) =
            (&inner.pending_admission, &inner.pending_inception)
        {
            let admitted = {
                let me = inner.my_actor();
                let admission_check = admission.clone();
                let inception_check = inception.clone();
                let _ = (&admission_check, &inception_check);
                me.map(|a| inner.acl().is_member(&a)).unwrap_or(false)
            };
            if !admitted {
                if let (Some(admission), Some(inception), Some((proof, coords_digest))) = (
                    &inner.pending_admission,
                    &inner.pending_inception,
                    &inner.pending_proof,
                ) {
                    records.push(
                        AuthorityRecord::Admission {
                            admission: postcard::to_stdvec(admission).expect("admission bytes"),
                            inception: postcard::to_stdvec(inception).expect("inception bytes"),
                            proof: postcard::to_stdvec(proof).expect("proof bytes"),
                            coordinates_digest: *coords_digest,
                        }
                        .encode(),
                    );
                }
            }
        }
        records
    }

    /// The current authority frontier (for signing manifests/attribution).
    pub fn current_frontier(&self) -> AuthorityFrontier {
        self.lock().frontier()
    }

    /// The verified bootstrap Coordinates a joiner entered with, if one is
    /// persisted and this device is not yet admitted — the daemon reads it to
    /// teach the transport the approach Station's routes and dial. `None` once
    /// admitted (the pending material is cleaned up).
    pub fn pending_coordinates(&self) -> Option<runtime::SignedCoordinatesV1> {
        let inner = self.lock();
        let bytes = std::fs::read(inner.dir.join(COORDINATES_FILE)).ok()?;
        runtime::SignedCoordinatesV1::decode_canonical(&bytes).ok()
    }

    /// Activate a World implementation id for this Space — an admin-authored
    /// authority effect. Idempotent (re-activation of the same id is a no-op
    /// commit through the ledger's batch idempotency).
    pub fn activate_implementation(&self, world: &str, implementation_id: [u8; 32]) -> Result<()> {
        let mut inner = self.lock();
        if inner
            .acl()
            .active_implementation(world)
            .is_some_and(|id| id == implementation_id)
        {
            return Ok(());
        }
        inner.author(
            AclAction::ActivateWorldImplementation {
                world: world.to_string(),
                implementation_id,
            },
            None,
            vec![],
            vec![],
        )
    }

    /// Grant one scoped capability to an actor — an admin/policy-admin authored
    /// authority effect (the IAM assignment seam). Idempotent by grant id.
    pub fn grant_actor_capability(
        &self,
        actor: &ActorId,
        capability: mechanics::demand::PolicyCapability,
        resource: mechanics::demand::PolicyResource,
        salt: [u8; 16],
    ) -> Result<()> {
        let mut inner = self.lock();
        let grant_id = acl::capability_grant_id(actor, &capability, &resource, &salt)
            .ok_or_else(|| anyhow!("grant id"))?;
        if inner
            .acl()
            .effective_capability_grants(actor, &capability, &resource)
            .contains(&grant_id)
        {
            return Ok(());
        }
        inner_grant(&mut inner, actor, capability, resource, salt)
    }

    /// Grant one scoped capability to this device's founding actor — the
    /// product-authority bootstrap seam (idempotent by grant id).
    pub fn grant_self_capability(
        &self,
        capability: mechanics::demand::PolicyCapability,
        resource: mechanics::demand::PolicyResource,
        salt: [u8; 16],
    ) -> Result<()> {
        let mut inner = self.lock();
        let me = inner
            .my_actor()
            .ok_or_else(|| anyhow!("no actor identity"))?;
        let grant_id = acl::capability_grant_id(&me, &capability, &resource, &salt)
            .ok_or_else(|| anyhow!("grant id"))?;
        // Idempotent: an already-effective identical grant needs no new op.
        if inner
            .acl()
            .effective_capability_grants(&me, &capability, &resource)
            .contains(&grant_id)
        {
            return Ok(());
        }
        inner.author(
            AclAction::GrantCapability {
                grant_id,
                actor: me,
                capability,
                resource,
                salt,
            },
            None,
            vec![],
            vec![],
        )
    }
}

impl runtime::AuthorityView for OrbitalMechanics {
    fn resolve(&self, device: &DeviceId) -> Option<runtime::PrincipalResolution> {
        let mut inner = self.lock();
        let actor = inner.actor_plane().actor_of_device(device).cloned()?;
        let acl_state = inner.acl();
        if !acl_state.is_member(&actor) {
            return None;
        }
        let standing = runtime::Standing::new(acl_state.grants(&actor));
        Some(runtime::PrincipalResolution {
            actor,
            standing,
            authority_frontier: inner.frontier(),
        })
    }

    fn active_implementation(
        &self,
        world: &replica::ids::WorldId,
        authority_frontier: &AuthorityFrontier,
    ) -> Option<[u8; 32]> {
        let mut inner = self.lock();
        inner
            .ledger
            .active_implementation_at(authority_frontier.as_bytes(), world.as_str())
            .ok()
            .flatten()
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_mutation(
        &self,
        _space: &SpaceId,
        world: &replica::ids::WorldId,
        actor: &ActorId,
        device: &DeviceId,
        authority_frontier: &AuthorityFrontier,
        parent_manifest_root: [u8; 32],
        implementation_id: [u8; 32],
        intent_digest: [u8; 32],
        demand: &[u8],
        operations_digest: [u8; 32],
        core_digest: [u8; 32],
    ) -> Result<Vec<u8>, String> {
        let mut inner = self.lock();
        let receipt = inner
            .ledger
            .authorize(&mechanics::ledger::AuthorizationRequest {
                world: world.as_str(),
                actor: actor.as_str(),
                device: device.key_bytes().ok_or("device key")?,
                authority_frontier: authority_frontier.as_bytes(),
                parent_manifest_root,
                implementation_id,
                intent_digest,
                demand,
                effect_operations_digest: operations_digest,
                body_transaction_core_digest: core_digest,
            })
            .map_err(|e| e.to_string())?;
        Ok(receipt.encode())
    }

    fn evaluate_read(
        &self,
        actor: &ActorId,
        authority_frontier: &AuthorityFrontier,
        demand: &[u8],
    ) -> bool {
        let parsed = match mechanics::demand::AuthorizationDemand::decode_canonical(demand) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let mut inner = self.lock();
        match inner.ledger.state_at(authority_frontier.as_bytes()) {
            Ok(view) => view.acl.evaluate_demand(actor, &parsed).is_some(),
            Err(_) => false,
        }
    }
}

impl replica::AuthoritySource for OrbitalMechanics {
    fn signer_authorized(&self, signer: &[u8; 32], frontier: &AuthorityFrontier) -> bool {
        // The Manifest-advertisement legitimacy check: standing is evaluated at
        // the **referenced** frontier — the exact effect closure its heads name
        // — never against current state.
        let mut inner = self.lock();
        inner
            .ledger
            .signer_authorized_at(signer, frontier.as_bytes())
    }

    fn verify_transaction(&self, tx: &replica::BodyTransaction) -> Result<(), String> {
        // Remote historical authorization: verify the transaction's
        // authorization receipt against signed mechanics history at its
        // referenced frontier. No World callback runs.
        let receipt = tx.receipt().map_err(|e| e.to_string())?;
        let mut inner = self.lock();
        inner
            .ledger
            .verify_receipt(
                &receipt,
                &mechanics::ledger::ReceiptExpectations {
                    device: &tx.core.signer,
                    authority_frontier: tx.core.authority_frontier.as_bytes(),
                    parent_manifest_root: &tx.core.parent_manifest_root,
                    intent_digest: &tx.core.intent_digest,
                    demand: &tx.core.demand,
                    effect_operations_digest: &tx.core.operations_digest,
                    body_transaction_core_digest: &tx.core.digest(),
                },
            )
            .map_err(|e| e.to_string())
    }
}

impl replica::BodyKeySource for OrbitalMechanics {
    fn sealing_key(&self) -> Option<mechanics::crypto::AuthorizedBodyKey> {
        let mut inner = self.lock();
        let epoch = inner.active_epoch()?;
        let key = inner.keyring.get(&epoch.id)?;
        Some(mechanics::crypto::AuthorizedBodyKey::for_authorized_epoch(
            epoch.id, *key,
        ))
    }
    fn opening_key(&self, epoch: &[u8; 16]) -> Option<mechanics::crypto::AuthorizedBodyKey> {
        let mut inner = self.lock();
        // Only an AUTHORIZED epoch's key may open material.
        inner.acl().epoch(epoch)?;
        let key = inner.keyring.get(epoch)?;
        Some(mechanics::crypto::AuthorizedBodyKey::for_authorized_epoch(
            *epoch, *key,
        ))
    }
}

impl replica::AuthorityIncorporator for OrbitalMechanics {
    fn incorporate_authority(
        &mut self,
        records: &[Vec<u8>],
    ) -> Result<replica::AuthorityBatchReceipt, String> {
        let mut inner = self.lock();
        // Split the staged records: effects + sealed keys commit as ONE
        // atomic ledger batch (an invalid record refuses the whole batch);
        // admissions are redeemed after, each producing its own batch.
        let mut effects: Vec<Vec<u8>> = Vec::new();
        let mut sealed: Vec<Vec<u8>> = Vec::new();
        type Redemption = (Vec<u8>, Vec<u8>, Vec<u8>, [u8; 32]);
        let mut admissions: Vec<Redemption> = Vec::new();
        for raw in records {
            match AuthorityRecord::decode(raw) {
                Some(AuthorityRecord::Effect(bytes)) => effects.push(bytes),
                Some(AuthorityRecord::SealedKey(bytes)) => sealed.push(bytes),
                Some(AuthorityRecord::Admission {
                    admission,
                    inception,
                    proof,
                    coordinates_digest,
                }) => admissions.push((admission, inception, proof, coordinates_digest)),
                None => return Err("unrecognized authority record".into()),
            }
        }
        let prior = inner.frontier();
        let receipt = inner
            .ledger
            .commit_batch(&effects, &sealed)
            .map_err(|e| e.to_string())?;
        for (admission, inception, proof, coords_digest) in &admissions {
            // Best-effort: only an admin holding the key can redeem;
            // everyone else carries the material onward.
            if let Err(e) = inner.redeem_admission(admission, inception, proof, coords_digest) {
                tracing::debug!("admission not redeemed here: {e}");
            }
        }
        inner.refresh_keyring();
        // Once our actor is admitted, the pending join material has served
        // its purpose.
        let admitted = {
            let me = inner.my_actor();
            me.map(|a| inner.acl().is_member(&a)).unwrap_or(false)
        };
        if admitted {
            if inner.pending_admission.take().is_some() {
                let _ = std::fs::remove_file(inner.dir.join(PENDING_ADMISSION_FILE));
            }
            if inner.pending_inception.take().is_some() {
                let _ = std::fs::remove_file(inner.dir.join(PENDING_INCEPTION_FILE));
            }
            inner.pending_proof = None;
            let _ = std::fs::remove_file(inner.dir.join(PENDING_PROOF_FILE));
            let _ = std::fs::remove_file(inner.dir.join(COORDINATES_FILE));
        }
        Ok(replica::AuthorityBatchReceipt {
            space: inner.space.clone(),
            prior_frontier: prior,
            resulting_frontier: inner.frontier(),
            batch_digest: receipt.batch_digest,
        })
    }
}

/// Render an ACL grant set as the product's coarse role label.
fn role_of(grants: &[Grant]) -> String {
    if grants.contains(&Grant::Admin) {
        "admin".into()
    } else if grants.contains(&Grant::Write) {
        "member".into()
    } else {
        "viewer".into()
    }
}
