//! The product's mechanics composition for the orbital plane (C5).
//!
//! `OrbitalMechanics` owns the Space's **signed authority material** — the
//! genesis and the mechanics membership document (actor inceptions, signed ACL
//! ops, sealed key-epoch envelopes) — persisted beside the orbital store, and
//! implements every seam the runtime consumes:
//!
//! - [`runtime::AuthorityView`]: device → actor/standing/authority frontier,
//!   re-resolved per request from deterministic ACL replay;
//! - [`replica::AuthoritySource`]: signer standing for retained/incorporated
//!   material (replayed against the full current signed history — the
//!   monotonicity of the signed DAG stands in for per-frontier replay);
//! - [`replica::BodyKeySource`]: authorized key epochs from the sealed
//!   envelopes, opened with this device's seed, bound to the signed mint's
//!   key commitment — the existing construction, no new cryptography;
//! - [`replica::AuthorityIncorporator`] + the authority export: membership
//!   material and admission redemptions ride Contact's authority records —
//!   the explicit first durable Convergence phase.
//!
//! Formation mints the founding material exactly as the legacy path did
//! (self-certifying SpaceId over founder device + salt + recovery root,
//! founding inception, epoch-0 mint sealed to the founder); entry verifies
//! Coordinates offline and establishes standing by having its inception (and
//! any admission capability) pulled by an admin over Contact, whose
//! incorporator validates and redeems it (AddMember + epoch sealing).

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
use crate::membership::MembershipDoc;
use replica::frontier::AuthorityFrontier;
use runtime::coordinates::AdmissionCapabilityV1;

const MEMBERSHIP_FILE: &str = "mech-membership.loro";
const GENESIS_FILE: &str = "mech-genesis.json";
const PENDING_INCEPTION_FILE: &str = "mech-pending-inception.bin";
const PENDING_ADMISSION_FILE: &str = "mech-pending-admission.bin";

/// One authority-record unit riding Contact's authority section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorityRecord {
    /// A full membership-document export (Loro snapshot); import is
    /// idempotent and convergent.
    Membership(Vec<u8>),
    /// A joiner's admission redemption: the admin-signed capability plus the
    /// joiner's canonical inception bytes. An admin incorporator validates
    /// and redeems it (AddMember + epoch sealing); everyone else retains the
    /// membership material it rides beside.
    Admission {
        admission: Vec<u8>,
        inception: Vec<u8>,
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

struct Inner {
    space: SpaceId,
    genesis: Genesis,
    membership: MembershipDoc,
    seed: [u8; 32],
    me: DeviceId,
    keyring: BTreeMap<[u8; 16], SpaceKey>,
    dir: PathBuf,
    /// A joiner's own admission, served until standing is established.
    pending_admission: Option<AdmissionCapabilityV1>,
    /// A joiner's self-inception, held OUT of the membership doc until the
    /// founder's containers have been imported (writing into a bare doc would
    /// mint conflicting containers the import then shadows — the legacy
    /// joiner trap). It rides the Admission record; the signed AddMember path
    /// brings it back into the doc.
    pending_inception: Option<actor::SignedEvent>,
}

impl Inner {
    fn acl(&self) -> AclState {
        acl::replay(
            &self.genesis,
            &self.membership.actor_events(),
            &self.membership.ops(),
        )
    }

    fn actor_plane(&self) -> actor::ActorPlane {
        actor::replay(&self.space, &self.membership.actor_events())
    }

    fn my_actor(&self) -> Option<ActorId> {
        self.actor_plane().actor_of_device(&self.me).cloned()
    }

    fn frontier(&self) -> AuthorityFrontier {
        AuthorityFrontier::from_canonical_bytes(self.membership.head_bytes())
    }

    fn persist(&self) -> Result<()> {
        let bytes = self.membership.snapshot()?;
        let tmp = self.dir.join(format!("{MEMBERSHIP_FILE}.tmp"));
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, self.dir.join(MEMBERSHIP_FILE))?;
        Ok(())
    }

    /// Unseal every authorized epoch key addressed to this device, bound to
    /// the signed mint's commitment.
    fn refresh_keyring(&mut self) {
        for e in self.acl().epochs() {
            if self.keyring.contains_key(&e.id) {
                continue;
            }
            if let Some(sealed) = self.membership.get_sealed(&e.id, &self.me) {
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

    /// The deterministic active epoch: highest authorized `(gen, id)`.
    fn active_epoch(&self) -> Option<acl::EpochAuth> {
        self.acl()
            .epochs()
            .into_iter()
            .max_by(|a, b| a.gen.cmp(&b.gen).then_with(|| a.id.cmp(&b.id)))
    }

    /// Seal every held epoch key to every device of `actor`.
    fn seal_epochs_to_actor(&mut self, target: &ActorId) -> Result<()> {
        let devices = self.actor_plane().devices_of(target);
        let epochs: Vec<([u8; 16], SpaceKey)> =
            self.keyring.iter().map(|(e, k)| (*e, *k)).collect();
        for (epoch, key) in epochs {
            for d in &devices {
                if let Some(sealed) = crypto::seal_to(d, &key) {
                    self.membership.put_sealed(&epoch, d, &sealed)?;
                }
            }
        }
        Ok(())
    }

    /// Author + apply one signed ACL op as this device's actor.
    fn author(&mut self, action: AclAction, nonce: Option<[u8; 16]>, kind: &str) -> Result<()> {
        let me = self
            .my_actor()
            .ok_or_else(|| anyhow!("no actor identity"))?;
        let op = acl::sign_op(
            &self.seed,
            &AclOp {
                action,
                by: me.clone(),
                actor_asof: self.membership.actor_heads(&me),
                nonce,
            },
            self.membership.heads(),
            &self.space,
        );
        self.membership.add_op(&op)?;
        self.membership
            .apply(&fabric::op::OpCtx::authority(kind, &self.me));
        self.persist()?;
        Ok(())
    }

    /// The admin-side admission redemption (the orbital heir of the legacy
    /// `redeem_invite`): validate the capability and the joiner's inception,
    /// then admit + seal.
    fn redeem_admission(&mut self, admission_bytes: &[u8], inception_bytes: &[u8]) -> Result<()> {
        let admission: AdmissionCapabilityV1 =
            postcard::from_bytes(admission_bytes).context("admission decode")?;
        admission
            .verify_structure(&self.space)
            .map_err(|e| anyhow!("admission: {e}"))?;
        let inception: actor::SignedEvent =
            postcard::from_bytes(inception_bytes).context("inception decode")?;
        let joiner_actor = ActorId::from_incept_hash(&inception.hash());
        // The inception must cleanly incept for THIS space.
        let mut candidate = self.membership.actor_events();
        candidate.push(inception.clone());
        if !actor::replay(&self.space, &candidate).exists(&joiner_actor) {
            return Err(anyhow!("invalid joiner inception"));
        }
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
        if admission.single_use && acl_state.is_nonce_spent(&admission.nonce) {
            return Err(anyhow!("admission already redeemed"));
        }
        if acl_state.is_member(&joiner_actor) {
            return Ok(()); // idempotent
        }
        self.membership.add_actor_event(&inception)?;
        let nonce = admission.single_use.then_some(admission.nonce);
        self.author(
            AclAction::AddMember {
                actor: joiner_actor.clone(),
                grants: vec![Grant::Write],
            },
            nonce,
            "invite_redeem",
        )?;
        self.seal_epochs_to_actor(&joiner_actor)?;
        self.persist()?;
        Ok(())
    }
}

/// The shared, thread-safe mechanics composition handle. Clone freely; every
/// clone shares the same durable membership state.
#[derive(Clone)]
pub struct OrbitalMechanics {
    inner: Arc<Mutex<Inner>>,
}

impl OrbitalMechanics {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The directory this Space's mechanics material lives in.
    fn dir_for(root: &Path, space: &SpaceId) -> PathBuf {
        root.join(space.as_str())
    }

    /// Found a fresh Space's mechanics material under `root` (the orbital
    /// store root): genesis, founding inception, epoch-0 mint sealed to the
    /// founder. Returns the handle and the founder's signed Coordinates.
    pub fn form(
        root: &Path,
        device_seed: &[u8; 32],
        display_name: &str,
        approach_addrs: Vec<runtime::coordinates::ApproachAddr>,
    ) -> Result<(Self, runtime::SignedCoordinatesV1)> {
        let me = crypto::device_from_seed(device_seed);
        let salt = super::rand16();
        let (recovery_pub, _recovery_secret) = crate::space::mint_recovery_key();
        let recovery_root =
            crate::space::recovery_commit(&recovery_pub).ok_or_else(|| anyhow!("recovery key"))?;
        let space = crate::space::derive_space_id(&me, &salt, &recovery_root);
        let dir = Self::dir_for(root, &space);
        std::fs::create_dir_all(&dir)?;

        let (recovery_commit, _recovery_seed) = {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("getrandom");
            let public = crypto::device_from_seed(&seed);
            (
                actor::recovery_commitment(&public).ok_or_else(|| anyhow!("recovery pub"))?,
                seed,
            )
        };
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
        let membership = MembershipDoc::create(&space, None, &me)?;
        membership.add_actor_event(&inception)?;
        // Epoch 0, sealed to the founder.
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
            membership.heads(),
            &space,
        );
        membership.add_op(&mint)?;
        if let Some(sealed) = crypto::seal_to(&me, &key) {
            membership.put_sealed(&epoch0, &me, &sealed)?;
        }
        membership.apply(&fabric::op::OpCtx::authority("found", &me));

        let mut inner = Inner {
            space: space.clone(),
            genesis,
            membership,
            seed: *device_seed,
            me,
            keyring: BTreeMap::new(),
            dir,
            pending_admission: None,
            pending_inception: None,
        };
        inner.keyring.insert(epoch0, key);
        inner.persist()?;
        let mech = Self {
            inner: Arc::new(Mutex::new(inner)),
        };
        let coords = mech.mint_coordinates(device_seed, display_name, approach_addrs, None)?;
        Ok((mech, coords))
    }

    /// Enter a Space from verified Coordinates: persist its genesis + founder
    /// inception (empty membership otherwise), stash the admission for
    /// redemption over Contact, and self-incept so an admin can admit us.
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
        let (membership, fresh) = match std::fs::read(dir.join(MEMBERSHIP_FILE)) {
            Ok(bytes) => (MembershipDoc::from_snapshot(&bytes, None)?, false),
            Err(_) => (MembershipDoc::empty(None), true),
        };
        if fresh {
            std::fs::write(dir.join(GENESIS_FILE), serde_json::to_vec_pretty(&genesis)?)?;
            membership.add_actor_event(&founder_inception)?;
            membership.apply(&fabric::op::OpCtx::authority("join", &me));
        }
        let mut inner = Inner {
            space,
            genesis,
            membership,
            seed: *device_seed,
            me,
            keyring: BTreeMap::new(),
            dir,
            pending_admission: verified.admission.clone(),
            pending_inception: None,
        };
        // Self-incept so our identity can be admitted — held PENDING, never
        // written into the pre-import doc (container adoption).
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
        }
        inner.refresh_keyring();
        inner.persist()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Open existing mechanics material for a Space.
    pub fn open(root: &Path, space: &SpaceId, device_seed: &[u8; 32]) -> Result<Self> {
        let dir = Self::dir_for(root, space);
        let genesis: Genesis = serde_json::from_slice(&std::fs::read(dir.join(GENESIS_FILE))?)
            .context("mechanics genesis")?;
        let membership =
            MembershipDoc::from_snapshot(&std::fs::read(dir.join(MEMBERSHIP_FILE))?, None)?;
        let me = crypto::device_from_seed(device_seed);
        let mut inner = Inner {
            space: space.clone(),
            genesis,
            membership,
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
        approach_addrs: Vec<runtime::coordinates::ApproachAddr>,
        admission: Option<AdmissionCapabilityV1>,
    ) -> Result<runtime::SignedCoordinatesV1> {
        let inner = self.lock();
        let founder = inner
            .genesis
            .founding_actors
            .first()
            .ok_or_else(|| anyhow!("no founding actor"))?;
        let inception = inner
            .membership
            .actor_events()
            .into_iter()
            .find(|ev| ActorId::from_incept_hash(&ev.hash()) == *founder)
            .ok_or_else(|| anyhow!("founder inception not held"))?;
        let payload = runtime::coordinates::CoordinatesPayloadV1 {
            space: <[u8; 29]>::try_from(inner.space.as_str().as_bytes())
                .map_err(|_| anyhow!("space id shape"))?,
            salt: inner.genesis.salt,
            recovery_root: inner.genesis.recovery_root,
            founder_inception: postcard::to_stdvec(&inception)?,
            display_name_hint: display_name.to_string(),
            approach_station: crypto::device_from_seed(station_seed)
                .key_bytes()
                .ok_or_else(|| anyhow!("station key"))?,
            approach_nick_hint: String::new(),
            approach_addrs,
            admission: match admission {
                Some(a) => runtime::coordinates::CoordinatesAdmission::Some(a),
                None => runtime::coordinates::CoordinatesAdmission::None,
            },
        };
        Ok(runtime::SignedCoordinatesV1::sign(payload, station_seed))
    }

    /// Mint an admission capability (admin-only, checked by the redeemer).
    pub fn mint_admission(
        &self,
        issuer_seed: &[u8; 32],
        ttl_secs: u64,
        single_use: bool,
        now: u64,
    ) -> Result<AdmissionCapabilityV1> {
        let inner = self.lock();
        AdmissionCapabilityV1::sign(
            &inner.space,
            super::rand16(),
            now,
            now + ttl_secs,
            single_use,
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
        let inner = self.lock();
        inner.my_actor().is_some_and(|a| inner.acl().is_member(&a))
    }

    /// Whether this device's actor is an admin.
    pub fn am_i_admin(&self) -> bool {
        let inner = self.lock();
        inner.my_actor().is_some_and(|a| inner.acl().is_admin(&a))
    }

    /// This device's actor id, if established.
    pub fn my_actor(&self) -> Option<ActorId> {
        self.lock().my_actor()
    }

    /// The membership roster as `control::MemberDto` rows.
    pub fn members(&self) -> Vec<crate::dto::MemberDto> {
        let inner = self.lock();
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
        inner
            .membership
            .ops()
            .into_iter()
            .map(|signed| {
                let decoded: Option<AclOp> = postcard::from_bytes(&signed.op).ok();
                let actor = decoded
                    .as_ref()
                    .map(|o| o.by.as_str().to_string())
                    .unwrap_or_default();
                let (kind, subject, role) = match decoded.as_ref().map(|o| &o.action) {
                    Some(AclAction::AddMember { actor, grants }) => (
                        "add_member",
                        Some(actor.as_str().to_string()),
                        Some(role_of(grants)),
                    ),
                    Some(AclAction::RemoveMember { actor }) => {
                        ("remove_member", Some(actor.as_str().to_string()), None)
                    }
                    Some(AclAction::SetGrants { actor, grants }) => (
                        "set_grants",
                        Some(actor.as_str().to_string()),
                        Some(role_of(grants)),
                    ),
                    Some(AclAction::AddAgent { actor }) => {
                        ("add_agent", Some(actor.as_str().to_string()), None)
                    }
                    Some(AclAction::MintEpoch { .. }) => ("mint_epoch", None, None),
                    Some(AclAction::RevokeInvite { .. }) => ("revoke_invite", None, None),
                    None => ("unknown", None, None),
                };
                crate::dto::MemberLogEntry {
                    op: signed.hash(),
                    actor,
                    kind: kind.into(),
                    subject,
                    role,
                    authorized: decoded.is_some(),
                }
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
        inner.author(
            AclAction::AddMember {
                actor: actor.clone(),
                grants,
            },
            None,
            "member_add",
        )?;
        inner.seal_epochs_to_actor(&actor)?;
        inner.persist()?;
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
        inner.author(AclAction::RemoveMember { actor }, None, "member_remove")?;
        Ok(())
    }

    /// The authority records this Station serves in a Contact (the export
    /// seam): its membership material, plus — while unadmitted — its
    /// admission redemption request.
    pub fn export_records(&self) -> Vec<Vec<u8>> {
        let inner = self.lock();
        let mut records = Vec::new();
        if let Ok(snapshot) = inner.membership.snapshot() {
            records.push(AuthorityRecord::Membership(snapshot).encode());
        }
        if let (Some(admission), Some(inception)) =
            (&inner.pending_admission, &inner.pending_inception)
        {
            let admitted = inner
                .my_actor()
                .is_some_and(|me| inner.acl().is_member(&me));
            if !admitted {
                records.push(
                    AuthorityRecord::Admission {
                        admission: postcard::to_stdvec(admission).expect("admission bytes"),
                        inception: postcard::to_stdvec(inception).expect("inception bytes"),
                    }
                    .encode(),
                );
            }
        }
        records
    }

    /// The current authority frontier (for signing manifests/attribution).
    pub fn current_frontier(&self) -> AuthorityFrontier {
        self.lock().frontier()
    }
}

impl runtime::AuthorityView for OrbitalMechanics {
    fn resolve(&self, device: &DeviceId) -> Option<runtime::PrincipalResolution> {
        let inner = self.lock();
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
}

impl replica::AuthoritySource for OrbitalMechanics {
    fn signer_authorized(&self, signer: &[u8; 32], _frontier: &AuthorityFrontier) -> bool {
        let inner = self.lock();
        let device = DeviceId::from_key_bytes(signer);
        let plane = inner.actor_plane();
        let Some(actor) = plane.actor_of_device(&device) else {
            return false;
        };
        // Signed-history replay is monotone: a signer admitted at the
        // referenced frontier remains resolvable in the current replay (the
        // signed DAG never forgets an admission op), so current-replay
        // standing subsumes the historical check for retained material.
        inner.acl().can_write(actor)
    }
}

impl replica::BodyKeySource for OrbitalMechanics {
    fn sealing_key(&self) -> Option<mechanics::crypto::AuthorizedBodyKey> {
        let inner = self.lock();
        let epoch = inner.active_epoch()?;
        let key = inner.keyring.get(&epoch.id)?;
        Some(mechanics::crypto::AuthorizedBodyKey::for_authorized_epoch(
            epoch.id, *key,
        ))
    }
    fn opening_key(&self, epoch: &[u8; 16]) -> Option<mechanics::crypto::AuthorizedBodyKey> {
        let inner = self.lock();
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
    ) -> Result<replica::AuthorityReceipt, String> {
        let mut inner = self.lock();
        for raw in records {
            match AuthorityRecord::decode(raw) {
                Some(AuthorityRecord::Membership(snapshot)) => {
                    inner
                        .membership
                        .import(&snapshot)
                        .map_err(|e| format!("membership import: {e}"))?;
                }
                Some(AuthorityRecord::Admission {
                    admission,
                    inception,
                }) => {
                    // Best-effort: only an admin holding the key can redeem;
                    // everyone else carries the material onward.
                    if let Err(e) = inner.redeem_admission(&admission, &inception) {
                        tracing::debug!("admission not redeemed here: {e}");
                    }
                }
                None => return Err("unrecognized authority record".into()),
            }
        }
        inner.refresh_keyring();
        // Once our actor is admitted, the pending join material has served
        // its purpose.
        if inner
            .my_actor()
            .is_some_and(|me| inner.acl().is_member(&me))
        {
            if inner.pending_admission.take().is_some() {
                let _ = std::fs::remove_file(inner.dir.join(PENDING_ADMISSION_FILE));
            }
            if inner.pending_inception.take().is_some() {
                let _ = std::fs::remove_file(inner.dir.join(PENDING_INCEPTION_FILE));
            }
        }
        inner.persist().map_err(|e| e.to_string())?;
        Ok(replica::AuthorityReceipt {
            frontier: inner.frontier(),
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
