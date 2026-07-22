//! Generic ceremony orchestration owned by mechanics.
//!
//! This module owns the complete generic ceremony state machine — break-glass
//! recovery, FROST elevation, threshold signing, custody export/import, the
//! device-local artifact store, and the semantic result types — plus the
//! ceremony-material retention policy. Product layers supply only control
//! request/result adaptation; they never advance a transcript themselves.
//!
//! Ceremony material is a distinct journal class with its own bounded cursor;
//! only a transcript's one terminal `SpaceAuthority` effect ever enters an
//! authority frontier. Body-key policy stays outside: the engine calls an
//! injected epoch fence after a terminal install and never touches Body
//! encryption itself.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

use crate::dkg::{self, CeremonyOp, SignTarget};
use crate::ids::{ActorId, DeviceId, SpaceId};
use crate::ledger::AuthorityLedger;
use crate::space::{RootState, SignedSpaceEvent, SpaceOp};

/// Argon2 cost for a share package's passphrase slot.
///
/// Production always pays the real cost; the weak parameters are reachable only
/// from this crate's own test builds, never from a release binary.
#[cfg(not(test))]
fn custody_kdf_params() -> crate::custody::Argon2Params {
    crate::custody::Argon2Params::default()
}
#[cfg(test)]
fn custody_kdf_params() -> crate::custody::Argon2Params {
    crate::custody::Argon2Params {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    }
}

/// A random 16-byte value (nonces, salts).
fn rand16() -> [u8; 16] {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("getrandom");
    raw
}

/// Read a hex-encoded 32-byte secret (the offline recovery-key escrow format).
fn read_hex_key(path: &Path) -> Option<[u8; 32]> {
    let bytes = crate::secretfs::read_private(path).ok().flatten()?;
    let hex = String::from_utf8(bytes).ok()?;
    let raw = data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.trim().as_bytes())
        .ok()?;
    raw.as_slice().try_into().ok()
}

/// What a break-glass space recovery did.
///
/// The two arms are not success-and-failure: a group recovery that has not yet
/// gathered its threshold is a correct, expected outcome that the operator must
/// act on. Both are committed changes.
#[derive(Debug)]
pub enum SpaceRecovery {
    /// The re-root is installed and this device is the new root.
    Installed(SpaceRecovered),
    /// A signing ceremony is open and needs the other holders.
    Pending {
        session: crate::dkg::TranscriptId,
        /// A local step that did not complete *after* the request landed on the
        /// board. Carried rather than returned as an error: the request is
        /// durable and other holders can see it, so the change must still be
        /// announced even though this device's own contribution did not land.
        incomplete: Option<anyhow::Error>,
    },
}

/// A completed re-root.
#[derive(Debug)]
pub struct SpaceRecovered {
    pub root: ActorId,
    /// The re-root landed; this says whether the follow-on content re-key did.
    ///
    /// A failure here leaves the space re-rooted but still under the old key —
    /// a degraded state the operator must be told about and can retry. It is
    /// never reported as a plain error, because the re-root is already durable
    /// and an error would suppress its doorbell.
    pub rekey_failed: Option<anyhow::Error>,
}

/// A proposed K-of-N recovery arrangement.
///
/// The proposal is durable by the time this exists — that is what makes the
/// optional fields honest rather than sloppy. `grant_request` names the signing
/// transcript when the standing authority is a group and must authorize the
/// change; `incomplete` carries a step that did not finish after the proposal
/// was posted, which the operator needs to know without being told the whole
/// elevation failed.
#[derive(Debug)]
pub struct Elevation {
    pub k: u16,
    pub n: u16,
    pub proposal: crate::dkg::TranscriptId,
    pub grant_request: Option<crate::dkg::TranscriptId>,
    pub incomplete: Option<anyhow::Error>,
}

/// A holder co-signed an authorization for a proposed arrangement.
#[derive(Debug)]
pub struct ElevationApproved {
    pub k: u16,
    pub n: usize,
}

/// A share package written to disk and verified by reopening it.
///
/// `indispensable` and `outstanding` are the facts; which of the three notes a
/// custodian reads is derived from them at the adapter.
#[derive(Debug)]
pub struct CustodyExport {
    pub path: String,
    pub indispensable: bool,
    pub outstanding: usize,
}

/// A share restored from a portable package.
#[derive(Debug)]
pub struct CustodyImport {
    pub ceremony: crate::dkg::TranscriptId,
    /// The share is durable by the time this exists; this carries a follow-on
    /// step that did not complete.
    pub incomplete: Option<anyhow::Error>,
}

/// What one pass over the ceremony board accomplished.
///
/// Two kinds of failure come out of a pass, and they must not share a channel.
/// A per-transcript fault — a malformed package from one participant — is
/// isolated and logged, because propagating it would wedge membership sync
/// permanently on an already-persisted event. `install_incomplete` is the other
/// kind: *this* node installed something durable and the follow-on step failed.
/// That is our failure, it is not isolatable, and on the recovery path it is a
/// security claim, so it travels back to the caller.
#[derive(Debug, Default)]
pub struct CeremonyProgress {
    pub progressed: bool,
    pub install_incomplete: Option<anyhow::Error>,
}

/// A holder co-signed a pending recovery.
///
/// Co-signing can *be* the last signature: the threshold completes inside this
/// command, the re-root installs, and the re-key runs — so `incomplete` carries
/// a re-key failure for the same reason the recovery outcomes do. Without it a
/// holder would be told the recovery "installs once the threshold has
/// co-signed" at the exact moment it had installed unfenced.
#[derive(Debug)]
pub struct RecoveryApproved {
    pub roots: Vec<ActorId>,
    pub incomplete: Option<anyhow::Error>,
}

/// Persist the recovery secret beside the store. This is a root credential (the
/// pre-rotation escrow — losing it forfeits recovery, never space access),
/// so it is created **owner-only from the start** (never world-readable, even
/// for an instant) and any permission error is propagated, never swallowed.
/// The state of a device-local ceremony artifact.
///
/// Three states, not two: an artifact that is present but unreadable is neither
/// usable nor absent, and reporting it as absent would hide the loss of a
/// holder's recovery capability.
///
/// `Unreadable` keeps the **typed** cause rather than a rendered string. An
/// access-denied error, a corrupt file or a transient I/O fault must not be
/// diagnosed as "this belongs to another Windows account": that is one specific
/// cause among several, and guessing it sends an operator to the wrong remedy.
#[derive(Debug)]
pub enum ArtifactRead {
    Missing,
    Present(Vec<u8>),
    Unreadable(crate::secretfs::SecretError),
}

/// Why a recovery artifact could not be produced, for structured reporting.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum RecoveryArtifactFailure {
    /// Wrapped for a different Windows account or machine. The bytes are intact;
    /// this identity cannot open them.
    Undecryptable(String),
    /// Present but could not be read at all — permissions, corruption, I/O.
    Io(String),
}

/// What this device can say about recovery readiness.
///
/// Deliberately does NOT assert that recovery is possible. This node knows its
/// own custody and the arrangement's shape; it does not know whether other
/// holders still have their shares, and claiming they do would be the most
/// dangerous kind of reassurance — believed, unverifiable, and only disproved
/// during an actual emergency.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryStatus {
    /// Short form of the standing authority's key, or `None` when this device
    /// cannot attribute the standing key to any arrangement it has seen.
    pub authority: Option<String>,
    pub scheme: crate::authority::AuthorityScheme,
    /// Phase B reports the shape. Phase D will report policy branches and
    /// qualified-set readiness instead.
    pub k: u16,
    pub n: u16,
    pub local_custody: LocalCustodyState,
}

/// This device's standing as a custodian.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum LocalCustodyState {
    /// Not a holder — nothing is expected of this device.
    NotAHolder,
    /// Holding usable material.
    Ready,
    /// Expected to hold a share and does not.
    Missing,
    /// The share is present but cannot be produced.
    Unreadable(RecoveryArtifactFailure),
    /// Holding a share of an **indispensable** arrangement with no verified
    /// portable backup. Distinct from `Ready` because the share is usable today
    /// and unrecoverable tomorrow, and that difference is invisible until it
    /// matters.
    BackupUnverified,
}

/// A holder whose share exists on this device but cannot be used.
///
/// Structured rather than preformatted, so status, diagnosis and the CLI can
/// each render it as they see fit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DegradedRecoveryHolder {
    /// The DKG transcript whose share is unusable.
    pub transcript: String,
    pub reason: RecoveryArtifactFailure,
    /// `Some(true)` when this transcript IS the standing recovery authority,
    /// `None` when currency could not be established (the public-key package
    /// was itself unreadable).
    pub is_current_authority: Option<bool>,
}

/// The generic ceremony state machine over one Space's authority ledger and
/// device-local artifact store.
///
/// Borrows the ledger and an injected **epoch fence** — the Body-key policy a
/// composition supplies (mint a fresh key epoch when this device is an admin
/// holding none). The engine calls it after a terminal install; mechanics
/// itself never touches Body encryption.
pub struct CeremonyEngine<'a> {
    ledger: &'a mut AuthorityLedger,
    space: SpaceId,
    seed: [u8; 32],
    me: DeviceId,
    /// The Space's mechanics directory: `dkg/` artifacts and the offline
    /// `space-recovery.key` escrow live under it.
    dir: PathBuf,
    fence: &'a mut dyn FnMut(&mut AuthorityLedger) -> Result<()>,
}

impl<'a> CeremonyEngine<'a> {
    pub fn new(
        ledger: &'a mut AuthorityLedger,
        seed: [u8; 32],
        me: DeviceId,
        dir: PathBuf,
        fence: &'a mut dyn FnMut(&mut AuthorityLedger) -> Result<()>,
    ) -> Self {
        let space = ledger.space().clone();
        Self {
            ledger,
            space,
            seed,
            me,
            dir,
            fence,
        }
    }

    /// This device's actor identity in the Space, if established.
    fn my_actor(&self) -> Option<ActorId> {
        self.ledger.actor_plane().actor_of_device(&self.me).cloned()
    }

    /// Resolve an actor by its actor id or by one of its device keys.
    fn resolve_actor(&self, who: &str) -> Option<ActorId> {
        let who = who.trim();
        if let Some(actor) = ActorId::parse(who) {
            if self.ledger.actor_plane().exists(&actor) {
                return Some(actor);
            }
        }
        if let Some(device) = DeviceId::parse(who) {
            if let Some(actor) = self.ledger.actor_plane().actor_of_device(&device) {
                return Some(actor.clone());
            }
        }
        None
    }

    /// This device's offline **space** break-glass recovery secret, if it holds
    /// the solo authority. `None` once elevated to a threshold group key.
    fn read_space_recovery_key(&self) -> Option<[u8; 32]> {
        read_hex_key(&self.dir.join("space-recovery.key"))
    }

    /// Commit one **terminal** Space-authority event. Idempotent by node hash.
    fn commit_space_authority(&mut self, ev: SignedSpaceEvent) -> Result<()> {
        self.ledger
            .commit_batch(
                &[crate::ledger::LedgerEffect::SpaceAuthority(ev).encode()],
                &[],
            )
            .map_err(|e| anyhow!("space-authority commit: {e}"))?;
        Ok(())
    }

    /// Append one signed ceremony-board node to the ceremony-material log.
    fn commit_ceremony_material(&mut self, ev: SignedSpaceEvent) -> Result<()> {
        self.ledger
            .commit_ceremony_batch(&[crate::ledger::CeremonyMaterial::new(ev).encode()])
            .map_err(|e| anyhow!("ceremony-material commit: {e}"))?;
        Ok(())
    }

    /// The injected Body-key epoch fence (idempotent; see [`CeremonyEngine`]).
    fn fence_epoch(&mut self) -> Result<()> {
        (self.fence)(self.ledger)
    }
}

impl CeremonyEngine<'_> {
    /// Break-glass **space recovery** (lait/space/1 W5). Authors a signed
    /// `Recover` with the space recovery key, re-rooting the space to THIS
    /// device and re-keying to fence the old root. For a solo bootstrap key the
    /// held secret signs directly; a K-of-N group key instead produces the group
    /// signature via a FROST ceremony and assembles the same event (the plane
    /// verifies one signature either way — the threshold is invisible here).
    ///
    /// The private `bootstrap_root_epoch_if_needed` helper performs the re-key.
    pub fn space_recover(&mut self) -> Result<SpaceRecovery> {
        let genesis = self.ledger.genesis().clone();
        let cur =
            crate::space::replay(&genesis, &self.space, &self.ledger.space_authority_events());
        // Solo path: a held recovery key that IS the current authority signs the
        // Recover directly.
        if let Some(secret) = self.read_space_recovery_key() {
            let held = crate::space::recovery_commit(&crate::space::recovery_pub_of(&secret));
            if held == Some(cur.recovery_commit) {
                return self.space_recover_solo(&cur, &secret);
            }
        }
        // Group path: this device holds a threshold share of the current group
        // recovery key — open (or drive) a FROST signing ceremony that produces
        // the Recover group signature. The plane verifies one signature either
        // way; the threshold is invisible to it.
        if self.active_dkg_session().is_some() {
            return self.space_recover_group(&cur);
        }
        // Distinguish "this device never held a share" from "the share is right
        // here and cannot be opened". Collapsing those would send a holder to
        // look elsewhere for material sitting on the disk in front of them.
        let degraded = self.degraded_recovery_holders();
        if !degraded.is_empty() {
            return Err(anyhow!(
                "this device holds shares of the current group recovery key that it cannot open: {}",
                degraded
                    .iter()
                    .map(|h| h.transcript.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Err(anyhow!(
            "no way to recover from this device — need either the space's current space-recovery.key beside the store, or a threshold share of the current group recovery key",
        ))
    }

    fn space_recover_solo(
        &mut self,
        cur: &crate::space::RootState,
        secret: &[u8; 32],
    ) -> Result<SpaceRecovery> {
        // Re-root to this device's actor (self-incept if needed).
        let me_actor = self
            .my_actor()
            .ok_or_else(|| anyhow!("this device has no actor identity in the space"))?;
        let op = crate::space::SpaceOp::Recover {
            new_root: vec![me_actor.clone()],
            gen: cur.gen + 1,
        };
        let ev = crate::space::sign_op(secret, &op, vec![], &self.space);
        self.commit_space_authority(ev)?;
        // The re-root is now durable. The follow-on re-key fences the old root,
        // and if it fails the space is left re-rooted but readable under the old
        // key — degraded, not un-recovered. Reporting that as an error would
        // both deny a change that landed and silence its doorbell, so it rides
        // out as part of the committed outcome.
        let rekey_failed = self.fence_epoch().err();
        Ok(SpaceRecovery::Installed(SpaceRecovered {
            root: me_actor,
            rekey_failed,
        }))
    }

    /// The signing transcript holders should converge on for one
    /// `(authority, target, op)` request, if any is already open.
    ///
    /// Content-derived transcript ids make concurrency visible: two holders
    /// independently requesting the same recovery author different nodes and so
    /// open different transcripts, and commitments split across both. The rule
    /// is **prefer the lowest id** — deterministic, no coordinator.
    ///
    /// It is a *preference*, not an override, because correctness never depended
    /// on it: both transcripts sign `Recover { gen: cur.gen + 1 }`, and whichever
    /// installs first advances the generation, so the space plane's monotonicity
    /// guard rejects the loser. A split therefore costs liveness only. Strictly
    /// preferring the lowest id would abandon a transcript that is one share from
    /// completing in favour of one that may never gather K — the wrong trade for
    /// break-glass — so a transcript that has already reached threshold wins.
    pub fn canonical_signing_session(
        &self,
        board: &crate::dkg::CeremonyBoard,
        authority: &crate::dkg::TranscriptId,
        target: crate::dkg::SignTarget,
        op_bytes: &[u8],
        threshold: u16,
    ) -> Option<crate::dkg::TranscriptId> {
        let mut matching: Vec<(&crate::dkg::TranscriptId, &crate::dkg::SignTranscript)> = board
            .signing
            .iter()
            .filter(|(_, t)| {
                t.request.as_ref().is_some_and(|r| match &r.op {
                    crate::dkg::CeremonyOp::SignRequest {
                        authority: a,
                        target: g,
                        op,
                        ..
                    } => a == authority && *g == target && op.as_slice() == op_bytes,
                    _ => false,
                })
            })
            .collect();
        if matching.is_empty() {
            return None;
        }
        // A transcript already at threshold is one aggregation away; take it.
        let complete = matching.iter().find(|(_, t)| {
            t.rounds
                .iter()
                .filter(|v| matches!(v.op, crate::dkg::CeremonyOp::SignRound2 { .. }))
                .count()
                >= threshold as usize
        });
        if let Some((id, _)) = complete {
            return Some(**id);
        }
        matching.sort_by_key(|(id, _)| **id);
        Some(*matching[0].0)
    }

    /// Break-glass recovery under a K-of-N group key: post a signing request for a
    /// Recover re-rooting to this device (joining one already open for this gen),
    /// then drive the ceremony as far as this device can. Holders converge on the
    /// group signature and any of them installs it; idempotent across re-runs.
    fn space_recover_group(&mut self, cur: &crate::space::RootState) -> Result<SpaceRecovery> {
        let me_actor = self
            .my_actor()
            .ok_or_else(|| anyhow!("this device has no actor identity in the space"))?;
        let Some(authority) = self.active_dkg_session() else {
            return Err(anyhow!(
                "this device holds no share of the current group recovery key",
            ));
        };
        let op = crate::space::SpaceOp::Recover {
            new_root: vec![me_actor.clone()],
            gen: cur.gen + 1,
        };
        let op_bytes = postcard::to_stdvec(&op).map_err(|e| anyhow!("encode recover op: {e}"))?;
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let threshold = board
            .dkg
            .get(&authority)
            .and_then(|t| self.accepted_proposal(&authority, t))
            .map(|(_, k, _)| k)
            .unwrap_or(0);
        // Join the transcript holders converge on, or open one.
        let existing = self.canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::SpaceOp,
            &op_bytes,
            threshold,
        );
        let signing = match existing {
            Some(id) => id,
            None => {
                let req = crate::dkg::CeremonyOp::SignRequest {
                    nonce: rand16(),
                    authority,
                    target: crate::dkg::SignTarget::SpaceOp,
                    coordinator: self.me.clone(),
                    op: op_bytes.clone(),
                };
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.space);
                let Some(id) = crate::dkg::TranscriptId::of(&ev) else {
                    return Err(anyhow!("could not derive the request id"));
                };
                self.commit_ceremony_material(ev)?;
                id
            }
        };
        // Record LOCAL intent for this transcript's op so our node co-signs this
        // recovery (the consent gate in `sign_advance_session`).
        //
        // The request is on the board by now — durable, and visible to the other
        // holders. A failure from here is this device failing to contribute, not
        // the ceremony failing to open, so it rides out with the committed
        // outcome instead of erasing it.
        let incomplete = match self
            .dkg_write(&signing, "intent", &op_bytes)
            .and_then(|()| self.dkg_advance())
        {
            Ok(progress) => progress.install_incomplete,
            Err(e) => Some(e),
        };
        let after = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        let installed = after.gen > cur.gen && after.root == vec![me_actor.clone()];
        // If the re-root installed on this pass, a follow-on failure *is* the
        // re-key failure — the same degraded state the solo path reports. It
        // must not be dropped on the way into the installed arm.
        let outcome = if installed {
            SpaceRecovery::Installed(SpaceRecovered {
                root: me_actor,
                rekey_failed: incomplete,
            })
        } else {
            SpaceRecovery::Pending {
                session: signing,
                incomplete,
            }
        };
        Ok(outcome)
    }

    /// Co-sign a pending break-glass recovery request as a holder of the current
    /// group key. This is the explicit consent that `sign_advance_session` demands:
    /// the holder has verified out-of-band that `session` re-roots the space to
    /// the agreed party, and records local intent so their share is contributed to
    /// exactly that op (and no other request on the board).
    pub fn space_recover_approve(
        &mut self,
        session_hex: String,
        expect: Vec<String>,
    ) -> Result<RecoveryApproved> {
        // Strict parse: a session id names a filesystem artifact, so a
        // permissive decode would let two spellings name one transcript.
        let Some(session) = crate::dkg::TranscriptId::parse_hex(session_hex.trim()) else {
            return Err(anyhow!(
                "not a valid recovery session id (64 lowercase hex chars)",
            ));
        };
        if self.active_dkg_session().is_none() {
            return Err(anyhow!(
                "this device holds no share of the current group recovery key — nothing to co-sign",
            ));
        }
        // The holder MUST state which actor(s) they expect this recovery to re-root
        // to, so consent binds to the roots — not to an opaque session id whose
        // request could re-root anywhere. Resolve them up front.
        if expect.is_empty() {
            return Err(anyhow!(
                "name the actor(s) you expect this recovery to re-root to (`--to <actor>`); refusing to co-sign a session blind",
            ));
        }
        let mut expected: Vec<ActorId> = Vec::with_capacity(expect.len());
        for who in &expect {
            let Some(a) = self.resolve_actor(who) else {
                return Err(anyhow!("no actor on this space matches \"{who}\""));
            };
            expected.push(a);
        }
        expected.sort();
        expected.dedup();
        // The exact op the request asks the group to sign, taken from the
        // VERIFIED board and from the transcript the id names — not from the
        // first raw decode that happens to match.
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let request = board.signing.get(&session).and_then(|t| t.request.as_ref());
        let Some((op_bytes, req_target)) = request.and_then(|r| match &r.op {
            crate::dkg::CeremonyOp::SignRequest { op, target, .. } => Some((op.clone(), *target)),
            _ => None,
        }) else {
            return Err(anyhow!(
                "no pending recovery request for that session (sync from the initiator first)",
            ));
        };
        // A recovery approval consents to a SPACE op. Refuse to lend consent to
        // a request aimed at any other plane — approving a ceremony proposal is
        // a different decision and must not ride this command.
        if req_target != crate::dkg::SignTarget::SpaceOp {
            return Err(anyhow!(
                "that request is not a space-recovery request — refusing to co-sign",
            ));
        }
        // It must be a Recover for the next generation re-rooting to EXACTLY the
        // actor set the holder named — refuse to co-sign anything else.
        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        let target = match postcard::from_bytes::<crate::space::SpaceOp>(&op_bytes) {
            Ok(crate::space::SpaceOp::Recover { new_root, gen })
                if gen == cur.gen + 1 && !new_root.is_empty() =>
            {
                new_root
            }
            _ => {
                return Err(anyhow!(
                    "that request is not a current-generation Recover — refusing to co-sign",
                ));
            }
        };
        let mut got = target.clone();
        got.sort();
        got.dedup();
        if got != expected {
            return Err(anyhow!(
                "that request re-roots the space to {} — not the actors you named; refusing to co-sign",
                target
                    .iter()
                    .map(|r| r.short())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        // Both steps precede any durable ceremony write on this path, so a
        // failure here has committed nothing.
        self.dkg_write(&session, "intent", &op_bytes)?;
        let incomplete = self.dkg_advance()?.install_incomplete;
        Ok(RecoveryApproved {
            roots: target,
            incomplete,
        })
    }

    // ---- FROST recovery elevation (solo key → K-of-N DKG group key) ----

    /// Path of a ceremony artifact. The transcript component is always
    /// [`TranscriptId::to_hex`] — canonical lowercase hex, validated when the id
    /// was constructed — so no remote-derived string ever reaches the filesystem
    /// and two spellings can never name one artifact.
    ///
    /// [`TranscriptId::to_hex`]: crate::dkg::TranscriptId::to_hex
    pub fn dkg_path(&self, t: &crate::dkg::TranscriptId, label: &str) -> std::path::PathBuf {
        self.dir.join("dkg").join(format!("{}-{label}", t.to_hex()))
    }
    fn dkg_has(&self, t: &crate::dkg::TranscriptId, label: &str) -> bool {
        self.dkg_path(t, label).exists()
    }
    /// The state of a ceremony artifact on this device.
    ///
    /// `Unreadable` must never be flattened into `Missing`. A share protected
    /// under a different Windows account or machine is *present* — the holder
    /// exists but cannot act — and for an N-of-N group that is the difference
    /// between a degraded holder and an unrecoverable space. Operators need
    /// to see which one they have.
    pub fn dkg_artifact(&self, t: &crate::dkg::TranscriptId, label: &str) -> ArtifactRead {
        match crate::secretfs::read_private(&self.dkg_path(t, label)) {
            Ok(Some(v)) => ArtifactRead::Present(v),
            Ok(None) => ArtifactRead::Missing,
            Err(e) => {
                tracing::error!(
                    "ceremony artifact {label} for transcript {} is present but unreadable: {e}",
                    t.to_hex()
                );
                ArtifactRead::Unreadable(e)
            }
        }
    }

    /// The bytes of a ceremony artifact, or `None` if it is absent **or**
    /// unreadable. Callers that must distinguish those — anything reporting to
    /// an operator — use [`Self::dkg_artifact`] instead.
    pub fn dkg_read(&self, t: &crate::dkg::TranscriptId, label: &str) -> Option<Vec<u8>> {
        match self.dkg_artifact(t, label) {
            ArtifactRead::Present(v) => Some(v),
            _ => None,
        }
    }

    /// Holders on this device whose share exists but cannot be used, restricted
    /// to transcripts that are — or might be — the space's **current**
    /// recovery authority.
    ///
    /// The currency check matters: an unreadable share from a superseded group
    /// is not a recovery problem, so announcing "this device has a share for the
    /// space recovery key" on its account would be false. Candidates are
    /// filtered through: public-key package, derived group key, recovery commit,
    /// standing RootState.
    ///
    /// A transcript whose package cannot be read yields `is_current_authority`
    /// of `None` and is still reported: we cannot prove it is live, but nor can
    /// we rule it out, and dropping the one artifact an operator needs to hear
    /// about would be the worse error.
    pub fn degraded_recovery_holders(&self) -> Vec<DegradedRecoveryHolder> {
        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        board
            .dkg
            .keys()
            .filter_map(|id| {
                let reason = match self.dkg_artifact(id, "share") {
                    ArtifactRead::Unreadable(crate::secretfs::SecretError::Undecryptable(m)) => {
                        RecoveryArtifactFailure::Undecryptable(m)
                    }
                    ArtifactRead::Unreadable(crate::secretfs::SecretError::Io(e)) => {
                        RecoveryArtifactFailure::Io(e.to_string())
                    }
                    _ => return None,
                };
                // Currency is DERIVED from the public-key package, never trusted
                // from a file naming the group key.
                let is_current_authority = match self.dkg_artifact(id, "pkp") {
                    ArtifactRead::Present(pkp) => Some(
                        crate::dkg::group_key_of_package(&pkp)
                            .ok()
                            .and_then(|g| crate::space::recovery_commit(&g))
                            == Some(cur.recovery_commit),
                    ),
                    _ => None,
                };
                // A share we can PROVE belongs to a superseded group is not a
                // recovery problem: it could not recover this space even if
                // it were readable, so reporting it would be false.
                if is_current_authority == Some(false) {
                    return None;
                }
                Some(DegradedRecoveryHolder {
                    transcript: id.to_hex(),
                    reason,
                    is_current_authority,
                })
            })
            .collect()
    }
    /// Write a ceremony artifact owner-only. Device-bound: shares, round secrets
    /// and nonces belong to this holder on this machine and are never carried
    /// elsewhere, unlike the break-glass keys (see [`crate::secretfs::Wrap`]).
    pub fn dkg_write(&self, t: &crate::dkg::TranscriptId, label: &str, bytes: &[u8]) -> Result<()> {
        let dir = self.dir.join("dkg");
        crate::secretfs::create_private_dir(&dir).map_err(|e| anyhow!("create dkg dir: {e}"))?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::Replace,
            crate::secretfs::Wrap::DeviceBound,
        )
        .map_err(|e| anyhow!("write dkg artifact: {e}"))
    }
    /// Write a ceremony artifact owner-only but **portable** - no device
    /// binding. For public material that must stay legible after a store is
    /// restored onto another account (see [`crate::secretfs::Wrap::Portable`]).
    pub fn dkg_write_portable(
        &self,
        t: &crate::dkg::TranscriptId,
        label: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let dir = self.dir.join("dkg");
        crate::secretfs::create_private_dir(&dir).map_err(|e| anyhow!("create dkg dir: {e}"))?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::Replace,
            crate::secretfs::Wrap::Portable,
        )
        .map_err(|e| anyhow!("write portable dkg artifact: {e}"))
    }

    /// Write a ceremony artifact that must not already exist. For single-use
    /// material (signing nonces): an existing record has to be *examined* — it
    /// may already be bound to a signing package — never silently replaced.
    fn dkg_write_new(&self, t: &crate::dkg::TranscriptId, label: &str, bytes: &[u8]) -> Result<()> {
        let dir = self.dir.join("dkg");
        crate::secretfs::create_private_dir(&dir).map_err(|e| anyhow!("create dkg dir: {e}"))?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::New,
            crate::secretfs::Wrap::DeviceBound,
        )
        .map_err(|e| anyhow!("write single-use dkg artifact: {e}"))
    }

    /// Begin elevating the recovery authority to a `k`-of-N FROST group key over
    /// `cofounders` (their device keys) + this device. Only the holder of the
    /// current recovery key may elevate (they install the result). Posts the DKG
    /// proposal and this node's first round, then the ceremony advances on sync.
    pub fn space_elevate(&mut self, cofounders: Vec<String>, k: u16) -> Result<Elevation> {
        // Must hold the current recovery key to install the resulting Rotate.
        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        let holds_solo = self
            .read_space_recovery_key()
            .and_then(|s| crate::space::recovery_commit(&crate::space::recovery_pub_of(&s)))
            == Some(cur.recovery_commit);
        // Group→group reconfiguration: we hold a share of the standing group, so
        // we can OPEN the grant request even though we cannot sign it alone.
        let holds_share = self.active_dkg_session().is_some();
        if !holds_solo && !holds_share {
            return Err(anyhow!(
                "only the current recovery authority can elevate: run this where space-recovery.key lives, or on a device holding a share of the current group key",
            ));
        }
        // Assemble the sorted participant set (co-founders + me). Sorted and
        // deduped here AND re-checked by every acceptor: a hostile proposer must
        // not be able to hand honest nodes a malformed participant list.
        let mut set: std::collections::BTreeSet<DeviceId> = std::collections::BTreeSet::new();
        for c in cofounders {
            match DeviceId::parse(&c) {
                Some(u) => {
                    set.insert(u);
                }
                None => return Err(anyhow!("not a valid co-founder device key: {c}")),
            }
        }
        set.insert(self.me.clone());
        let participants: Vec<DeviceId> = set.into_iter().collect();
        let n = participants.len() as u16;
        // k == 0 means "all holders" (N-of-N) — the safe default.
        let k = if k == 0 { n } else { k };
        if !(1..=n).contains(&k) || n < 2 {
            return Err(anyhow!(
                "elevation needs ≥2 participants and threshold in 1..=N",
            ));
        }
        if !self.rotation_can_complete(&participants) {
            return Err(anyhow!(
                "too few of the current holders are in the proposed arrangement: installing the result needs the current group to sign the rotation, and only a participant of the new ceremony can derive the key it installs. Include at least the current threshold of existing holders.",
            ));
        }
        // Sign the proposal FIRST: its id is the hash of the signed node, so it
        // does not exist until now. `nonce` keeps two identical elevations by
        // the same initiator from colliding — Ed25519 signing is deterministic,
        // so without it the same (n, k, participants) would hash identically.
        let Some(current) = self.current_authority() else {
            return Err(anyhow!(
                "cannot determine the arrangement operating the current recovery key — sync the ceremony that produced it first",
            ));
        };
        let principals: Vec<crate::authority::PrincipalId> = participants
            .iter()
            .map(crate::authority::PrincipalId::of_device)
            .collect();
        let propose = crate::dkg::CeremonyOp::DkgPropose(crate::dkg::frost_rotation_proposal(
            rand16(),
            k,
            principals,
            current,
        ));
        let ev = crate::dkg::sign_ceremony(&self.seed, &propose, &self.space);
        let Some(transcript) = crate::dkg::TranscriptId::of(&ev) else {
            return Err(anyhow!("could not derive the proposal id"));
        };
        // Local consent record for the ceremony itself, keyed by the transcript
        // it consents to. Written before posting so a crash leaves an orphan
        // marker (harmless) rather than a proposal nobody will install.
        self.dkg_write(&transcript, "intent", transcript.to_hex().as_bytes())?;
        self.commit_ceremony_material(ev)?;

        // ---- the proposal is durable from here ----
        //
        // Every step below can fail, and none of them may report that failure as
        // an error: the proposal is on the board, other participants will see it
        // on their next sync, and an `Err` would both deny that and silence the
        // doorbell announcing it. They ride out as `incomplete` instead, and the
        // adapter says the proposal stands and what still needs doing.

        // Authorization. The device signature on the proposal proves only
        // control of a device; what every participant checks is a grant from the
        // standing authority. How that grant is produced is the ONLY thing that
        // differs between a solo and a group authority — the grant object itself
        // is identical either way, which is what B1 bought.
        let mut grant_request = None;
        let mut incomplete = None;
        if holds_solo {
            // The device signature on the proposal proves only control of a
            // device; what every participant checks is a grant from the standing
            // authority. A solo key signs it directly.
            match self.read_space_recovery_key() {
                Some(secret) => {
                    let grant = crate::dkg::sign_authority_grant(&secret, &self.space, &transcript);
                    let auth_ev = crate::dkg::sign_ceremony(
                        &self.seed,
                        &crate::dkg::CeremonyOp::DkgAuthorize(grant),
                        &self.space,
                    );
                    incomplete = self.commit_ceremony_material(auth_ev).err();
                }
                None => incomplete = Some(anyhow!("recovery key disappeared mid-elevation")),
            }
        } else {
            // The standing authority is a group, so the grant needs a threshold
            // signature. Open a signing request for it; the other holders consent
            // with `space elevate-approve`, and the aggregate lands as the grant.
            match self.open_grant_request(&transcript) {
                Ok((signing, _)) => grant_request = Some(signing),
                Err(e) => incomplete = Some(e),
            }
        }
        // Driving the ceremony is opportunistic — it advances again on the next
        // sync — but a failure here is still worth surfacing rather than
        // discarding, provided something worse has not already been recorded.
        match self.dkg_advance() {
            Ok(progress) => {
                if let Some(e) = progress.install_incomplete {
                    incomplete.get_or_insert(e);
                }
            }
            Err(e) => {
                incomplete.get_or_insert(e);
            }
        }
        Ok(Elevation {
            k,
            n,
            proposal: transcript,
            grant_request,
            incomplete,
        })
    }

    /// Begin a **same-key reshare**: redistribute the standing group key onto a
    /// new `k`-of-N arrangement over `participants` (device keys), without
    /// changing the key and without reconstructing the secret. Participant
    /// replacement is the ordinary use: name the retained holders plus the
    /// replacements.
    ///
    /// Requires the standing authority to be a group this device holds a
    /// usable share of (a solo authority has no shares to redistribute — use
    /// `space elevate`). Posts the reshare proposal plus the standing group's
    /// authorization request; the other holders consent with
    /// `space elevate-approve`, dealing/combination advances on sync, and the
    /// standing group threshold-signs the terminal `Reshare` installation.
    /// Resharing is not a revocation — an old coalition that kept its shares
    /// can still sign; a removal that must revoke uses a key rotation.
    pub fn space_reshare(&mut self, participants: Vec<String>, k: u16) -> Result<Elevation> {
        let Some(standing) = self.active_dkg_session() else {
            return Err(anyhow!(
                "the standing recovery authority is not a group this device holds a share of — a solo authority has no shares to redistribute; use `space elevate`",
            ));
        };
        let manifest = self
            .dkg_manifest(&standing)
            .ok_or_else(|| anyhow!("no acceptance record for the standing ceremony"))?;
        let group_key = self
            .group_key_of_transcript(&standing)
            .ok_or_else(|| anyhow!("cannot derive the standing group key"))?;
        let old_pkp = self
            .dkg_read(&standing, "pkp")
            .ok_or_else(|| anyhow!("the standing public-key package is missing"))?;
        // Assemble the sorted new participant set. Sorted and deduped here AND
        // re-checked by every acceptor.
        let mut set: std::collections::BTreeSet<DeviceId> = std::collections::BTreeSet::new();
        for p in participants {
            match DeviceId::parse(&p) {
                Some(d) => {
                    set.insert(d);
                }
                None => return Err(anyhow!("not a valid participant device key: {p}")),
            }
        }
        let new_devices: Vec<DeviceId> = set.into_iter().collect();
        let n = new_devices.len() as u16;
        let k = if k == 0 { n } else { k };
        if !(1..=n).contains(&k) || n < 1 {
            return Err(anyhow!(
                "resharing needs ≥1 participant and threshold in 1..=N"
            ));
        }
        let principals: Vec<crate::authority::PrincipalId> = new_devices
            .iter()
            .map(crate::authority::PrincipalId::of_device)
            .collect();
        let proposal = crate::dkg::KeyCeremonyProposal {
            nonce: rand16(),
            configuration: crate::authority::AuthorityConfiguration::frost_threshold(
                &crate::authority::FrostThresholdConfig {
                    k,
                    participants: principals,
                },
            ),
            transition: crate::dkg::ProposedTransition::Reshare {
                authority: crate::authority::AuthorityId::new(
                    group_key.clone(),
                    &manifest.configuration,
                ),
                current_configuration: manifest.configuration.clone(),
                old_public_package: old_pkp,
            },
        };
        if proposal.reshare_context().is_none() {
            return Err(anyhow!(
                "the standing arrangement cannot be redistributed (not a flat threshold group)",
            ));
        }
        let propose = crate::dkg::CeremonyOp::DkgPropose(proposal);
        let ev = crate::dkg::sign_ceremony(&self.seed, &propose, &self.space);
        let Some(transcript) = crate::dkg::TranscriptId::of(&ev) else {
            return Err(anyhow!("could not derive the proposal id"));
        };
        // Local consent for the ceremony, then the durable proposal.
        self.dkg_write(&transcript, "intent", transcript.to_hex().as_bytes())?;
        self.commit_ceremony_material(ev)?;

        // ---- the proposal is durable from here (failures ride out) ----
        let mut grant_request = None;
        let mut incomplete = None;
        match self.open_grant_request(&transcript) {
            Ok((signing, _)) => grant_request = Some(signing),
            Err(e) => incomplete = Some(e),
        }
        match self.dkg_advance() {
            Ok(progress) => {
                if let Some(e) = progress.install_incomplete {
                    incomplete.get_or_insert(e);
                }
            }
            Err(e) => {
                incomplete.get_or_insert(e);
            }
        }
        Ok(Elevation {
            k,
            n,
            proposal: transcript,
            grant_request,
            incomplete,
        })
    }

    /// Open (or join) a threshold-signing transcript asking the standing group to
    /// authorize `proposal`, and record our own consent to it.
    ///
    /// The request carries the grant bytes verbatim as its op, so what the group
    /// signs is exactly the object `authority_grant_of` will later verify — the
    /// signing path never constructs the payload a second way.
    fn open_grant_request(
        &mut self,
        proposal: &crate::dkg::TranscriptId,
    ) -> Result<(crate::dkg::TranscriptId, bool)> {
        let authority = self
            .active_dkg_session()
            .ok_or_else(|| anyhow!("this device holds no share of the current group key"))?;
        let group_key = self
            .group_key_of_transcript(&authority)
            .ok_or_else(|| anyhow!("cannot derive the current group key"))?;
        let (op_bytes, _payload) =
            crate::dkg::authority_grant_payload(&self.space, &group_key, proposal);
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let threshold = board
            .dkg
            .get(&authority)
            .and_then(|t| self.accepted_proposal(&authority, t))
            .map(|(_, k, _)| k)
            .unwrap_or(0);
        let mut changed = false;
        let signing = match self.canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::AuthorityGrant,
            &op_bytes,
            threshold,
        ) {
            Some(id) => id,
            None => {
                let req = crate::dkg::CeremonyOp::SignRequest {
                    nonce: rand16(),
                    authority,
                    target: crate::dkg::SignTarget::AuthorityGrant,
                    coordinator: self.me.clone(),
                    op: op_bytes.clone(),
                };
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.space);
                let id = crate::dkg::TranscriptId::of(&ev)
                    .ok_or_else(|| anyhow!("could not derive the request id"))?;
                self.commit_ceremony_material(ev)?;
                changed = true;
                id
            }
        };
        if self.dkg_read(&signing, "intent").as_deref() != Some(op_bytes.as_slice()) {
            self.dkg_write(&signing, "intent", &op_bytes)?;
            changed = true;
        }
        Ok((signing, changed))
    }

    /// Co-sign a pending authority-grant request as a holder of the current
    /// group key.
    ///
    /// Consent binds to the **proposal**, not to an opaque session id: the caller
    /// must name the proposal they believe is being authorized, and the request
    /// must actually be for that one. Approving a session blind would mean
    /// lending a share to whatever configuration happened to be proposed —
    /// including one that hands the next authority to someone else.
    pub fn space_elevate_approve(
        &mut self,
        session_hex: String,
        expect_proposal: String,
    ) -> Result<ElevationApproved> {
        let Some(session) = crate::dkg::TranscriptId::parse_hex(session_hex.trim()) else {
            return Err(anyhow!("not a valid request id (64 lowercase hex chars)"));
        };
        let Some(expected) = crate::dkg::TranscriptId::parse_hex(expect_proposal.trim()) else {
            return Err(anyhow!(
                "name the proposal you expect this to authorize (`--proposal <64-hex>`)",
            ));
        };
        if self.active_dkg_session().is_none() {
            return Err(anyhow!(
                "this device holds no share of the current group key — nothing to co-sign",
            ));
        }
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let Some((op_bytes, target)) = board
            .signing
            .get(&session)
            .and_then(|t| t.request.as_ref())
            .and_then(|r| match &r.op {
                crate::dkg::CeremonyOp::SignRequest { op, target, .. } => {
                    Some((op.clone(), *target))
                }
                _ => None,
            })
        else {
            return Err(anyhow!(
                "no pending request for that id (sync from the initiator first)",
            ));
        };
        if target != crate::dkg::SignTarget::AuthorityGrant {
            return Err(anyhow!(
                "that request is not an authority grant — refusing to co-sign",
            ));
        }
        let Ok(grant) = postcard::from_bytes::<crate::dkg::AuthorityGrant>(&op_bytes) else {
            return Err(anyhow!("that request does not carry a well-formed grant"));
        };
        if grant.proposal != expected {
            return Err(anyhow!(
                "that signing request authorizes a different proposal ({}) than the one you named; refusing to co-sign",
                grant.proposal.to_hex()
            ));
        }
        // The proposal must be one we can see and would accept on its own terms:
        // well formed, a transition we implement, and replacing the authority
        // actually standing. Otherwise a holder could be talked into authorizing
        // a ceremony that is unusable or aimed at the wrong authority.
        let Some(proposal) = board
            .dkg
            .get(&expected)
            .and_then(|t| t.proposal.as_ref())
            .and_then(|v| match &v.op {
                crate::dkg::CeremonyOp::DkgPropose(p) => Some(p.clone()),
                _ => None,
            })
        else {
            return Err(anyhow!(
                "that proposal has not synced here yet — sync and retry"
            ));
        };
        let Some(cfg) = proposal.frost_config() else {
            return Err(anyhow!(
                "that proposal is malformed or uses an unsupported transition",
            ));
        };
        if !self.claims_the_standing_authority(proposal.current_authority()) {
            return Err(anyhow!(
                "that proposal does not replace the authority standing here — refusing to co-sign",
            ));
        }
        // A holder must not authorize a ceremony that cannot be installed. The
        // proposer checks this too, but a hostile or stale proposer does not, and
        // the cost of being wrong is a permanently stalled rotation. A same-key
        // reshare is exempt: its installation is signed by the CURRENT holders
        // (who all hold usable shares) and names only the new configuration, so
        // no overlap with the new arrangement is required.
        let proposed: Vec<DeviceId> = cfg
            .participants
            .iter()
            .filter_map(|p| p.as_device())
            .collect();
        if !proposal.is_reshare() && !self.rotation_can_complete(&proposed) {
            return Err(anyhow!(
                "refusing to authorize: too few of the current holders are in the proposed arrangement, so the resulting key could never be installed",
            ));
        }
        // These write local consent artifacts only; nothing reaches the shared
        // board here, so a failure has committed nothing.
        self.dkg_write(&session, "intent", &op_bytes)?;
        // Consent to the CEREMONY as well, not only to the grant that authorizes
        // it. The holder named this proposal explicitly, so this is exactly what
        // they agreed to — and without it they would authorize a ceremony they
        // then refuse to help install, stalling the rotation at the last step
        // with no indication why.
        self.dkg_write(&expected, "intent", expected.to_hex().as_bytes())?;
        self.dkg_advance()?;
        Ok(ElevationApproved {
            k: cfg.k,
            n: cfg.participants.len(),
        })
    }

    /// Drive every FROST ceremony this device participates in to a fixpoint, based
    /// on what has synced. Idempotent: posts each round once, and installs the
    /// group key (via a space `Rotate`) once, by the recovery-key holder. Called
    /// by `space_elevate`, an explicit advance, and on import.
    ///
    /// The ceremony board is grow-only and re-scanned each import; completed and
    /// abandoned sessions are never pruned, so a member could pad it to inflate
    /// per-import work (bounded per call by the `guard` below). Session GC/expiry
    /// is future work — see the `C_CEREMONY` container in `fabric::membership`.
    pub fn dkg_advance(&mut self) -> Result<CeremonyProgress> {
        let mut out = CeremonyProgress::default();
        // A ceremony has a bounded number of steps; the guard is a backstop
        // against any unforeseen non-convergence, never reached in normal flow.
        let mut guard = 0;
        loop {
            let pass = self.dkg_advance_once()?;
            // First one wins: the earliest install failure is the one whose
            // cause is still legible.
            if out.install_incomplete.is_none() {
                out.install_incomplete = pass.install_incomplete;
            }
            if !pass.progressed {
                break;
            }
            out.progressed = true;
            guard += 1;
            if guard > 64 {
                break;
            }
        }
        Ok(out)
    }

    fn dkg_advance_once(&mut self) -> Result<CeremonyProgress> {
        // ONE verified pass over the board. Everything below reads from this —
        // discovery included. Previously sessions were discovered by decoding
        // events *unverified* and the whole board was then re-verified once per
        // discovered session, so forged events both manufactured transcripts and
        // multiplied the work (`transcripts × board`, attacker-controlled on
        // both axes).
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        // Per-transcript advancement is best-effort: a malformed, signature-valid
        // package from one participant must never fail the whole import (which
        // would wedge membership sync permanently on the persisted event). Isolate
        // and log each transcript's error instead of propagating it.
        let mut progressed = false;
        // DKG transcripts naming me as a participant, under an *accepted*
        // proposal. Acceptance (not just a valid signature) is the gate — see
        // `accepted_proposal`. A same-key reshare additionally involves the
        // standing arrangement's OLD holders (the dealers), who need not be
        // new participants.
        let dkg_ids: Vec<(crate::dkg::TranscriptId, bool)> = board
            .dkg
            .iter()
            .filter_map(|(id, t)| {
                let (_, _, participants) = self.accepted_proposal(id, t)?;
                let reshare = t.proposal.as_ref().and_then(|p| match &p.op {
                    crate::dkg::CeremonyOp::DkgPropose(prop) => prop.reshare_context(),
                    _ => None,
                });
                match reshare {
                    Some(ctx) => (participants.contains(&self.me)
                        || ctx.old_devices.contains(&self.me))
                    .then_some((*id, true)),
                    None => participants.contains(&self.me).then_some((*id, false)),
                }
            })
            .collect();
        for (id, is_reshare) in dkg_ids {
            let t = &board.dkg[&id];
            let outcome = if is_reshare {
                self.reshare_advance_session(&id, t)
            } else {
                self.dkg_advance_session(&id, t)
            };
            match outcome {
                Ok(p) => progressed |= p,
                Err(e) => tracing::warn!("dkg ceremony advance failed (skipped): {e:#}"),
            }
        }
        // Threshold-signing transcripts I can co-sign.
        let sign_ids: Vec<crate::dkg::TranscriptId> = board.signing.keys().copied().collect();
        let mut install_incomplete = None;
        for id in sign_ids {
            let t = &board.signing[&id];
            match self.sign_advance_session(&id, t, &board, &mut install_incomplete) {
                Ok(p) => progressed |= p,
                Err(e) => tracing::warn!("recovery signing advance failed (skipped): {e:#}"),
            }
        }
        Ok(CeremonyProgress {
            progressed,
            install_incomplete,
        })
    }

    /// Whether `claimed` really is the authority standing here.
    ///
    /// Two checks, and the second is only available to some nodes:
    ///
    /// Both halves are checkable by every node, whether or not it holds a share:
    ///
    /// - **The key must commit to the standing commitment.** A hash comparison
    ///   against `RootState.recovery_commit`; always worked.
    /// - **The arrangement must match the standing configuration.** Rotation records the
    ///   configuration id on the space plane, so `RootState.configuration` gives
    ///   it for every replica through replay. Without that replicated arrangement, a non-holder could not learn
    ///   the arrangement and acceptance fell back to key-alone — sound only while
    ///   `RotateKey` always changed the key. `Reshare` breaks that, which is why
    ///   the gap had to close before same-key transitions exist.
    ///
    /// The public key still arrives *in the proposal* (the proposer names it) and
    /// is verified against the on-plane commitment; the configuration now arrives
    /// on-plane too, so the "accept because we cannot tell" escape hatch is gone.
    fn claims_the_standing_authority(&self, claimed: &crate::authority::AuthorityId) -> bool {
        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        crate::space::recovery_commit(&claimed.public_key) == Some(cur.recovery_commit)
            && claimed.configuration == cur.configuration
    }

    /// Whether a proposed participant set leaves the current group able to
    /// install the result.
    ///
    /// Installing a rotation needs the *current* authority to sign it, and a
    /// signer only reaches that point if it can derive the candidate key —
    /// which requires holding the new ceremony's public package, i.e. being one
    /// of its participants. So at least `k_current` members of the current
    /// arrangement must also be in the proposed one.
    ///
    /// Checked at authorization time because the failure is otherwise silent and
    /// terminal: a ceremony with too little overlap authorizes cleanly, runs the
    /// whole DKG, collects custody attestations, and then stalls forever at
    /// installation with every participant believing it succeeded.
    fn rotation_can_complete(&self, proposed: &[DeviceId]) -> bool {
        let Some(current) = self.standing_dkg_session() else {
            // A solo authority signs the rotation by itself; no overlap needed.
            return true;
        };
        let Some(cfg) = self
            .dkg_manifest(&current)
            .and_then(|m| m.configuration.as_frost_threshold())
        else {
            // Cannot determine the current arrangement, so cannot judge. Let the
            // ceremony proceed rather than block on our own ignorance.
            return true;
        };
        let overlap = cfg
            .participants
            .iter()
            .filter_map(|p| p.as_device())
            .filter(|d| proposed.contains(d))
            .count();
        overlap >= cfg.k as usize
    }

    /// Whether `dkg`'s arrangement is **indispensable**: every holder is
    /// required, so no share is redundant and losing one ends the authority.
    fn is_indispensable(&self, dkg: &crate::dkg::TranscriptId) -> bool {
        self.dkg_manifest(dkg)
            .and_then(|m| m.configuration.as_frost_threshold())
            .is_some_and(|c| c.k as usize == c.participants.len())
    }

    /// Custodians of `dkg` that have **not** attested portable custody.
    ///
    /// Only meaningful for an indispensable arrangement; a redundant one can
    /// afford to lose a holder, so it does not gate on this.
    fn custody_outstanding(
        &self,
        dkg: &crate::dkg::TranscriptId,
        t: &crate::dkg::DkgTranscript,
        participants: &[DeviceId],
    ) -> Vec<DeviceId> {
        if !self.is_indispensable(dkg) {
            return Vec::new();
        }
        let acked = t.custody_acks();
        participants
            .iter()
            .filter(|p| !acked.contains(p))
            .cloned()
            .collect()
    }

    /// Export this device's share for `dkg` as a portable package, verify it by
    /// reopening it, and attest that on the board.
    ///
    /// The verification is the point. Writing a file proves nothing — the
    /// failure this guards against is a package that cannot be reopened, which
    /// is indistinguishable from a good one until the day it is needed. So the
    /// package is read back from disk and opened through the **portable** slot
    /// specifically, never the local convenience path, before anything is
    /// attested.
    pub fn space_custody_export(
        &mut self,
        path: String,
        passphrase: String,
    ) -> Result<CustodyExport> {
        if passphrase.chars().count() < 12 {
            return Err(anyhow!(
                "choose a passphrase of at least 12 characters — this is the only thing standing between an attacker with the file and your share",
            ));
        }
        // The ceremony to export for: one we hold a share of. A pending
        // arrangement takes precedence, since that is the one whose install is
        // waiting on this attestation.
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let standing = self.active_dkg_session();
        let Some(dkg) = board
            .dkg
            .keys()
            .find(|id| self.dkg_read(id, "share").is_some() && Some(**id) != standing)
            .copied()
            .or(standing)
        else {
            return Err(anyhow!("this device holds no share to export"));
        };
        let Some(t) = board.dkg.get(&dkg) else {
            return Err(anyhow!("that ceremony is not on the board"));
        };
        let Some((_, _, participants)) = self.accepted_proposal(&dkg, t) else {
            return Err(anyhow!("that ceremony is not accepted here"));
        };
        let Some(manifest) = self.dkg_manifest(&dkg) else {
            return Err(anyhow!("no acceptance record for that ceremony"));
        };
        let (Some(share), Some(pkp)) = (self.dkg_read(&dkg, "share"), self.dkg_read(&dkg, "pkp"))
        else {
            return Err(anyhow!(
                "this device's share for that ceremony is missing or unreadable",
            ));
        };
        let Ok(group_key) = crate::dkg::group_key_of_package(&pkp) else {
            return Err(anyhow!("the public-key package is unusable"));
        };
        let Some(index) = participants.iter().position(|p| p == &self.me) else {
            return Err(anyhow!("this device is not a participant"));
        };
        let principal = crate::authority::PrincipalId::of_device(&self.me);
        let leaf = crate::authority::LeafId::of_principal(&principal);
        let authority =
            crate::authority::AuthorityId::new(group_key.clone(), &manifest.configuration);
        let payload = crate::custody::SharePayload::Frost(crate::custody::FrostSharePayload {
            key_share: share,
            public_package: pkp,
            index: index as u16 + 1,
        });
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&rand16());
        let package = crate::custody::AuthoritySharePackage::seal(
            &self.space,
            &authority,
            &dkg.to_hex(),
            &principal,
            &leaf,
            &payload,
            &[crate::custody::SlotSpec::Passphrase {
                passphrase: passphrase.clone(),
                salt,
                params: custody_kdf_params(),
            }],
        )?;
        let bytes = match postcard::to_stdvec(&package) {
            Ok(b) => b,
            Err(e) => return Err(anyhow!("encode package: {e}")),
        };
        let out = std::path::PathBuf::from(&path);
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                crate::secretfs::create_private_dir(parent)?;
            }
        }
        // Write to a temp sibling, verify it opens, and only then rename it over
        // the target. Overwriting `out` up front and verifying afterwards would
        // destroy a good prior share whenever the fresh export fails to reopen —
        // an all-holders arrangement then loses a custodian to a bad passphrase
        // typo. The verified temp is the only thing that ever replaces the target.
        let nonce_hex = data_encoding::HEXLOWER.encode(&rand16());
        let base = out.file_name().and_then(|n| n.to_str()).unwrap_or("share");
        let tmp = out.with_file_name(format!("{base}.tmp-{nonce_hex}"));
        // Portable: a share package is meant to be carried off this machine, so
        // it must not be wrapped to this account. `New` so a stray temp is loud.
        crate::secretfs::write_private(
            &tmp,
            &bytes,
            crate::secretfs::Create::New,
            crate::secretfs::Wrap::Portable,
        )?;
        // Read the temp back from disk and open through the portable slot.
        // Verifying the in-memory value would test nothing that could fail.
        let verify = (|| -> std::result::Result<(), String> {
            let reread = match crate::secretfs::read_private(&tmp) {
                Ok(Some(b)) => b,
                Ok(None) => return Err("the package vanished after writing".into()),
                Err(e) => return Err(format!("re-reading the package failed: {e}")),
            };
            let restored: crate::custody::AuthoritySharePackage = postcard::from_bytes(&reread)
                .map_err(|e| format!("the written package does not decode: {e}"))?;
            let expect = crate::custody::PackageExpectation {
                space: &self.space,
                authority: &authority,
                ceremony: &dkg.to_hex(),
                leaf: &leaf,
                group_key: &group_key,
                index: index as u16 + 1,
            };
            restored
                .verify_and_open(
                    &crate::custody::UnlockKey::Passphrase(passphrase.clone()),
                    &expect,
                )
                .map_err(|e| format!("the exported package could not be reopened: {e:#}"))?;
            Ok(())
        })();
        if let Err(msg) = verify {
            // Leave any existing target untouched; discard the unverified temp.
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow!("{msg}, so it was NOT attested"));
        }
        // The temp opened cleanly: promote it atomically. Only now is the old
        // target (if any) replaced.
        if let Err(e) = crate::secretfs::persist_replace(&tmp, &out) {
            let _ = std::fs::remove_file(&tmp);
            return Err(anyhow!(
                "the verified package could not be moved into place: {e}"
            ));
        }
        self.post_ceremony(crate::dkg::CeremonyOp::CustodyAck { dkg })?;
        // Recompute from the board so the count reflects our own attestation.
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let outstanding = board
            .dkg
            .get(&dkg)
            .map(|t| self.custody_outstanding(&dkg, t, &participants))
            .unwrap_or_default();
        Ok(CustodyExport {
            indispensable: self.is_indispensable(&dkg),
            outstanding: outstanding.len(),
            path,
        })
    }

    /// Restore a share from a portable package written by
    /// [`Self::space_custody_export`].
    ///
    /// This is the half that makes the backup mean anything. Without it the
    /// package preserves the material and the product still cannot resume
    /// signing after an account or machine loss — which is not what "DPAPI loss
    /// does not destroy an owner" claims.
    ///
    /// Refuses to replace a share that is already readable unless `force`: the
    /// common case for running this by mistake is a working device, and
    /// overwriting good material with an older package would turn a typo into
    /// the loss it exists to prevent.
    pub fn space_custody_import(
        &mut self,
        path: String,
        passphrase: String,
        force: bool,
    ) -> Result<CustodyImport> {
        let bytes = match crate::secretfs::read_private(std::path::Path::new(&path)) {
            Ok(Some(b)) => b,
            Ok(None) => return Err(anyhow!("no package at {path}")),
            Err(e) => return Err(anyhow!("reading {path}: {e}")),
        };
        let package: crate::custody::AuthoritySharePackage = match postcard::from_bytes(&bytes) {
            Ok(p) => p,
            Err(e) => return Err(anyhow!("that file is not a share package: {e}")),
        };
        if package.space != self.space {
            return Err(anyhow!("that package belongs to a different space"));
        }
        // Resolve the ceremony it claims, from the board — never from the
        // package. A package names its own ceremony; that is a claim, not proof.
        let Some(dkg) = crate::dkg::TranscriptId::parse_hex(&package.ceremony) else {
            return Err(anyhow!("that package names no valid ceremony"));
        };
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let Some(t) = board.dkg.get(&dkg) else {
            return Err(anyhow!(
                "that ceremony is not on this device's board — sync the space first",
            ));
        };
        let Some((_, _, participants)) = self.accepted_proposal(&dkg, t) else {
            return Err(anyhow!(
                "that ceremony is not accepted here — it may not be authorized",
            ));
        };
        let Some(index) = participants.iter().position(|p| p == &self.me) else {
            return Err(anyhow!("this device is not a participant of that ceremony"));
        };
        let index = index as u16 + 1;
        let Some(manifest) = self.dkg_manifest(&dkg) else {
            return Err(anyhow!("no acceptance record for that ceremony"));
        };
        // Refuse to clobber usable material.
        if !force && matches!(self.dkg_artifact(&dkg, "share"), ArtifactRead::Present(_)) {
            return Err(anyhow!(
                "this device already holds a readable share for that ceremony — pass --force only if you mean to replace it",
            ));
        }
        // The expected group key comes from the board's ceremony where possible,
        // so a package cannot introduce a group this device never accepted. When
        // the local public package is gone (the very case this command exists
        // for), fall back to the package's own — still bound by the authority
        // and space checks, and validated against the private half below.
        let expected_group = match self.dkg_artifact(&dkg, "pkp") {
            ArtifactRead::Present(pkp) => match crate::dkg::group_key_of_package(&pkp) {
                Ok(k) => k,
                Err(e) => return Err(anyhow!("local public package unusable: {e}")),
            },
            _ => package.authority.public_key.clone(),
        };
        let authority =
            crate::authority::AuthorityId::new(expected_group.clone(), &manifest.configuration);
        let principal = crate::authority::PrincipalId::of_device(&self.me);
        let leaf = crate::authority::LeafId::of_principal(&principal);
        let expect = crate::custody::PackageExpectation {
            space: &self.space,
            authority: &authority,
            ceremony: &package.ceremony,
            leaf: &leaf,
            group_key: &expected_group,
            index,
        };
        // `verify_and_open` performs the private-half validation, so a package
        // that opens but carries unusable material never reaches storage.
        let payload =
            package.verify_and_open(&crate::custody::UnlockKey::Passphrase(passphrase), &expect)?;
        let crate::custody::SharePayload::Frost(f) = payload else {
            return Err(anyhow!(
                "that package carries a share this build cannot use",
            ));
        };
        // Write the public package first: if the process dies between the two,
        // a share without its package is unusable and looks broken, whereas a
        // package without a share is simply an absent share — the recoverable
        // side of the failure.
        self.dkg_write_portable(&dkg, "pkp", &f.public_package)?;
        self.dkg_write(&dkg, "share", &f.key_share)?;
        // Prove the restore actually worked by reading back what was stored,
        // rather than trusting the write. This is the same discipline as export:
        // the failure being guarded is one that only shows up on re-read.
        let restored = match (
            self.dkg_artifact(&dkg, "share"),
            self.dkg_artifact(&dkg, "pkp"),
        ) {
            (ArtifactRead::Present(s), ArtifactRead::Present(p)) => (s, p),
            _ => return Err(anyhow!("the restored share could not be read back")),
        };
        if let Err(e) = crate::dkg::validate_share(&restored.0, &restored.1, index) {
            return Err(anyhow!("the restored share does not validate: {e:#}"));
        }
        // The share is on disk and validated by now, so a failure to drive the
        // ceremony is worth reporting but must not deny the restore.
        let incomplete = match self.dkg_advance() {
            Ok(progress) => progress.install_incomplete,
            Err(e) => Some(e),
        };
        Ok(CustodyImport {
            ceremony: dkg,
            incomplete,
        })
    }

    /// What this device can say about recovery right now.
    pub fn recovery_status(&self) -> RecoveryStatus {
        let authority = self.current_authority();
        // Shape describes the STANDING arrangement. Deriving it from a session
        // we can use would report a fictitious 1-of-1 for exactly the holder
        // whose share has gone missing — the case where the real shape matters
        // most, because it says whether anyone else can still recover.
        let standing = self.standing_dkg_session();
        let scheme = standing
            .and_then(|id| self.dkg_manifest(&id))
            .map(|m| m.configuration.scheme)
            .unwrap_or(crate::authority::AuthorityScheme::Single);
        let (k, n) = standing
            .and_then(|id| self.dkg_manifest(&id))
            .and_then(|m| m.configuration.as_frost_threshold())
            .map(|c| (c.k, c.participants.len() as u16))
            .unwrap_or((1, 1));
        // Consider every ceremony this device is a custodian of, not only the
        // standing one. A PENDING indispensable arrangement is precisely the
        // case worth reporting: its install is blocked on this device, and
        // saying "Ready" because some other authority is currently fine would
        // hide the one thing the operator needs to act on.
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let mine: Vec<crate::dkg::TranscriptId> = board
            .dkg
            .iter()
            .filter(|(id, t)| {
                self.accepted_proposal(id, t)
                    .is_some_and(|(_, _, ps)| ps.contains(&self.me))
            })
            .map(|(id, _)| *id)
            .collect();
        // Worst state wins: an unusable share outranks an unbacked one, which
        // outranks a healthy one.
        let mut state = if self.read_space_recovery_key().is_some() && standing.is_none() {
            LocalCustodyState::Ready
        } else {
            // Anyone else starts as not-a-holder and is upgraded by whatever
            // shares they turn out to hold.
            LocalCustodyState::NotAHolder
        };
        for id in &mine {
            match self.dkg_artifact(id, "share") {
                ArtifactRead::Unreadable(e) => {
                    return RecoveryStatus {
                        authority: authority.map(|a| a.public_key.short()),
                        scheme,
                        k,
                        n,
                        local_custody: LocalCustodyState::Unreadable(match e {
                            crate::secretfs::SecretError::Undecryptable(m) => {
                                RecoveryArtifactFailure::Undecryptable(m)
                            }
                            crate::secretfs::SecretError::Io(e) => {
                                RecoveryArtifactFailure::Io(e.to_string())
                            }
                        }),
                    };
                }
                ArtifactRead::Present(_) => {
                    let attested = board
                        .dkg
                        .get(id)
                        .map(|t| t.custody_acks().contains(&self.me))
                        .unwrap_or(false);
                    if self.is_indispensable(id) && !attested {
                        state = LocalCustodyState::BackupUnverified;
                    } else if state == LocalCustodyState::NotAHolder {
                        state = LocalCustodyState::Ready;
                    }
                }
                ArtifactRead::Missing => {
                    // Only a gap in the STANDING authority is a missing share;
                    // mid-DKG absence is ordinary progress, not a fault.
                    //
                    // This compares against the standing session rather than the
                    // usable one. `active_dkg_session` requires a readable share,
                    // so asking it here could never be true when the share is
                    // missing — the condition was unreachable, and a holder whose
                    // standing share disappeared reported as "not a holder".
                    if Some(*id) == standing && state == LocalCustodyState::NotAHolder {
                        state = LocalCustodyState::Missing;
                    }
                }
            }
        }
        let local_custody = state;
        RecoveryStatus {
            authority: authority.map(|a| a.public_key.short()),
            scheme,
            k,
            n,
            local_custody,
        }
    }

    /// The authority standing right now: its public key, and the arrangement
    /// operating it.
    ///
    /// The key comes from the space plane. The *arrangement* does not — the
    /// plane deliberately knows nothing about signing topology — so it comes
    /// from this device's own acceptance record for the ceremony that produced
    /// the key. A solo bootstrap key has no ceremony and is `Single` by
    /// construction.
    ///
    /// Deliberately reads manifests rather than re-deriving acceptance from the
    /// board: acceptance already asks "does this proposal replace the standing
    /// authority?", so resolving the standing authority through acceptance would
    /// be mutually recursive. The manifest is written only *after* a genuine
    /// acceptance, and the group key is still DERIVED from the public-key
    /// package rather than read from a file naming it, so the filesystem is an
    /// index here and not a source of authority.
    ///
    /// `None` when a group key is standing that this device cannot attribute to
    /// any accepted ceremony: we know a key is in force but not what governs it,
    /// and answering `Single` there would let a proposal claim to replace an
    /// arrangement nobody has seen.
    pub fn current_authority(&self) -> Option<crate::authority::AuthorityId> {
        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        if let Some(secret) = self.read_space_recovery_key() {
            let pubkey = crate::space::recovery_pub_of(&secret);
            if crate::space::recovery_commit(&pubkey) == Some(cur.recovery_commit) {
                return Some(crate::authority::AuthorityId::single(pubkey));
            }
        }
        // Prefer the manifest whose configuration is the STANDING one (same-key
        // reshares leave several transcripts sharing the key); fall back to the
        // key-only match.
        let mut key_only: Option<crate::authority::AuthorityId> = None;
        for (id, manifest) in self.dkg_manifests() {
            let Some(group_key) = self.group_key_of_transcript(&id) else {
                continue;
            };
            if crate::space::recovery_commit(&group_key) == Some(cur.recovery_commit) {
                let claimed =
                    crate::authority::AuthorityId::new(group_key, &manifest.configuration);
                if claimed.configuration == cur.configuration {
                    return Some(claimed);
                }
                key_only.get_or_insert(claimed);
            }
        }
        key_only
    }

    /// Every acceptance record on this device, keyed by transcript.
    pub fn dkg_manifests(&self) -> Vec<(crate::dkg::TranscriptId, crate::dkg::DkgManifest)> {
        let dir = self.dir.join("dkg");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(hex) = name.strip_suffix("-manifest") else {
                continue;
            };
            // Strict: a non-canonical filename names no transcript.
            let Some(id) = crate::dkg::TranscriptId::parse_hex(hex) else {
                continue;
            };
            if let Some(m) = self.dkg_manifest(&id) {
                out.push((id, m));
            }
        }
        out
    }

    /// The verified, retention-filtered ceremony board.
    ///
    /// The **only** way this file obtains a board. `parse_board` alone leaves
    /// signing rounds unrestricted, so a caller that forgot the second step
    /// would silently reintroduce an unbounded signing projection; routing every
    /// caller through here makes that impossible to forget.
    ///
    /// The fallback resolves an authority whose proposal is not in the
    /// projection through this device's own accepted manifest — authenticated
    /// local state, never a participant list taken from the signing request.
    fn ceremony_board(
        &self,
        events: &[crate::space::SignedSpaceEvent],
    ) -> crate::dkg::CeremonyBoard {
        let mut board = crate::dkg::parse_board(events, &self.space);
        board.restrict_signing_rounds(|authority| {
            self.dkg_manifest(authority).and_then(|m| {
                m.configuration
                    .as_frost_threshold()?
                    .participants
                    .iter()
                    .map(|p| p.as_device())
                    .collect()
            })
        });
        board
    }

    /// A DKG transcript's configuration, **only if the proposal is accepted**.
    ///
    /// The device signature on a proposal proves control of a device and nothing
    /// more. Acceptance requires an authorization signed by the key that is the
    /// space's recovery authority — without this, any device could post a
    /// proposal for a transcript and supply its `(n, k, participants)`, which on
    /// the node that initiated an elevation and holds the recovery key would be
    /// installed as the new recovery authority.
    ///
    /// Two ways to satisfy it, and the second is not a weaker path:
    /// - the authorizer IS the standing authority; or
    /// - we recorded a [`crate::dkg::DkgManifest`] for this exact proposal
    ///   earlier, i.e. it was the standing authority when we accepted. Required
    ///   because a successful elevation *rotates* the authority: re-checking
    ///   against the standing key would un-accept every transcript at the moment
    ///   it succeeds, orphaning holders mid-DKG.
    ///
    /// Well-formedness is re-checked here rather than trusted from the proposer:
    /// `space_elevate` sorts and dedupes, but a hostile proposer does not.
    fn accepted_proposal(
        &self,
        dkg: &crate::dkg::TranscriptId,
        t: &crate::dkg::DkgTranscript,
    ) -> Option<(u16, u16, Vec<DeviceId>)> {
        let proposal = t.proposal.as_ref()?;
        let crate::dkg::CeremonyOp::DkgPropose(p) = &proposal.op else {
            return None;
        };
        // Well-formedness and scheme support are the configuration's own rules,
        // re-checked at every acceptor rather than trusted from the proposer.
        // A reshare proposal must additionally carry valid standing-arrangement
        // bindings (configuration hash, derivable old group key).
        let cfg = p.frost_config()?;
        if p.is_reshare() && p.reshare_context().is_none() {
            return None;
        }
        let participants = p.frost_devices()?;
        let (n, k) = (participants.len() as u16, cfg.k);

        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        // `parse_board` already checked every detached signature; what it cannot
        // know is which signer is the standing authority. Scanning ALL retained
        // authorizations — rather than one slot — is what stops a wrong-key
        // authorization from displacing the right one, and makes the outcome a
        // function of authority validation rather than of board order.
        // Fresh acceptance needs BOTH: the proposal targets the authority
        // standing right now, and a grant from that authority is present.
        //
        // The target check lives here rather than as a hard gate because a
        // successful ceremony rotates the authority it named — so a gate would
        // make every transcript un-accept itself at the moment it succeeded,
        // stranding holders mid-DKG and orphaning the very group it created.
        let fresh = self.claims_the_standing_authority(p.current_authority())
            && t.auths
                .values()
                .any(|g| crate::space::recovery_commit(&g.author) == Some(cur.recovery_commit));
        // Or: the authority that was standing when we accepted, whose
        // authorization must still be present. A successful elevation rotates
        // the authority, so `fresh` alone would un-accept every transcript at the
        // moment it succeeds and orphan holders mid-DKG.
        let recorded = self.dkg_manifest(dkg).is_some_and(|m| {
            m.proposal == *dkg
                && m.proposal_author == proposal.author
                && m.configuration == p.configuration
                && t.auths.contains_key(&m.authorized_by)
        });
        (fresh || recorded).then(|| (n, k, participants.clone()))
    }

    /// This transcript's local acceptance record, if we wrote one.
    pub fn dkg_manifest(&self, dkg: &crate::dkg::TranscriptId) -> Option<crate::dkg::DkgManifest> {
        postcard::from_bytes(&self.dkg_read(dkg, "manifest")?).ok()
    }

    /// The DKG transcript whose group key is the space's **standing**
    /// recovery authority, whether or not this device can use its share.
    ///
    /// Separate from [`Self::active_dkg_session`] because conflating them makes
    /// two states unreportable. The old single accessor required a readable
    /// share, so a holder whose standing share went missing or unreadable
    /// resolved to `None` and was reported as "not a holder" — the one answer
    /// that is definitely wrong — and the arrangement's shape fell back to a
    /// fictitious 1-of-1.
    ///
    /// Resolution does not depend on the share: the public-key package is stored
    /// portable precisely so a device that has lost its secret can still say
    /// which group it belongs to. Failing that, an acceptance record names the
    /// configuration.
    pub fn standing_dkg_session(&self) -> Option<crate::dkg::TranscriptId> {
        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        // A same-key reshare leaves several transcripts sharing the standing
        // KEY; the standing *arrangement* disambiguates. Prefer the manifest
        // whose configuration is on-plane, falling back to key-only match for
        // material predating the configuration commitment.
        let matches: Vec<(crate::dkg::TranscriptId, crate::dkg::DkgManifest)> = self
            .dkg_manifests()
            .into_iter()
            .filter(|(id, _)| {
                self.group_key_of_transcript(id)
                    .as_ref()
                    .and_then(crate::space::recovery_commit)
                    == Some(cur.recovery_commit)
            })
            .collect();
        matches
            .iter()
            .find(|(_, m)| m.configuration.id() == cur.configuration)
            .or_else(|| matches.first())
            .map(|(id, _)| *id)
    }

    /// The standing transcript **whose share this device can actually use**.
    ///
    /// This is the signing accessor: everything that needs to produce a
    /// signature needs a readable share, and a holder that cannot read its own
    /// share must not be treated as able to contribute.
    pub fn active_dkg_session(&self) -> Option<crate::dkg::TranscriptId> {
        let id = self.standing_dkg_session()?;
        matches!(self.dkg_artifact(&id, "share"), ArtifactRead::Present(_)).then_some(id)
    }

    /// This transcript's group key, recomputed from the stored public-key
    /// package. Never read from a `-group` file: a plaintext artifact naming the
    /// rotation target is a swap target, and the value is derivable.
    pub fn group_key_of_transcript(&self, t: &crate::dkg::TranscriptId) -> Option<DeviceId> {
        crate::dkg::group_key_of_package(&self.dkg_read(t, "pkp")?).ok()
    }

    /// Advance one FROST threshold-signing transcript over the bulletin board.
    ///
    /// Any available K holders can sign, not a predetermined K. That needs a
    /// single canonical answer to "which K", because a signature share binds to
    /// the whole signing package and two holders signing under different
    /// packages produce shares that do not aggregate — and a holder signing
    /// twice under different packages with one nonce leaks its share outright.
    ///
    /// The answer is the [`SigningPlan`], published by the coordinator the
    /// request names. Holders do not trust it: every selected signer re-derives
    /// the message, checks each commitment against what its author actually
    /// posted, confirms its own commitment is unchanged, and only then binds its
    /// nonce record to the plan. What the coordinator supplies is a *choice*,
    /// not an input to the cryptography.
    ///
    /// [`SigningPlan`]: crate::dkg::SigningPlan
    /// `install_incomplete` is an out-parameter rather than part of the return
    /// value because the caller isolates this function's `Err` — one participant's
    /// bad package must not wedge the import — and a failed re-key after our own
    /// durable install must survive exactly that isolation.
    fn sign_advance_session(
        &mut self,
        signing: &crate::dkg::TranscriptId,
        t: &crate::dkg::SignTranscript,
        board: &crate::dkg::CeremonyBoard,
        install_incomplete: &mut Option<anyhow::Error>,
    ) -> Result<bool> {
        let Some(request) = t.request.as_ref() else {
            return Ok(false);
        };
        let crate::dkg::CeremonyOp::SignRequest {
            authority,
            target,
            coordinator,
            op: op_bytes,
            ..
        } = &request.op
        else {
            return Ok(false);
        };
        let Some(dkg_t) = board.dkg.get(authority) else {
            return Ok(false);
        };
        let Some((_, threshold, participants)) = self.accepted_proposal(authority, dkg_t) else {
            return Ok(false);
        };
        let (Some(share), Some(pkp)) = (
            self.dkg_read(authority, "share"),
            self.dkg_read(authority, "pkp"),
        ) else {
            return Ok(false);
        };
        let Ok(group_key) = crate::dkg::group_key_of_package(&pkp) else {
            return Ok(false);
        };
        let index_of = |dev: &DeviceId| {
            participants
                .iter()
                .position(|p| p == dev)
                .map(|i| i as u16 + 1)
        };
        let Some(my_index) = index_of(&self.me) else {
            return Ok(false);
        };
        // Consent gate: we contribute only to a request we ourselves authorized,
        // byte-for-byte. Without it, posting a Recover-to-me request would let
        // honest holders' shares hand the space over.
        if self.dkg_read(signing, "intent").as_deref() != Some(op_bytes.as_slice()) {
            return Ok(false);
        }
        // Domain separation. The message is built under the domain matching what
        // the signature is FOR, and the finished signature is installed on the
        // matching plane. Postcard is not self-describing and
        // `CeremonyOp::DkgPropose` shares variant tag 0 with `SpaceOp::Recover`,
        // so signing ceremony bytes under the space domain would not merely be
        // misfiled — it would be a type-confusion primitive. No default arm: a
        // future target must make an explicit choice here.
        let domain: &[u8] = match target {
            crate::dkg::SignTarget::SpaceOp => crate::space::SPACE_EVENT_DOMAIN,
            crate::dkg::SignTarget::AuthorityGrant => crate::dkg::AUTHORITY_GRANT_DOMAIN,
        };
        let message =
            crate::sigdag::payload_to_sign(domain, op_bytes, &group_key, &[], self.space.as_str());

        // Every commitment posted so far, keyed by index, taken from the authors
        // who actually posted them.
        let mut posted: crate::dkg::Packages = std::collections::BTreeMap::new();
        for v in &t.rounds {
            if let crate::dkg::CeremonyOp::SignRound1 { commitments, .. } = &v.op {
                if let Some(i) = index_of(&v.author) {
                    posted.entry(i).or_insert_with(|| commitments.clone());
                }
            }
        }
        let i_posted_r1 = posted.contains_key(&my_index);

        // Step 1 — commit. EVERY holder commits, not only a predetermined K:
        // that is what makes any available K able to sign. The nonce record is
        // created exclusively, since single-use material that already exists
        // must be examined rather than overwritten.
        if !i_posted_r1 && !self.dkg_has(signing, "nonce") {
            let (nonces, commitments) = crate::dkg::sign_round1(&share)?;
            let pending = crate::dkg::PendingNonce {
                signing: *signing,
                // Bound at step 3, once the coordinator has fixed the plan.
                binding: [0u8; 32],
                nonces,
            };
            self.dkg_write_new(signing, "nonce", &postcard::to_stdvec(&pending)?)?;
            self.post_ceremony(crate::dkg::CeremonyOp::SignRound1 {
                signing: *signing,
                commitments,
            })?;
            return Ok(true);
        }

        // Step 2 — the coordinator freezes a plan once enough holders have
        // committed. Only the named coordinator may do this, and only once.
        let existing_plan = t.plan();
        if existing_plan.is_none() && &self.me == coordinator && posted.len() >= threshold as usize
        {
            // Take the lowest `threshold` indices among those that committed.
            // Any qualified subset would do; a deterministic rule keeps a
            // coordinator restarted mid-flight from producing a second plan.
            let chosen: Vec<u16> = posted.keys().copied().take(threshold as usize).collect();
            let commitments: crate::dkg::Packages =
                chosen.iter().map(|i| (*i, posted[i].clone())).collect();
            let signers: Vec<crate::authority::LeafId> = chosen
                .iter()
                .map(|i| {
                    crate::authority::LeafId::of_principal(
                        &crate::authority::PrincipalId::of_device(&participants[*i as usize - 1]),
                    )
                })
                .collect();
            let Some(config) = self.dkg_manifest(authority).map(|m| m.configuration) else {
                return Ok(false);
            };
            let plan = crate::dkg::SigningPlan {
                signing: *signing,
                authority: crate::authority::AuthorityId::new(group_key.clone(), &config),
                message_commitment: *blake3::hash(&message).as_bytes(),
                signers,
                commitments,
                witness: crate::dkg::AccessWitness::FrostThreshold {
                    k: threshold,
                    participant_indices: chosen,
                },
            };
            self.post_ceremony(crate::dkg::CeremonyOp::SignPlan {
                signing: *signing,
                plan: plan.encode(),
            })?;
            return Ok(true);
        }
        let Some(plan) = existing_plan else {
            return Ok(false);
        };

        // Step 3 — validate the plan, then sign under it.
        //
        // Nothing here trusts the coordinator's arithmetic. The message is
        // re-derived; every commitment is checked against the round-1 event its
        // author actually posted; our own commitment must be the one we hold a
        // nonce for. A coordinator can choose WHO signs; it cannot choose WHAT
        // they sign or forge a commitment on their behalf.
        let crate::dkg::AccessWitness::FrostThreshold {
            k,
            participant_indices,
        } = &plan.witness
        else {
            // A witness this build cannot evaluate is refused rather than
            // assumed valid.
            return Ok(false);
        };
        let plan_ok = plan.signing == *signing
            && plan.authority.public_key == group_key
            && plan.message_commitment == *blake3::hash(&message).as_bytes()
            && *k == threshold
            && participant_indices.len() == threshold as usize
            && plan.commitments.len() == threshold as usize
            && plan.signers.len() == threshold as usize
            // Canonical ordering, so two coordinators cannot produce differing
            // encodings of the same choice.
            && participant_indices.windows(2).all(|w| w[0] < w[1])
            && participant_indices
                .iter()
                .all(|i| *i >= 1 && (*i as usize) <= participants.len())
            && plan.commitments.keys().eq(participant_indices.iter())
            // Authenticity: each commitment must be what that participant
            // actually posted, not what the coordinator says they posted.
            && plan
                .commitments
                .iter()
                .all(|(i, c)| posted.get(i) == Some(c));
        if !plan_ok {
            anyhow::bail!("refusing to sign: the coordinator's plan does not validate");
        }
        let in_plan = participant_indices.contains(&my_index);
        let i_posted_r2 = t.rounds.iter().any(|v| {
            v.author == self.me && matches!(v.op, crate::dkg::CeremonyOp::SignRound2 { .. })
        });
        if in_plan && !i_posted_r2 {
            let Some(raw) = self.dkg_read(signing, "nonce") else {
                return Ok(false);
            };
            let mut pending: crate::dkg::PendingNonce = postcard::from_bytes(&raw)?;
            // Our own commitment in the plan must be the one these nonces
            // produced. This is the check that makes a shifted signer set safe.
            if plan.commitments.get(&my_index) != posted.get(&my_index) {
                anyhow::bail!("refusing to sign: the plan carries a commitment we did not post");
            }
            let binding = crate::dkg::nonce_binding(signing, &message, &plan);
            // THE nonce-reuse gate. One stored record may produce shares for
            // exactly one plan; if the plan moved under us, refuse rather than
            // sign. The comparison — not the deletion — is what prevents reuse,
            // since a crash between publishing and deleting always leaves the
            // record behind.
            if pending.binding == [0u8; 32] {
                pending.binding = binding;
                self.dkg_write(signing, "nonce", &postcard::to_stdvec(&pending)?)?;
            } else if pending.binding != binding {
                anyhow::bail!(
                    "refusing to sign: this transcript's signing plan changed after commitment (signing again would reuse the nonce and leak the key share)"
                );
            }
            let share_sig =
                crate::dkg::sign_round2(&plan.commitments, &message, &pending.nonces, &share)?;
            self.post_ceremony(crate::dkg::CeremonyOp::SignRound2 {
                signing: *signing,
                share: share_sig,
            })?;
            // `post_ceremony` persisted the share, so the one-use material can
            // go. Order matters: never delete before the share is durable.
            let _ = std::fs::remove_file(self.dkg_path(signing, "nonce"));
            return Ok(true);
        }

        // Step 4 — any participant aggregates the plan's shares and installs.
        let mut r2: crate::dkg::Packages = std::collections::BTreeMap::new();
        for v in &t.rounds {
            if let crate::dkg::CeremonyOp::SignRound2 { share, .. } = &v.op {
                if let Some(i) = index_of(&v.author) {
                    if participant_indices.contains(&i) {
                        r2.entry(i).or_insert_with(|| share.clone());
                    }
                }
            }
        }
        if r2.len() == threshold as usize {
            let sig = crate::dkg::aggregate(&plan.commitments, &message, &r2, &pkp)?;
            let node = crate::sigdag::assemble_signed(op_bytes.clone(), group_key, sig, vec![]);
            match target {
                crate::dkg::SignTarget::SpaceOp => {
                    let fresh = !self
                        .ledger
                        .space_authority_events()
                        .iter()
                        .any(|e| e.hash() == node.hash());
                    if fresh
                        && node.verify_sig(crate::space::SPACE_EVENT_DOMAIN, self.space.as_str())
                    {
                        self.commit_space_authority(node)?;
                        // The re-root is durable now. Re-keying fences the old
                        // root, and if it fails the space stays readable under
                        // the old key — a degraded state, not a failed recovery.
                        // It must not be reported as this session erroring, or
                        // the caller's isolation would turn a false "and
                        // re-keyed" into what the operator reads.
                        if let Err(e) = self.fence_epoch() {
                            *install_incomplete = Some(e);
                        }
                        return Ok(true);
                    }
                }
                crate::dkg::SignTarget::AuthorityGrant => {
                    if crate::dkg::authority_grant_of(&node, &self.space).is_some() {
                        let already = self.ledger.ceremony_nodes().iter().any(|e| {
                            matches!(
                                postcard::from_bytes::<crate::dkg::CeremonyOp>(&e.op),
                                Ok(crate::dkg::CeremonyOp::DkgAuthorize(g)) if g.hash() == node.hash()
                            )
                        });
                        if !already {
                            self.post_ceremony(crate::dkg::CeremonyOp::DkgAuthorize(node))?;
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Advance one DKG transcript. Configuration comes **only** from the
    /// accepted proposal ([`Self::accepted_proposal`]) — never from whichever
    /// signature-valid proposal happens to sort first, which is how a rogue
    /// proposal could previously substitute `(n, k, participants)` into a
    /// transcript an honest initiator had opened.
    fn dkg_advance_session(
        &mut self,
        dkg: &crate::dkg::TranscriptId,
        t: &crate::dkg::DkgTranscript,
    ) -> Result<bool> {
        let Some((n, k, participants)) = self.accepted_proposal(dkg, t) else {
            return Ok(false);
        };
        // Record acceptance the first time we act on this proposal, so a later
        // rotation of the authority cannot orphan a transcript mid-DKG.
        if self.dkg_manifest(dkg).is_none() {
            let cur = crate::space::replay(
                &self.ledger.genesis().clone(),
                &self.space,
                &self.ledger.space_authority_events(),
            );
            // Pin WHICH authorization we accepted, not merely that one existed.
            let authorized_by = t
                .auths
                .values()
                .find(|g| crate::space::recovery_commit(&g.author) == Some(cur.recovery_commit))
                .map(|g| g.author.clone());
            if let (Some(proposal), Some(authorized_by)) = (t.proposal.as_ref(), authorized_by) {
                let crate::dkg::CeremonyOp::DkgPropose(p) = &proposal.op else {
                    return Ok(false);
                };
                let manifest = crate::dkg::DkgManifest {
                    proposal: *dkg,
                    proposal_author: proposal.author.clone(),
                    authorized_by,
                    configuration: p.configuration.clone(),
                };
                self.dkg_write(dkg, "manifest", &postcard::to_stdvec(&manifest)?)?;
            }
        }
        let index_of = |dev: &DeviceId| {
            participants
                .iter()
                .position(|p| p == dev)
                .map(|i| i as u16 + 1)
        };
        let Some(my_index) = index_of(&self.me) else {
            return Ok(false);
        };

        // Round-1 packages posted so far, keyed by participant index. Authors
        // outside the participant set resolve to no index and are dropped.
        let mut round1: crate::dkg::Packages = std::collections::BTreeMap::new();
        for v in &t.rounds {
            if let crate::dkg::CeremonyOp::DkgRound1 { package, .. } = &v.op {
                if let Some(i) = index_of(&v.author) {
                    round1.entry(i).or_insert_with(|| package.clone());
                }
            }
        }
        let i_posted_round1 = round1.contains_key(&my_index);

        // Step 1 — post my round-1.
        if !i_posted_round1 {
            let (s1, pkg) = crate::dkg::dkg_round1(my_index, n, k)?;
            self.dkg_write(dkg, "r1", &s1)?;
            self.post_ceremony(crate::dkg::CeremonyOp::DkgRound1 {
                dkg: *dkg,
                package: pkg,
            })?;
            return Ok(true);
        }

        // Step 2 — once all N round-1s are in, post my (sealed) round-2 shares.
        let i_posted_round2 = t.rounds.iter().any(|v| {
            v.author == self.me && matches!(v.op, crate::dkg::CeremonyOp::DkgRound2 { .. })
        });
        if round1.len() == n as usize && !i_posted_round2 && self.dkg_has(dkg, "r1") {
            let others: crate::dkg::Packages = round1
                .iter()
                .filter(|(i, _)| **i != my_index)
                .map(|(i, v)| (*i, v.clone()))
                .collect();
            let (s2, outgoing) =
                crate::dkg::dkg_round2(&self.dkg_read(dkg, "r1").unwrap(), &others)?;
            self.dkg_write(dkg, "r2", &s2)?;
            for (recipient_index, pkg) in outgoing {
                let recipient = participants[recipient_index as usize - 1].clone();
                let Some(sealed) = crate::crypto::seal_to(&recipient, &pkg) else {
                    continue;
                };
                self.post_ceremony(crate::dkg::CeremonyOp::DkgRound2 {
                    dkg: *dkg,
                    to: recipient,
                    sealed,
                })?;
            }
            return Ok(true);
        }

        // Step 3 — once all round-2 shares sent TO me are in, finalize my key
        // share. Only `r2`, `share` and `pkp` are persisted: everything else the
        // old code stored (`group`, `index`, `threshold`, `participants`) is
        // derivable from the accepted proposal or the public-key package, and a
        // trusted plaintext copy is only a swap target.
        let mut round2_to_me: crate::dkg::Packages = std::collections::BTreeMap::new();
        for v in &t.rounds {
            if let crate::dkg::CeremonyOp::DkgRound2 { to, sealed, .. } = &v.op {
                if to == &self.me {
                    if let (Some(sender_i), Some(pkg)) = (
                        index_of(&v.author),
                        crate::crypto::open_sealed(&self.seed, &self.me, sealed),
                    ) {
                        round2_to_me.entry(sender_i).or_insert(pkg);
                    }
                }
            }
        }
        if round2_to_me.len() == n as usize - 1
            && self.dkg_has(dkg, "r2")
            && !self.dkg_has(dkg, "share")
        {
            let others: crate::dkg::Packages = round1
                .iter()
                .filter(|(i, _)| **i != my_index)
                .map(|(i, v)| (*i, v.clone()))
                .collect();
            let (share, pkp, _group_key) =
                crate::dkg::dkg_round3(&self.dkg_read(dkg, "r2").unwrap(), &others, &round2_to_me)?;
            self.dkg_write(dkg, "share", &share)?;
            // The public-key package is PUBLIC: it needs owner-only permissions,
            // not device binding. Wrapping it would mean an account migration
            // also destroyed our ability to tell which group a stranded share
            // belongs to - the check `degraded_recovery_holders` depends on. The
            // group key is still DERIVED from it rather than trusted from a file
            // naming the key, so portability costs nothing.
            self.dkg_write_portable(dkg, "pkp", &pkp)?;
            return Ok(true);
        }

        // Step 4 — the recovery-key holder installs the group key with a Rotate.
        //
        // SECURITY. Four things must hold, and each closes a distinct path:
        // - the proposal is ACCEPTED (checked above): the recovery authority
        //   signed this exact transcript, so its configuration is not attacker-
        //   chosen;
        // - local `intent` names THIS transcript: we consented to this exact
        //   proposal, not merely to "an elevation" (the old marker was the
        //   constant `b"elevate"`, which a substituted config satisfied just as
        //   well as the real one);
        // - the group key is DERIVED from the stored public-key package, not
        //   read from a plaintext file that could be swapped;
        // - we still hold the current recovery key, and it is not already
        //   installed.
        if !self.dkg_has(dkg, "share") {
            return Ok(false);
        }
        let consented = self
            .dkg_read(dkg, "intent")
            .and_then(|b| String::from_utf8(b).ok())
            .is_some_and(|h| h == dkg.to_hex());
        if !consented {
            return Ok(false);
        }
        let Some(group_key) = self.group_key_of_transcript(dkg) else {
            return Ok(false);
        };
        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        let already = crate::space::recovery_commit(&group_key) == Some(cur.recovery_commit);
        if already {
            return Ok(false);
        }
        // The arrangement operating the new key is the candidate ceremony's own
        // configuration, committed on the space plane by the rotation, so
        // every replica (holder or not) learns the standing arrangement by
        // replay. Deterministic from the accepted proposal, so all group holders
        // sign byte-identical rotate ops.
        let Some(next_configuration) = self.dkg_manifest(dkg).map(|m| m.configuration.id()) else {
            return Ok(false);
        };
        // An INDISPENSABLE arrangement must not install until every custodian
        // has verified a portable backup. Otherwise an N-of-N authority can be
        // created in a state where one holder's share exists only behind a
        // Windows profile, and the space learns that on the day it needs to
        // recover — the day it is too late to fix.
        //
        // The gate reads signed attestations from the board rather than local
        // state, so no *other* node can install ahead of the checks. A redundant
        // arrangement is not gated: it can afford to lose a holder, which is
        // what redundancy means.
        let outstanding = self.custody_outstanding(dkg, t, &participants);
        if !outstanding.is_empty() {
            tracing::info!(
                "holding the rotation for {}: {} custodian(s) have not verified a portable backup",
                dkg.to_hex(),
                outstanding.len()
            );
            return Ok(false);
        }
        // Solo authority: sign the rotation directly.
        if let Some(secret) = self.read_space_recovery_key() {
            if crate::space::recovery_commit(&crate::space::recovery_pub_of(&secret))
                == Some(cur.recovery_commit)
            {
                let op = crate::space::SpaceOp::Rotate {
                    new_recovery_key: group_key,
                    next_configuration,
                    gen: cur.gen + 1,
                };
                let ev = crate::space::sign_op(&secret, &op, vec![], &self.space);
                self.commit_space_authority(ev)?;
                return Ok(true);
            }
        }
        // Group authority: the rotation itself needs a threshold signature.
        //
        // The grant said "this ceremony may create a candidate authority"; the
        // rotation says "install this exact candidate key". They are separate
        // authorizations, and the second must not be inferred from the first —
        // otherwise consenting to a ceremony would silently consent to whatever
        // key someone later claims it produced.
        //
        // What makes it safe to open and consent automatically here is that
        // `group_key` was DERIVED from this device's own public-key package for
        // this transcript, moments ago. Every holder does the same derivation
        // independently on its own node, so no holder is ever asked to trust a
        // key it did not compute. A holder that cannot derive it — not a
        // participant in the new ceremony — never reaches this point and so
        // never signs.
        if self.active_dkg_session().is_some() {
            let (_, changed) =
                self.open_rotation_request(&group_key, next_configuration, cur.gen + 1)?;
            return Ok(changed);
        }
        Ok(false)
    }

    /// The transcript this device accepted for the standing arrangement a
    /// reshare proposal redistributes — where its old share artifacts live.
    fn transcript_of_reshare_source(
        &self,
        ctx: &crate::dkg::ReshareContext,
    ) -> Option<crate::dkg::TranscriptId> {
        self.dkg_manifests().into_iter().find_map(|(id, m)| {
            (m.configuration.id() == ctx.authority.configuration
                && self.group_key_of_transcript(&id).as_ref() == Some(&ctx.authority.public_key))
            .then_some(id)
        })
    }

    /// Advance one **same-key reshare** transcript over the bulletin board.
    ///
    /// Roles, all driven from this one pass:
    /// - an OLD holder deals: posts its Feldman commitments once and a sealed
    ///   sub-share to every new participant, from persisted material (a retry
    ///   re-posts the SAME polynomial, never a second one);
    /// - the proposal author freezes the qualified old set (a `ResharePlan`)
    ///   once enough dealers posted complete material — every combiner must
    ///   use the same set, or their shares would belong to different
    ///   polynomials;
    /// - a NEW participant combines once the plan and every qualified dealer's
    ///   material are present, verifying each dealer's `C_0` against the
    ///   authenticated old verifying shares, and persists its share + package;
    /// - the CURRENT group opens/joins the threshold signing of the terminal
    ///   `Reshare` installation — gated on complete material and, for an
    ///   indispensable new arrangement, on every custodian's attestation.
    fn reshare_advance_session(
        &mut self,
        dkg: &crate::dkg::TranscriptId,
        t: &crate::dkg::DkgTranscript,
    ) -> Result<bool> {
        let Some(proposal_node) = t.proposal.as_ref() else {
            return Ok(false);
        };
        let crate::dkg::CeremonyOp::DkgPropose(p) = &proposal_node.op else {
            return Ok(false);
        };
        let Some(ctx) = p.reshare_context() else {
            return Ok(false);
        };
        // Record acceptance the first time we act on this proposal (the same
        // rule as a rotation DKG: a later authority change must not orphan a
        // transcript mid-flight).
        if self.dkg_manifest(dkg).is_none() {
            let cur = crate::space::replay(
                &self.ledger.genesis().clone(),
                &self.space,
                &self.ledger.space_authority_events(),
            );
            let authorized_by = t
                .auths
                .values()
                .find(|g| crate::space::recovery_commit(&g.author) == Some(cur.recovery_commit))
                .map(|g| g.author.clone());
            if let Some(authorized_by) = authorized_by {
                let manifest = crate::dkg::DkgManifest {
                    proposal: *dkg,
                    proposal_author: proposal_node.author.clone(),
                    authorized_by,
                    configuration: p.configuration.clone(),
                };
                self.dkg_write(dkg, "manifest", &postcard::to_stdvec(&manifest)?)?;
            }
        }
        let new_k = ctx.new_config.k;
        let new_n = ctx.new_devices.len() as u16;
        let old_k = ctx.old_config.k;
        let old_index_of = |dev: &DeviceId| {
            ctx.old_devices
                .iter()
                .position(|d| d == dev)
                .map(|i| i as u16 + 1)
        };
        let new_index_of = |dev: &DeviceId| {
            ctx.new_devices
                .iter()
                .position(|d| d == dev)
                .map(|i| i as u16 + 1)
        };

        // Index the posted reshare material. Authors outside the old set
        // resolve to no index and are dropped; the plan counts only from the
        // proposal author.
        let mut commits: std::collections::BTreeMap<u16, Vec<u8>> =
            std::collections::BTreeMap::new();
        let mut deals: std::collections::BTreeMap<(u16, DeviceId), Vec<u8>> =
            std::collections::BTreeMap::new();
        let mut plan: Option<Vec<u16>> = None;
        for v in &t.rounds {
            match &v.op {
                crate::dkg::CeremonyOp::ReshareCommit { commitments, .. } => {
                    if let Some(i) = old_index_of(&v.author) {
                        commits.entry(i).or_insert_with(|| commitments.clone());
                    }
                }
                crate::dkg::CeremonyOp::ReshareDeal { to, sealed, .. } => {
                    if let Some(i) = old_index_of(&v.author) {
                        deals
                            .entry((i, to.clone()))
                            .or_insert_with(|| sealed.clone());
                    }
                }
                crate::dkg::CeremonyOp::ResharePlan { qualified, .. }
                    if v.author == proposal_node.author =>
                {
                    plan.get_or_insert(qualified.clone());
                }
                _ => {}
            }
        }

        // Step 1 — dealer: an OLD holder posts commitments + sealed deals,
        // exactly once, from persisted material.
        if let Some(my_old) = old_index_of(&self.me) {
            if let Some(old_tx) = self.transcript_of_reshare_source(&ctx) {
                if let Some(old_share) = self.dkg_read(&old_tx, "share") {
                    let material: Option<(Vec<u8>, crate::dkg::Packages)> =
                        match self.dkg_read(dkg, "rdeal") {
                            Some(raw) => postcard::from_bytes(&raw).ok(),
                            None => {
                                let dealt = crate::dkg::reshare_deal(&old_share, new_k, new_n)?;
                                self.dkg_write_new(dkg, "rdeal", &postcard::to_stdvec(&dealt)?)?;
                                Some(dealt)
                            }
                        };
                    if let Some((blob, subs)) = material {
                        let mut posted_any = false;
                        if !commits.contains_key(&my_old) {
                            self.post_ceremony(crate::dkg::CeremonyOp::ReshareCommit {
                                dkg: *dkg,
                                commitments: blob,
                            })?;
                            posted_any = true;
                        }
                        for (j, device) in ctx.new_devices.iter().enumerate() {
                            let jdx = j as u16 + 1;
                            if deals.contains_key(&(my_old, device.clone())) {
                                continue;
                            }
                            let Some(sub) = subs.get(&jdx) else { continue };
                            let Some(sealed) = crate::crypto::seal_to(device, sub) else {
                                continue;
                            };
                            self.post_ceremony(crate::dkg::CeremonyOp::ReshareDeal {
                                dkg: *dkg,
                                to: device.clone(),
                                sealed,
                            })?;
                            posted_any = true;
                        }
                        if posted_any {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        // Step 2 — the proposal author freezes the qualified old set once
        // enough dealers posted complete material (commit + a deal to every
        // new participant).
        let dealer_complete = |i: &u16| {
            commits.contains_key(i)
                && ctx
                    .new_devices
                    .iter()
                    .all(|d| deals.contains_key(&(*i, d.clone())))
        };
        if plan.is_none() && self.me == proposal_node.author {
            let complete: Vec<u16> = commits.keys().copied().filter(dealer_complete).collect();
            if complete.len() >= old_k as usize {
                let qualified: Vec<u16> = complete.into_iter().take(old_k as usize).collect();
                self.post_ceremony(crate::dkg::CeremonyOp::ResharePlan {
                    dkg: *dkg,
                    qualified,
                })?;
                return Ok(true);
            }
        }
        let Some(qualified) = plan else {
            return Ok(false);
        };
        // The plan is a coordinator's CHOICE, never trusted arithmetic.
        let plan_ok = qualified.len() == old_k as usize
            && qualified.windows(2).all(|w| w[0] < w[1])
            && qualified
                .iter()
                .all(|i| *i >= 1 && (*i as usize) <= ctx.old_devices.len());
        if !plan_ok {
            anyhow::bail!("refusing to combine: the reshare plan does not validate");
        }

        // Step 3 — a NEW participant combines once every qualified dealer's
        // commitments and deal-to-me are present. `reshare_finalize`
        // re-verifies each dealer's C_0 against the authenticated old
        // verifying shares and that the recombined key IS the standing key.
        if let Some(my_new) = new_index_of(&self.me) {
            if !self.dkg_has(dkg, "share") {
                let mut my_commits: std::collections::BTreeMap<u16, Vec<u8>> =
                    std::collections::BTreeMap::new();
                let mut my_subs: std::collections::BTreeMap<u16, Vec<u8>> =
                    std::collections::BTreeMap::new();
                let mut complete = true;
                for &i in &qualified {
                    let (Some(c), Some(sealed)) =
                        (commits.get(&i), deals.get(&(i, self.me.clone())))
                    else {
                        complete = false;
                        break;
                    };
                    let Some(sub) = crate::crypto::open_sealed(&self.seed, &self.me, sealed) else {
                        complete = false;
                        break;
                    };
                    my_commits.insert(i, c.clone());
                    my_subs.insert(i, sub);
                }
                if complete {
                    let (share, pkp, _group) = crate::dkg::reshare_finalize(
                        my_new,
                        new_k,
                        new_n,
                        &qualified,
                        &my_commits,
                        &my_subs,
                        &ctx.old_public_package,
                    )?;
                    self.dkg_write(dkg, "share", &share)?;
                    self.dkg_write_portable(dkg, "pkp", &pkp)?;
                    return Ok(true);
                }
            }
        }

        // Step 4 — the CURRENT group threshold-signs the terminal `Reshare`
        // installation. Consent binds to the transcript we accepted; material
        // must be complete for the whole qualified set, and an indispensable
        // new arrangement waits for every custodian's attestation.
        let cur = crate::space::replay(
            &self.ledger.genesis().clone(),
            &self.space,
            &self.ledger.space_authority_events(),
        );
        if cur.configuration == p.configuration.id() {
            return Ok(false); // already installed
        }
        let consented = self
            .dkg_read(dkg, "intent")
            .and_then(|b| String::from_utf8(b).ok())
            .is_some_and(|h| h == dkg.to_hex());
        if !consented {
            return Ok(false);
        }
        if !qualified.iter().all(dealer_complete) {
            return Ok(false);
        }
        let outstanding = self.custody_outstanding(dkg, t, &ctx.new_devices);
        if !outstanding.is_empty() {
            tracing::info!(
                "holding the reshare installation for {}: {} custodian(s) have not verified a portable backup",
                dkg.to_hex(),
                outstanding.len()
            );
            return Ok(false);
        }
        if self.active_dkg_session().is_some() {
            let (_, changed) = self.open_reshare_install(p.configuration.id(), cur.gen + 1)?;
            return Ok(changed);
        }
        Ok(false)
    }

    /// Open (or join) a threshold-signing transcript asking the standing group
    /// to install the reshared arrangement, and record our consent.
    fn open_reshare_install(
        &mut self,
        next_configuration: crate::authority::AuthorityConfigurationId,
        gen: u32,
    ) -> Result<(crate::dkg::TranscriptId, bool)> {
        let authority = self
            .active_dkg_session()
            .ok_or_else(|| anyhow!("this device holds no share of the current group key"))?;
        let op = crate::space::SpaceOp::Reshare {
            next_configuration,
            gen,
        };
        let op_bytes = postcard::to_stdvec(&op)?;
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let threshold = board
            .dkg
            .get(&authority)
            .and_then(|t| self.accepted_proposal(&authority, t))
            .map(|(_, k, _)| k)
            .unwrap_or(0);
        let mut changed = false;
        let signing = match self.canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::SpaceOp,
            &op_bytes,
            threshold,
        ) {
            Some(id) => id,
            None => {
                let req = crate::dkg::CeremonyOp::SignRequest {
                    nonce: rand16(),
                    authority,
                    target: crate::dkg::SignTarget::SpaceOp,
                    coordinator: self.me.clone(),
                    op: op_bytes.clone(),
                };
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.space);
                let id = crate::dkg::TranscriptId::of(&ev)
                    .ok_or_else(|| anyhow!("could not derive the request id"))?;
                self.commit_ceremony_material(ev)?;
                changed = true;
                id
            }
        };
        if self.dkg_read(&signing, "intent").as_deref() != Some(op_bytes.as_slice()) {
            self.dkg_write(&signing, "intent", &op_bytes)?;
            changed = true;
        }
        Ok((signing, changed))
    }

    /// Open (or join) a threshold-signing transcript asking the standing group to
    /// install `new_key` as the recovery authority, and record our consent.
    ///
    /// Requires the caller to have derived `new_key` itself. Note the resulting
    /// constraint: the signing threshold of the *current* group must overlap the
    /// participants of the *new* ceremony, because only a new participant holds
    /// the package the key is derived from. Replacing one holder satisfies this
    /// easily; a handover to a wholly disjoint set does not, and would need an
    /// attested candidate key rather than a locally derived one.
    fn open_rotation_request(
        &mut self,
        new_key: &DeviceId,
        next_configuration: crate::authority::AuthorityConfigurationId,
        gen: u32,
    ) -> Result<(crate::dkg::TranscriptId, bool)> {
        let authority = self
            .active_dkg_session()
            .ok_or_else(|| anyhow!("this device holds no share of the current group key"))?;
        let op = crate::space::SpaceOp::Rotate {
            new_recovery_key: new_key.clone(),
            next_configuration,
            gen,
        };
        let op_bytes = postcard::to_stdvec(&op)?;
        let events = self.ledger.ceremony_nodes();
        let board = self.ceremony_board(&events);
        let threshold = board
            .dkg
            .get(&authority)
            .and_then(|t| self.accepted_proposal(&authority, t))
            .map(|(_, k, _)| k)
            .unwrap_or(0);
        let mut changed = false;
        let signing = match self.canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::SpaceOp,
            &op_bytes,
            threshold,
        ) {
            Some(id) => id,
            None => {
                let req = crate::dkg::CeremonyOp::SignRequest {
                    nonce: rand16(),
                    authority,
                    target: crate::dkg::SignTarget::SpaceOp,
                    coordinator: self.me.clone(),
                    op: op_bytes.clone(),
                };
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.space);
                let id = crate::dkg::TranscriptId::of(&ev)
                    .ok_or_else(|| anyhow!("could not derive the request id"))?;
                self.commit_ceremony_material(ev)?;
                changed = true;
                id
            }
        };
        if self.dkg_read(&signing, "intent").as_deref() != Some(op_bytes.as_slice()) {
            self.dkg_write(&signing, "intent", &op_bytes)?;
            changed = true;
        }
        Ok((signing, changed))
    }

    fn post_ceremony(&mut self, op: crate::dkg::CeremonyOp) -> Result<()> {
        let ev = crate::dkg::sign_ceremony(&self.seed, &op, &self.space);
        self.commit_ceremony_material(ev)
    }
}

/// The ceremony packet hashes that are **terminal** — safe to compact behind a
/// durable audit commitment — given the retained board nodes and the standing
/// space-plane state.
///
/// A packet is terminal iff it belongs to a threshold-signing transcript that
/// can no longer change anything:
///
/// - a `SignTarget::SpaceOp` transcript whose requested op names a generation
///   `<= root_state.gen`: either its terminal effect already installed (the
///   plane advanced past it) or the monotone generation rule fences it
///   forever;
/// - a `SignTarget::AuthorityGrant` transcript whose named proposal created
///   the arrangement that is now **standing** (`root_state.configuration`
///   matches): the elevation completed, and the grant's aggregated outcome
///   (`DkgAuthorize`) is retained on the board independently of the signing
///   rounds that produced it.
///
/// Everything else — active transcripts, every DKG packet, authorizations and
/// custody attestations — is retained: material an acceptor needs to validate
/// the standing authority or prove custody may not be dropped.
pub fn terminal_compactable(
    nodes: &[SignedSpaceEvent],
    space: &SpaceId,
    root_state: &RootState,
) -> Vec<String> {
    let board = dkg::parse_board(nodes, space);
    let mut drop: Vec<String> = Vec::new();
    for transcript in board.signing.values() {
        let Some(request) = transcript.request.as_ref() else {
            continue;
        };
        let CeremonyOp::SignRequest { target, op, .. } = &request.op else {
            continue;
        };
        let terminal = match target {
            SignTarget::SpaceOp => match postcard::from_bytes::<SpaceOp>(op) {
                Ok(SpaceOp::Recover { gen, .. })
                | Ok(SpaceOp::Rotate { gen, .. })
                | Ok(SpaceOp::Reshare { gen, .. }) => gen <= root_state.gen,
                // An undecodable request can never install anything; its
                // transcript is inert, but keep it (cheap, and dropping
                // unclassifiable material is the wrong default).
                Err(_) => false,
            },
            SignTarget::AuthorityGrant => match postcard::from_bytes::<dkg::AuthorityGrant>(op) {
                Ok(grant) => board
                    .dkg
                    .get(&grant.proposal)
                    .and_then(|t| t.proposal.as_ref())
                    .and_then(|p| match &p.op {
                        CeremonyOp::DkgPropose(prop) => Some(prop.configuration.id()),
                        _ => None,
                    })
                    .is_some_and(|id| id == root_state.configuration),
                Err(_) => false,
            },
        };
        if terminal {
            drop.push(request.id.to_hex());
            for round in &transcript.rounds {
                drop.push(round.id.to_hex());
            }
        }
    }
    drop.sort();
    drop.dedup();
    drop
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{AuthorityConfigurationId, AuthorityId};
    use crate::ids::{DeviceId, SystemUlidSource};

    fn space() -> SpaceId {
        SpaceId::mint(&SystemUlidSource)
    }

    fn root_state(gen: u32) -> RootState {
        RootState {
            root: vec![],
            recovery_commit: [0u8; 32],
            configuration: AuthorityConfigurationId::single(),
            gen,
            recovered: gen > 0,
        }
    }

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// A signing request over a `Recover { gen }` plus one round, on a board
    /// with an authorized proposal so retention keeps the rounds.
    fn recover_request_nodes(ws: &SpaceId, gen: u32) -> (Vec<SignedSpaceEvent>, String) {
        // The transcript's authority: a 2-of-2 dkg proposal by device 1.
        let me = crate::crypto::device_from_seed(&seed(1));
        let other = crate::crypto::device_from_seed(&seed(2));
        let mut participants: Vec<crate::authority::PrincipalId> = vec![
            crate::authority::PrincipalId::of_device(&me),
            crate::authority::PrincipalId::of_device(&other),
        ];
        participants.sort();
        let proposal_op = CeremonyOp::DkgPropose(dkg::frost_rotation_proposal(
            [gen as u8; 16],
            2,
            participants,
            AuthorityId::single(DeviceId::from_key_string("00".repeat(32))),
        ));
        let proposal = dkg::sign_ceremony(&seed(1), &proposal_op, ws);
        let authority = dkg::TranscriptId::of(&proposal).unwrap();
        let op_bytes = postcard::to_stdvec(&SpaceOp::Recover {
            new_root: vec![crate::ids::ActorId::from_incept_hash(&"ab".repeat(32))],
            gen,
        })
        .unwrap();
        let request = dkg::sign_ceremony(
            &seed(1),
            &CeremonyOp::SignRequest {
                nonce: [gen as u8; 16],
                authority,
                target: SignTarget::SpaceOp,
                coordinator: me,
                op: op_bytes,
            },
            ws,
        );
        let signing = dkg::TranscriptId::of(&request).unwrap();
        let round = dkg::sign_ceremony(
            &seed(1),
            &CeremonyOp::SignRound1 {
                signing,
                commitments: vec![1, 2, 3],
            },
            ws,
        );
        let request_hash = request.hash();
        (vec![proposal, request, round], request_hash)
    }

    #[test]
    fn a_fenced_generation_signing_transcript_is_terminal() {
        let ws = space();
        let (nodes, request_hash) = recover_request_nodes(&ws, 1);
        // Current gen 1: the gen-1 request either installed or is fenced.
        let drop = terminal_compactable(&nodes, &ws, &root_state(1));
        assert!(drop.contains(&request_hash), "request compacts");
        // The proposal (a DKG packet) is never in the drop set.
        assert!(!drop.contains(&nodes[0].hash()), "dkg proposal retained");
    }

    #[test]
    fn an_active_next_generation_transcript_is_retained() {
        let ws = space();
        let (nodes, request_hash) = recover_request_nodes(&ws, 1);
        // Current gen 0: the gen-1 request is the ACTIVE next step.
        let drop = terminal_compactable(&nodes, &ws, &root_state(0));
        assert!(
            !drop.contains(&request_hash),
            "an active transcript may not be compacted"
        );
        assert!(drop.is_empty());
    }
}
