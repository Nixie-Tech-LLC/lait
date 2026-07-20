//! Break-glass space recovery and FROST recovery elevation (solo key → K-of-N DKG group key).

use super::*;

/// Persist the recovery secret beside the store. This is a root credential (the
/// pre-rotation escrow — losing it forfeits recovery, never workspace access),
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

/// Argon2 cost for a share package's passphrase slot.
///
/// Production always pays the real cost. Tests would otherwise spend minutes in
/// a debug-build KDF across many exports, and a slow suite is a suite that stops
/// being run — but the weak parameters must never be reachable from a release
/// binary, hence `cfg(test)` rather than a caller-supplied value.
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

pub(super) fn persist_recovery_key(store: &Store, seed: &[u8; 32]) -> Result<()> {
    let home = store.home_path();
    // Tighten the parent dir to owner-only before writing the secret.
    crate::secretfs::create_private_dir(home)
        .context("restrict store home permissions for recovery.key")?;
    // Portable for the same reason as `space-recovery.key`: an actor-recovery
    // key is useless if it cannot be carried to the device doing the recovering.
    crate::secretfs::write_private(
        &home.join("recovery.key"),
        data_encoding::HEXLOWER.encode(seed).as_bytes(),
        crate::secretfs::Create::New,
        crate::secretfs::Wrap::Portable,
    )
    .context("write recovery.key")
}

/// Persist the workspace **break-glass recovery** secret beside the store as
/// `space-recovery.key` (owner-only, move it offline). A root credential, so it is
/// created owner-only from the start and errors propagate. Elevating to a K-of-N
/// group key later replaces this with per-holder DKG shares.
pub(super) fn persist_space_recovery(store: &Store, secret: &[u8; 32]) -> Result<()> {
    let home = store.home_path();
    crate::secretfs::create_private_dir(home)
        .context("restrict store home permissions for space-recovery.key")?;
    // PORTABLE, deliberately. The operator is told to move this offline, so a
    // device-bound wrap would make the copy in the safe unopenable — losing the
    // workspace's last resort to protect it from a threat the file ACL already
    // covers.
    crate::secretfs::write_private(
        &home.join("space-recovery.key"),
        data_encoding::HEXLOWER.encode(secret).as_bytes(),
        crate::secretfs::Create::New,
        crate::secretfs::Wrap::Portable,
    )
    .context("write space-recovery.key")
}

impl Replica {
    /// Load the workspace break-glass recovery seed held beside the store (the
    /// solo bootstrap key). `None` once elevated to a group key held as DKG shares.
    pub(super) fn read_space_recovery_key(&self) -> Option<[u8; 32]> {
        let path = self.store.home_path().join("space-recovery.key");
        let bytes = crate::secretfs::read_private(&path).ok().flatten()?;
        let hex = String::from_utf8(bytes).ok()?;
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.trim().as_bytes())
            .ok()?;
        raw.as_slice().try_into().ok()
    }

    /// Break-glass **workspace recovery** (lait/space/1 W5). Authors a signed
    /// `Recover` with the workspace recovery key, re-rooting the space to THIS
    /// device and re-keying to fence the old root. For a solo bootstrap key the
    /// held secret signs directly; a K-of-N group key instead produces the group
    /// signature via a FROST ceremony and assembles the same event (the plane
    /// verifies one signature either way — the threshold is invisible here).
    ///
    /// The private `bootstrap_root_epoch_if_needed` helper performs the re-key.
    pub fn space_recover_cmd(&mut self) -> (Response, Option<DirtySet>) {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
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
            let detail = degraded
                .iter()
                .map(|h| {
                    // The cause decides the remedy, so it must not be guessed:
                    // an I/O or permissions fault is not an account mismatch.
                    let why = match &h.reason {
                        RecoveryArtifactFailure::Undecryptable(m) => {
                            format!("protected under another Windows account or machine ({m})")
                        }
                        RecoveryArtifactFailure::Io(m) => {
                            format!("present but could not be read ({m})")
                        }
                    };
                    let scope = match h.is_current_authority {
                        Some(true) => "the current recovery key",
                        // Unproven currency is reported as such rather than
                        // asserted either way.
                        None => "a recovery key whose group could not be identified",
                        Some(false) => unreachable!("superseded groups are filtered out"),
                    };
                    format!("  transcript {}: {scope} — {why}", h.transcript)
                })
                .collect::<Vec<_>>()
                .join("\n");
            return (
                Response::err(format!(
                    "this device holds a FROST share that cannot be used:\n{detail}\n\
                     This device cannot take part in recovery. Recovery remains \
                     possible only if the configured authority requirements can \
                     still be satisfied by the other holders, which this device \
                     cannot verify."
                )),
                None,
            );
        }
        (
            Response::err(
                "no way to recover from this device — need either the workspace's current space-recovery.key beside the store, or a threshold share of the current group recovery key",
            ),
            None,
        )
    }

    fn space_recover_solo(
        &mut self,
        cur: &crate::space::RootState,
        secret: &[u8; 32],
    ) -> (Response, Option<DirtySet>) {
        // Re-root to this device's actor (self-incept if needed).
        let me_actor = match self.self_inception() {
            Ok(ev) => ActorId::from_incept_hash(&ev.hash()),
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let op = crate::space::SpaceOp::Recover {
            new_root: vec![me_actor.clone()],
            gen: cur.gen + 1,
        };
        let ev = crate::space::sign_op(secret, &op, vec![], &self.workspace_id);
        let res = (|| -> Result<()> {
            self.membership.add_space_event(&ev)?;
            self.persist_membership("space_recover")
        })();
        if let Err(e) = res {
            return (Response::err(format!("{e:#}")), None);
        }
        // The new root bootstraps a fresh content key (fencing the old root).
        if let Err(e) = self.bootstrap_root_epoch_if_needed() {
            return (Response::err(format!("{e:#}")), None);
        }
        (
            Response::Ok {
                message: Some(format!(
                    "recovered the workspace — root reset to {} and re-keyed",
                    me_actor.short()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
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
    pub(super) fn canonical_signing_session(
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
    fn space_recover_group(
        &mut self,
        cur: &crate::space::RootState,
    ) -> (Response, Option<DirtySet>) {
        let me_actor = match self.self_inception() {
            Ok(ev) => ActorId::from_incept_hash(&ev.hash()),
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let Some(authority) = self.active_dkg_session() else {
            return (
                Response::err("this device holds no share of the current group recovery key"),
                None,
            );
        };
        let op = crate::space::SpaceOp::Recover {
            new_root: vec![me_actor.clone()],
            gen: cur.gen + 1,
        };
        let op_bytes = match postcard::to_stdvec(&op) {
            Ok(b) => b,
            Err(e) => return (Response::err(format!("encode recover op: {e}")), None),
        };
        let events = self.membership.ceremony_events();
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
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.workspace_id);
                let Some(id) = crate::dkg::TranscriptId::of(&ev) else {
                    return (Response::err("could not derive the request id"), None);
                };
                if let Err(e) = self
                    .membership
                    .add_ceremony_event(&ev)
                    .and_then(|()| self.persist_membership("sign_request"))
                {
                    return (Response::err(format!("{e:#}")), None);
                }
                id
            }
        };
        // Record LOCAL intent for this transcript's op so our node co-signs this
        // recovery (the consent gate in `sign_advance_session`).
        if let Err(e) = self.dkg_write(&signing, "intent", &op_bytes) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self.dkg_advance() {
            return (Response::err(format!("{e:#}")), None);
        }
        let after = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let installed = after.gen > cur.gen && after.root == vec![me_actor.clone()];
        let message = if installed {
            format!(
                "recovered the workspace — root reset to {} and re-keyed",
                me_actor.short()
            )
        } else {
            format!(
                "group recovery under way (session {}) — each other holder must approve it with `space recover-approve {}` until the threshold co-signs",
                signing.to_hex(),
                signing.to_hex(),
            )
        };
        (
            Response::Ok {
                message: Some(message),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Co-sign a pending break-glass recovery request as a holder of the current
    /// group key. This is the explicit consent that `sign_advance_session` demands:
    /// the holder has verified out-of-band that `session` re-roots the workspace to
    /// the agreed party, and records local intent so their share is contributed to
    /// exactly that op (and no other request on the board).
    pub fn space_recover_approve_cmd(
        &mut self,
        session_hex: String,
        expect: Vec<String>,
    ) -> (Response, Option<DirtySet>) {
        // Strict parse: a session id names a filesystem artifact, so a
        // permissive decode would let two spellings name one transcript.
        let Some(session) = crate::dkg::TranscriptId::parse_hex(session_hex.trim()) else {
            return (
                Response::err("not a valid recovery session id (64 lowercase hex chars)"),
                None,
            );
        };
        if self.active_dkg_session().is_none() {
            return (
                Response::err("this device holds no share of the current group recovery key — nothing to co-sign"),
                None,
            );
        }
        // The holder MUST state which actor(s) they expect this recovery to re-root
        // to, so consent binds to the roots — not to an opaque session id whose
        // request could re-root anywhere. Resolve them up front.
        if expect.is_empty() {
            return (
                Response::err(
                    "name the actor(s) you expect this recovery to re-root to (`--to <actor>`); refusing to co-sign a session blind",
                ),
                None,
            );
        }
        let mut expected: Vec<ActorId> = Vec::with_capacity(expect.len());
        for who in &expect {
            let Some(a) = self.resolve_actor(who) else {
                return (
                    Response::not_found(format!(
                        "no known actor matches '{who}' — sync the recovering device's identity first"
                    )),
                    None,
                );
            };
            expected.push(a);
        }
        expected.sort();
        expected.dedup();
        // The exact op the request asks the group to sign, taken from the
        // VERIFIED board and from the transcript the id names — not from the
        // first raw decode that happens to match.
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let request = board.signing.get(&session).and_then(|t| t.request.as_ref());
        let Some((op_bytes, req_target)) = request.and_then(|r| match &r.op {
            crate::dkg::CeremonyOp::SignRequest { op, target, .. } => Some((op.clone(), *target)),
            _ => None,
        }) else {
            return (
                Response::err(
                    "no pending recovery request for that session (sync from the initiator first)",
                ),
                None,
            );
        };
        // A recovery approval consents to a SPACE op. Refuse to lend consent to
        // a request aimed at any other plane — approving a ceremony proposal is
        // a different decision and must not ride this command.
        if req_target != crate::dkg::SignTarget::SpaceOp {
            return (
                Response::err(
                    "that request is not a workspace-recovery request — refusing to co-sign",
                ),
                None,
            );
        }
        // It must be a Recover for the next generation re-rooting to EXACTLY the
        // actor set the holder named — refuse to co-sign anything else.
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let target = match postcard::from_bytes::<crate::space::SpaceOp>(&op_bytes) {
            Ok(crate::space::SpaceOp::Recover { new_root, gen })
                if gen == cur.gen + 1 && !new_root.is_empty() =>
            {
                new_root
            }
            _ => {
                return (
                    Response::err(
                        "that request is not a current-generation Recover — refusing to co-sign",
                    ),
                    None,
                );
            }
        };
        let mut got = target.clone();
        got.sort();
        got.dedup();
        if got != expected {
            let roots = target
                .iter()
                .map(|a| a.short())
                .collect::<Vec<_>>()
                .join(", ");
            return (
                Response::err(format!(
                    "that request re-roots to {roots}, not the actor(s) you named — refusing to co-sign"
                )),
                None,
            );
        }
        if let Err(e) = self.dkg_write(&session, "intent", &op_bytes) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self.dkg_advance() {
            return (Response::err(format!("{e:#}")), None);
        }
        let roots = target
            .iter()
            .map(|a| a.short())
            .collect::<Vec<_>>()
            .join(", ");
        (
            Response::Ok {
                message: Some(format!(
                    "co-signed the recovery re-rooting the workspace to {roots} — it installs once the threshold has co-signed"
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// After a re-root the old admin's epochs are de-authorized, so the new root
    /// has no readable active epoch — mint a fresh one (idempotent: a no-op unless
    /// we are an admin holding no authorized active epoch). Fires here and on
    /// import, so whichever node completes the threshold re-keys.
    pub(super) fn bootstrap_root_epoch_if_needed(&mut self) -> Result<()> {
        if self.am_i_admin() && self.active_epoch().is_none() {
            self.rotate_key()?;
            self.persist_membership("recover_bootstrap_epoch")?;
        }
        Ok(())
    }

    // ---- FROST recovery elevation (solo key → K-of-N DKG group key) ----

    /// Path of a ceremony artifact. The transcript component is always
    /// [`TranscriptId::to_hex`] — canonical lowercase hex, validated when the id
    /// was constructed — so no remote-derived string ever reaches the filesystem
    /// and two spellings can never name one artifact.
    ///
    /// [`TranscriptId::to_hex`]: crate::dkg::TranscriptId::to_hex
    pub(super) fn dkg_path(&self, t: &crate::dkg::TranscriptId, label: &str) -> std::path::PathBuf {
        self.store
            .home_path()
            .join("dkg")
            .join(format!("{}-{label}", t.to_hex()))
    }
    fn dkg_has(&self, t: &crate::dkg::TranscriptId, label: &str) -> bool {
        self.dkg_path(t, label).exists()
    }
    /// The state of a ceremony artifact on this device.
    ///
    /// `Unreadable` must never be flattened into `Missing`. A share protected
    /// under a different Windows account or machine is *present* — the holder
    /// exists but cannot act — and for an N-of-N group that is the difference
    /// between a degraded holder and an unrecoverable workspace. Operators need
    /// to see which one they have.
    pub(super) fn dkg_artifact(&self, t: &crate::dkg::TranscriptId, label: &str) -> ArtifactRead {
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
    pub(super) fn dkg_read(&self, t: &crate::dkg::TranscriptId, label: &str) -> Option<Vec<u8>> {
        match self.dkg_artifact(t, label) {
            ArtifactRead::Present(v) => Some(v),
            _ => None,
        }
    }

    /// Holders on this device whose share exists but cannot be used, restricted
    /// to transcripts that are — or might be — the workspace's **current**
    /// recovery authority.
    ///
    /// The currency check matters: an unreadable share from a superseded group
    /// is not a recovery problem, so announcing "this device has a share for the
    /// workspace recovery key" on its account would be false. Candidates are
    /// filtered through: public-key package, derived group key, recovery commit,
    /// standing RootState.
    ///
    /// A transcript whose package cannot be read yields `is_current_authority`
    /// of `None` and is still reported: we cannot prove it is live, but nor can
    /// we rule it out, and dropping the one artifact an operator needs to hear
    /// about would be the worse error.
    pub fn degraded_recovery_holders(&self) -> Vec<DegradedRecoveryHolder> {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let events = self.membership.ceremony_events();
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
                // recovery problem: it could not recover this workspace even if
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
    pub(super) fn dkg_write(
        &self,
        t: &crate::dkg::TranscriptId,
        label: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let dir = self.store.home_path().join("dkg");
        crate::secretfs::create_private_dir(&dir).context("create dkg dir")?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::Replace,
            crate::secretfs::Wrap::DeviceBound,
        )
        .context("write dkg artifact")
    }
    /// Write a ceremony artifact owner-only but **portable** - no device
    /// binding. For public material that must stay legible after a store is
    /// restored onto another account (see [`crate::secretfs::Wrap::Portable`]).
    pub(super) fn dkg_write_portable(
        &self,
        t: &crate::dkg::TranscriptId,
        label: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let dir = self.store.home_path().join("dkg");
        crate::secretfs::create_private_dir(&dir).context("create dkg dir")?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::Replace,
            crate::secretfs::Wrap::Portable,
        )
        .context("write portable dkg artifact")
    }

    /// Write a ceremony artifact that must not already exist. For single-use
    /// material (signing nonces): an existing record has to be *examined* — it
    /// may already be bound to a signing package — never silently replaced.
    fn dkg_write_new(&self, t: &crate::dkg::TranscriptId, label: &str, bytes: &[u8]) -> Result<()> {
        let dir = self.store.home_path().join("dkg");
        crate::secretfs::create_private_dir(&dir).context("create dkg dir")?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::New,
            crate::secretfs::Wrap::DeviceBound,
        )
        .context("write single-use dkg artifact")
    }

    /// Begin elevating the recovery authority to a `k`-of-N FROST group key over
    /// `cofounders` (their device keys) + this device. Only the holder of the
    /// current recovery key may elevate (they install the result). Posts the DKG
    /// proposal and this node's first round, then the ceremony advances on sync.
    pub fn space_elevate_cmd(
        &mut self,
        cofounders: Vec<String>,
        k: u16,
    ) -> (Response, Option<DirtySet>) {
        // Must hold the current recovery key to install the resulting Rotate.
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let holds_solo = self
            .read_space_recovery_key()
            .and_then(|s| crate::space::recovery_commit(&crate::space::recovery_pub_of(&s)))
            == Some(cur.recovery_commit);
        // Group→group reconfiguration: we hold a share of the standing group, so
        // we can OPEN the grant request even though we cannot sign it alone.
        let holds_share = self.active_dkg_session().is_some();
        if !holds_solo && !holds_share {
            return (
                Response::err(
                    "only the current recovery authority can elevate: run this where space-recovery.key lives, or on a device holding a share of the current group key",
                ),
                None,
            );
        }
        // Assemble the sorted participant set (co-founders + me). Sorted and
        // deduped here AND re-checked by every acceptor: a hostile proposer must
        // not be able to hand honest nodes a malformed participant list.
        let mut set: std::collections::BTreeSet<UserId> = std::collections::BTreeSet::new();
        for c in cofounders {
            match UserId::parse(&c) {
                Some(u) => {
                    set.insert(u);
                }
                None => {
                    return (
                        Response::err(format!("'{c}' is not a device key (64 hex chars)")),
                        None,
                    )
                }
            }
        }
        set.insert(self.me.clone());
        let participants: Vec<UserId> = set.into_iter().collect();
        let n = participants.len() as u16;
        // k == 0 means "all holders" (N-of-N) — the safe default.
        let k = if k == 0 { n } else { k };
        if !(1..=n).contains(&k) || n < 2 {
            return (
                Response::err("elevation needs ≥2 participants and threshold in 1..=N"),
                None,
            );
        }
        if !self.rotation_can_complete(&participants) {
            return (
                Response::err(
                    "too few of the current holders are in the proposed arrangement: installing the result needs the current group to sign the rotation, and only a participant of the new ceremony can derive the key it installs. Include at least the current threshold of existing holders.",
                ),
                None,
            );
        }
        // Sign the proposal FIRST: its id is the hash of the signed node, so it
        // does not exist until now. `nonce` keeps two identical elevations by
        // the same initiator from colliding — Ed25519 signing is deterministic,
        // so without it the same (n, k, participants) would hash identically.
        let Some(current) = self.current_authority() else {
            return (
                Response::err(
                    "cannot determine the arrangement operating the current recovery key — sync the ceremony that produced it first",
                ),
                None,
            );
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
        let _ = n;
        let ev = crate::dkg::sign_ceremony(&self.seed, &propose, &self.workspace_id);
        let Some(transcript) = crate::dkg::TranscriptId::of(&ev) else {
            return (Response::err("could not derive the proposal id"), None);
        };
        // Local consent record for the ceremony itself, keyed by the transcript
        // it consents to. Written before posting so a crash leaves an orphan
        // marker (harmless) rather than a proposal nobody will install.
        if let Err(e) = self.dkg_write(&transcript, "intent", transcript.to_hex().as_bytes()) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self
            .membership
            .add_ceremony_event(&ev)
            .and_then(|()| self.persist_membership("dkg_propose"))
        {
            return (Response::err(format!("{e:#}")), None);
        }

        // Authorization. The device signature on the proposal proves only
        // control of a device; what every participant checks is a grant from the
        // standing authority. How that grant is produced is the ONLY thing that
        // differs between a solo and a group authority — the grant object itself
        // is identical either way, which is what B1 bought.
        let message = if holds_solo {
            let Some(secret) = self.read_space_recovery_key() else {
                return (
                    Response::err("recovery key disappeared mid-elevation"),
                    None,
                );
            };
            let grant = crate::dkg::sign_authority_grant(&secret, &self.workspace_id, &transcript);
            let auth_ev = crate::dkg::sign_ceremony(
                &self.seed,
                &crate::dkg::CeremonyOp::DkgAuthorize(grant),
                &self.workspace_id,
            );
            if let Err(e) = self
                .membership
                .add_ceremony_event(&auth_ev)
                .and_then(|()| self.persist_membership("dkg_authorize"))
            {
                return (Response::err(format!("{e:#}")), None);
            }
            format!(
                "started {k}-of-{n} recovery elevation — the DKG completes automatically as the co-founders' nodes sync; the group key installs once every share is in"
            )
        } else {
            // The standing authority is a group, so the grant needs a threshold
            // signature. Open a signing request for it; the other holders consent
            // with `space elevate-approve`, and the aggregate lands as the grant.
            match self.open_grant_request(&transcript).map(|(id, _)| id) {
                Ok(signing) => format!(
                    "proposed a {k}-of-{n} recovery arrangement (proposal {}) — the current group must authorize it: each holder runs `space elevate-approve {} --proposal {}`",
                    transcript.to_hex(),
                    signing.to_hex(),
                    transcript.to_hex(),
                ),
                Err(e) => return (Response::err(format!("{e:#}")), None),
            }
        };
        let _ = self.dkg_advance();
        (
            Response::Ok {
                message: Some(message),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
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
            crate::dkg::authority_grant_payload(&self.workspace_id, &group_key, proposal);
        let events = self.membership.ceremony_events();
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
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.workspace_id);
                let id = crate::dkg::TranscriptId::of(&ev)
                    .ok_or_else(|| anyhow!("could not derive the request id"))?;
                self.membership.add_ceremony_event(&ev)?;
                self.persist_membership("grant_request")?;
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
    pub fn space_elevate_approve_cmd(
        &mut self,
        session_hex: String,
        expect_proposal: String,
    ) -> (Response, Option<DirtySet>) {
        let Some(session) = crate::dkg::TranscriptId::parse_hex(session_hex.trim()) else {
            return (
                Response::err("not a valid request id (64 lowercase hex chars)"),
                None,
            );
        };
        let Some(expected) = crate::dkg::TranscriptId::parse_hex(expect_proposal.trim()) else {
            return (
                Response::err(
                    "name the proposal you expect this to authorize (`--proposal <64-hex>`)",
                ),
                None,
            );
        };
        if self.active_dkg_session().is_none() {
            return (
                Response::err(
                    "this device holds no share of the current group key — nothing to co-sign",
                ),
                None,
            );
        }
        let events = self.membership.ceremony_events();
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
            return (
                Response::err("no pending request for that id (sync from the initiator first)"),
                None,
            );
        };
        if target != crate::dkg::SignTarget::AuthorityGrant {
            return (
                Response::err("that request is not an authority grant — refusing to co-sign"),
                None,
            );
        }
        let Ok(grant) = postcard::from_bytes::<crate::dkg::AuthorityGrant>(&op_bytes) else {
            return (
                Response::err("that request does not carry a well-formed grant"),
                None,
            );
        };
        if grant.proposal != expected {
            return (
                Response::err(format!(
                    "that request authorizes proposal {}, not the one you named — refusing to co-sign",
                    grant.proposal.to_hex()
                )),
                None,
            );
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
            return (
                Response::err("that proposal has not synced here yet — sync and retry"),
                None,
            );
        };
        let Some(cfg) = proposal.frost_config() else {
            return (
                Response::err("that proposal is malformed or uses an unsupported transition"),
                None,
            );
        };
        if !self.claims_the_standing_authority(proposal.current_authority()) {
            return (
                Response::err(
                    "that proposal does not replace the authority standing here — refusing to co-sign",
                ),
                None,
            );
        }
        // A holder must not authorize a ceremony that cannot be installed. The
        // proposer checks this too, but a hostile or stale proposer does not, and
        // the cost of being wrong is a permanently stalled rotation.
        let proposed: Vec<UserId> = cfg
            .participants
            .iter()
            .filter_map(|p| p.as_device())
            .collect();
        if !self.rotation_can_complete(&proposed) {
            return (
                Response::err(
                    "refusing to authorize: too few of the current holders are in the proposed arrangement, so the resulting key could never be installed",
                ),
                None,
            );
        }
        if let Err(e) = self.dkg_write(&session, "intent", &op_bytes) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Consent to the CEREMONY as well, not only to the grant that authorizes
        // it. The holder named this proposal explicitly, so this is exactly what
        // they agreed to — and without it they would authorize a ceremony they
        // then refuse to help install, stalling the rotation at the last step
        // with no indication why.
        if let Err(e) = self.dkg_write(&expected, "intent", expected.to_hex().as_bytes()) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self.dkg_advance() {
            return (Response::err(format!("{e:#}")), None);
        }
        (
            Response::Ok {
                message: Some(format!(
                    "co-signed the authorization for a {}-of-{} arrangement — it takes effect once the threshold has signed",
                    cfg.k,
                    cfg.participants.len()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Drive every FROST ceremony this device participates in to a fixpoint, based
    /// on what has synced. Idempotent: posts each round once, and installs the
    /// group key (via a space `Rotate`) once, by the recovery-key holder. Called
    /// by `space_elevate_cmd`, an explicit advance, and on import.
    ///
    /// The ceremony board is grow-only and re-scanned each import; completed and
    /// abandoned sessions are never pruned, so a member could pad it to inflate
    /// per-import work (bounded per call by the `guard` below). Session GC/expiry
    /// is future work — see the `C_CEREMONY` container in `engine::membership`.
    pub fn dkg_advance(&mut self) -> Result<bool> {
        let mut any = false;
        // A ceremony has a bounded number of steps; the guard is a backstop
        // against any unforeseen non-convergence, never reached in normal flow.
        let mut guard = 0;
        while self.dkg_advance_once()? {
            any = true;
            guard += 1;
            if guard > 64 {
                break;
            }
        }
        Ok(any)
    }

    fn dkg_advance_once(&mut self) -> Result<bool> {
        // ONE verified pass over the board. Everything below reads from this —
        // discovery included. Previously sessions were discovered by decoding
        // events *unverified* and the whole board was then re-verified once per
        // discovered session, so forged events both manufactured transcripts and
        // multiplied the work (`transcripts × board`, attacker-controlled on
        // both axes).
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        // Per-transcript advancement is best-effort: a malformed, signature-valid
        // package from one participant must never fail the whole import (which
        // would wedge membership sync permanently on the persisted event). Isolate
        // and log each transcript's error instead of propagating it.
        let mut progressed = false;
        // DKG transcripts naming me as a participant, under an *accepted*
        // proposal. Acceptance (not just a valid signature) is the gate — see
        // `accepted_proposal`.
        let dkg_ids: Vec<crate::dkg::TranscriptId> = board
            .dkg
            .iter()
            .filter(|(id, t)| {
                self.accepted_proposal(id, t)
                    .is_some_and(|(_, _, participants)| participants.contains(&self.me))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in dkg_ids {
            let t = &board.dkg[&id];
            match self.dkg_advance_session(&id, t) {
                Ok(p) => progressed |= p,
                Err(e) => tracing::warn!("dkg ceremony advance failed (skipped): {e:#}"),
            }
        }
        // Threshold-signing transcripts I can co-sign.
        let sign_ids: Vec<crate::dkg::TranscriptId> = board.signing.keys().copied().collect();
        for id in sign_ids {
            let t = &board.signing[&id];
            match self.sign_advance_session(&id, t, &board) {
                Ok(p) => progressed |= p,
                Err(e) => tracing::warn!("recovery signing advance failed (skipped): {e:#}"),
            }
        }
        Ok(progressed)
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
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
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
    fn rotation_can_complete(&self, proposed: &[UserId]) -> bool {
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
        participants: &[UserId],
    ) -> Vec<UserId> {
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
    pub fn space_custody_export_cmd(
        &mut self,
        path: String,
        passphrase: String,
    ) -> (Response, Option<DirtySet>) {
        if passphrase.chars().count() < 12 {
            return (
                Response::err(
                    "choose a passphrase of at least 12 characters — this is the only thing standing between an attacker with the file and your share",
                ),
                None,
            );
        }
        // The ceremony to export for: one we hold a share of. A pending
        // arrangement takes precedence, since that is the one whose install is
        // waiting on this attestation.
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let standing = self.active_dkg_session();
        let Some(dkg) = board
            .dkg
            .keys()
            .find(|id| self.dkg_read(id, "share").is_some() && Some(**id) != standing)
            .copied()
            .or(standing)
        else {
            return (Response::err("this device holds no share to export"), None);
        };
        let Some(t) = board.dkg.get(&dkg) else {
            return (Response::err("that ceremony is not on the board"), None);
        };
        let Some((_, _, participants)) = self.accepted_proposal(&dkg, t) else {
            return (Response::err("that ceremony is not accepted here"), None);
        };
        let Some(manifest) = self.dkg_manifest(&dkg) else {
            return (
                Response::err("no acceptance record for that ceremony"),
                None,
            );
        };
        let (Some(share), Some(pkp)) = (self.dkg_read(&dkg, "share"), self.dkg_read(&dkg, "pkp"))
        else {
            return (
                Response::err("this device's share for that ceremony is missing or unreadable"),
                None,
            );
        };
        let Ok(group_key) = crate::dkg::group_key_of_package(&pkp) else {
            return (Response::err("the public-key package is unusable"), None);
        };
        let Some(index) = participants.iter().position(|p| p == &self.me) else {
            return (Response::err("this device is not a participant"), None);
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
        let package = match crate::custody::AuthoritySharePackage::seal(
            &self.workspace_id,
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
        ) {
            Ok(p) => p,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let bytes = match postcard::to_stdvec(&package) {
            Ok(b) => b,
            Err(e) => return (Response::err(format!("encode package: {e}")), None),
        };
        let out = std::path::PathBuf::from(&path);
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = crate::secretfs::create_private_dir(parent) {
                    return (Response::err(format!("{e:#}")), None);
                }
            }
        }
        // Portable: a share package is meant to be carried off this machine, so
        // it must not be wrapped to this account.
        if let Err(e) = crate::secretfs::write_private(
            &out,
            &bytes,
            crate::secretfs::Create::Replace,
            crate::secretfs::Wrap::Portable,
        ) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Read back from disk and open through the portable slot. Verifying the
        // in-memory value would test nothing that could actually fail.
        let reread = match crate::secretfs::read_private(&out) {
            Ok(Some(b)) => b,
            Ok(None) => return (Response::err("the package vanished after writing"), None),
            Err(e) => {
                return (
                    Response::err(format!("re-reading the package failed: {e}")),
                    None,
                )
            }
        };
        let restored: crate::custody::AuthoritySharePackage = match postcard::from_bytes(&reread) {
            Ok(p) => p,
            Err(e) => {
                return (
                    Response::err(format!("the written package does not decode: {e}")),
                    None,
                )
            }
        };
        let expect = crate::custody::PackageExpectation {
            workspace: &self.workspace_id,
            authority: &authority,
            ceremony: &dkg.to_hex(),
            leaf: &leaf,
            group_key: &group_key,
            index: index as u16 + 1,
        };
        if let Err(e) =
            restored.verify_and_open(&crate::custody::UnlockKey::Passphrase(passphrase), &expect)
        {
            return (
                Response::err(format!(
                    "the exported package could not be reopened, so it was NOT attested: {e:#}"
                )),
                None,
            );
        }
        if let Err(e) = self.post_ceremony(crate::dkg::CeremonyOp::CustodyAck { dkg }) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Recompute from the board so the count reflects our own attestation.
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let outstanding = board
            .dkg
            .get(&dkg)
            .map(|t| self.custody_outstanding(&dkg, t, &participants))
            .unwrap_or_default();
        let note = if !self.is_indispensable(&dkg) {
            "this arrangement tolerates a lost holder, so no attestation is required to install it"
                .to_string()
        } else if outstanding.is_empty() {
            "every custodian has attested — the arrangement can now install".to_string()
        } else {
            format!("still waiting on {} custodian(s)", outstanding.len())
        };
        (
            Response::Ok {
                message: Some(format!(
                    "exported and verified your share package to {path} — {note}. Keep it somewhere the passphrase alone cannot be found."
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Restore a share from a portable package written by
    /// [`Self::space_custody_export_cmd`].
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
    pub fn space_custody_import_cmd(
        &mut self,
        path: String,
        passphrase: String,
        force: bool,
    ) -> (Response, Option<DirtySet>) {
        let bytes = match crate::secretfs::read_private(std::path::Path::new(&path)) {
            Ok(Some(b)) => b,
            Ok(None) => return (Response::not_found(format!("no package at {path}")), None),
            Err(e) => return (Response::err(format!("reading {path}: {e}")), None),
        };
        let package: crate::custody::AuthoritySharePackage = match postcard::from_bytes(&bytes) {
            Ok(p) => p,
            Err(e) => {
                return (
                    Response::err(format!("that file is not a share package: {e}")),
                    None,
                )
            }
        };
        if package.workspace != self.workspace_id {
            return (
                Response::err("that package belongs to a different workspace"),
                None,
            );
        }
        // Resolve the ceremony it claims, from the board — never from the
        // package. A package names its own ceremony; that is a claim, not proof.
        let Some(dkg) = crate::dkg::TranscriptId::parse_hex(&package.ceremony) else {
            return (Response::err("that package names no valid ceremony"), None);
        };
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let Some(t) = board.dkg.get(&dkg) else {
            return (
                Response::err(
                    "that ceremony is not on this device's board — sync the workspace first",
                ),
                None,
            );
        };
        let Some((_, _, participants)) = self.accepted_proposal(&dkg, t) else {
            return (
                Response::err("that ceremony is not accepted here — it may not be authorized"),
                None,
            );
        };
        let Some(index) = participants.iter().position(|p| p == &self.me) else {
            return (
                Response::err("this device is not a participant of that ceremony"),
                None,
            );
        };
        let index = index as u16 + 1;
        let Some(manifest) = self.dkg_manifest(&dkg) else {
            return (
                Response::err("no acceptance record for that ceremony"),
                None,
            );
        };
        // Refuse to clobber usable material.
        if !force && matches!(self.dkg_artifact(&dkg, "share"), ArtifactRead::Present(_)) {
            return (
                Response::err(
                    "this device already holds a readable share for that ceremony — pass --force only if you mean to replace it",
                ),
                None,
            );
        }
        // The expected group key comes from the board's ceremony where possible,
        // so a package cannot introduce a group this device never accepted. When
        // the local public package is gone (the very case this command exists
        // for), fall back to the package's own — still bound by the authority
        // and workspace checks, and validated against the private half below.
        let expected_group = match self.dkg_artifact(&dkg, "pkp") {
            ArtifactRead::Present(pkp) => match crate::dkg::group_key_of_package(&pkp) {
                Ok(k) => k,
                Err(e) => {
                    return (
                        Response::err(format!("local public package unusable: {e}")),
                        None,
                    )
                }
            },
            _ => package.authority.public_key.clone(),
        };
        let authority =
            crate::authority::AuthorityId::new(expected_group.clone(), &manifest.configuration);
        let principal = crate::authority::PrincipalId::of_device(&self.me);
        let leaf = crate::authority::LeafId::of_principal(&principal);
        let expect = crate::custody::PackageExpectation {
            workspace: &self.workspace_id,
            authority: &authority,
            ceremony: &package.ceremony,
            leaf: &leaf,
            group_key: &expected_group,
            index,
        };
        // `verify_and_open` performs the private-half validation, so a package
        // that opens but carries unusable material never reaches storage.
        let payload = match package
            .verify_and_open(&crate::custody::UnlockKey::Passphrase(passphrase), &expect)
        {
            Ok(p) => p,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let crate::custody::SharePayload::Frost(f) = payload else {
            return (
                Response::err("that package carries a share this build cannot use"),
                None,
            );
        };
        // Write the public package first: if the process dies between the two,
        // a share without its package is unusable and looks broken, whereas a
        // package without a share is simply an absent share — the recoverable
        // side of the failure.
        if let Err(e) = self.dkg_write_portable(&dkg, "pkp", &f.public_package) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self.dkg_write(&dkg, "share", &f.key_share) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Prove the restore actually worked by reading back what was stored,
        // rather than trusting the write. This is the same discipline as export:
        // the failure being guarded is one that only shows up on re-read.
        let restored = match (
            self.dkg_artifact(&dkg, "share"),
            self.dkg_artifact(&dkg, "pkp"),
        ) {
            (ArtifactRead::Present(s), ArtifactRead::Present(p)) => (s, p),
            _ => {
                return (
                    Response::err("the restored share could not be read back"),
                    None,
                )
            }
        };
        if let Err(e) = crate::dkg::validate_share(&restored.0, &restored.1, index) {
            return (
                Response::err(format!("the restored share does not validate: {e:#}")),
                None,
            );
        }
        let _ = self.dkg_advance();
        (
            Response::Ok {
                message: Some(format!(
                    "restored and verified your share for ceremony {} — this device can take part in recovery again",
                    dkg.to_hex()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
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
        let events = self.membership.ceremony_events();
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
    pub(super) fn current_authority(&self) -> Option<crate::authority::AuthorityId> {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        if let Some(secret) = self.read_space_recovery_key() {
            let pubkey = crate::space::recovery_pub_of(&secret);
            if crate::space::recovery_commit(&pubkey) == Some(cur.recovery_commit) {
                return Some(crate::authority::AuthorityId::single(pubkey));
            }
        }
        for (id, manifest) in self.dkg_manifests() {
            let Some(group_key) = self.group_key_of_transcript(&id) else {
                continue;
            };
            if crate::space::recovery_commit(&group_key) == Some(cur.recovery_commit) {
                return Some(crate::authority::AuthorityId::new(
                    group_key,
                    &manifest.configuration,
                ));
            }
        }
        None
    }

    /// Every acceptance record on this device, keyed by transcript.
    pub(super) fn dkg_manifests(&self) -> Vec<(crate::dkg::TranscriptId, crate::dkg::DkgManifest)> {
        let dir = self.store.home_path().join("dkg");
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
        let mut board = crate::dkg::parse_board(events, &self.workspace_id);
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
    /// workspace's recovery authority — without this, any device could post a
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
    /// `space_elevate_cmd` sorts and dedupes, but a hostile proposer does not.
    fn accepted_proposal(
        &self,
        dkg: &crate::dkg::TranscriptId,
        t: &crate::dkg::DkgTranscript,
    ) -> Option<(u16, u16, Vec<UserId>)> {
        let proposal = t.proposal.as_ref()?;
        let crate::dkg::CeremonyOp::DkgPropose(p) = &proposal.op else {
            return None;
        };
        // Well-formedness and scheme support are the configuration's own rules,
        // re-checked at every acceptor rather than trusted from the proposer.
        // `frost_config` also refuses a transition this phase does not implement
        // (Reshare), so an unimplemented promise cannot enter a ceremony.
        let cfg = p.frost_config()?;
        let participants = p.frost_devices()?;
        let (n, k) = (participants.len() as u16, cfg.k);

        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
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
    pub(super) fn dkg_manifest(
        &self,
        dkg: &crate::dkg::TranscriptId,
    ) -> Option<crate::dkg::DkgManifest> {
        postcard::from_bytes(&self.dkg_read(dkg, "manifest")?).ok()
    }

    /// The DKG transcript whose group key is the workspace's **standing**
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
    pub(super) fn standing_dkg_session(&self) -> Option<crate::dkg::TranscriptId> {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        self.dkg_manifests().into_iter().find_map(|(id, _)| {
            (self
                .group_key_of_transcript(&id)
                .as_ref()
                .and_then(crate::space::recovery_commit)
                == Some(cur.recovery_commit))
            .then_some(id)
        })
    }

    /// The standing transcript **whose share this device can actually use**.
    ///
    /// This is the signing accessor: everything that needs to produce a
    /// signature needs a readable share, and a holder that cannot read its own
    /// share must not be treated as able to contribute.
    pub(super) fn active_dkg_session(&self) -> Option<crate::dkg::TranscriptId> {
        let id = self.standing_dkg_session()?;
        matches!(self.dkg_artifact(&id, "share"), ArtifactRead::Present(_)).then_some(id)
    }

    /// This transcript's group key, recomputed from the stored public-key
    /// package. Never read from a `-group` file: a plaintext artifact naming the
    /// rotation target is a swap target, and the value is derivable.
    pub(super) fn group_key_of_transcript(&self, t: &crate::dkg::TranscriptId) -> Option<UserId> {
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
    fn sign_advance_session(
        &mut self,
        signing: &crate::dkg::TranscriptId,
        t: &crate::dkg::SignTranscript,
        board: &crate::dkg::CeremonyBoard,
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
        let index_of = |dev: &UserId| {
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
        // honest holders' shares hand the workspace over.
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
        let message = crate::sigdag::payload_to_sign(
            domain,
            op_bytes,
            &group_key,
            &[],
            self.workspace_id.as_str(),
        );

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
                        .membership
                        .space_events()
                        .iter()
                        .any(|e| e.hash() == node.hash());
                    if fresh
                        && node.verify_sig(
                            crate::space::SPACE_EVENT_DOMAIN,
                            self.workspace_id.as_str(),
                        )
                    {
                        self.membership.add_space_event(&node)?;
                        self.persist_membership("group_recover")?;
                        self.bootstrap_root_epoch_if_needed()?;
                        return Ok(true);
                    }
                }
                crate::dkg::SignTarget::AuthorityGrant => {
                    if crate::dkg::authority_grant_of(&node, &self.workspace_id).is_some() {
                        let already = self.membership.ceremony_events().iter().any(|e| {
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
                &self.genesis,
                &self.workspace_id,
                &self.membership.space_events(),
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
        let index_of = |dev: &UserId| {
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
                let Some(sealed) = crypto::seal_to(&recipient, &pkg) else {
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
                        crypto::open_sealed(&self.seed, &self.me, sealed),
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
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
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
        // Windows profile, and the workspace learns that on the day it needs to
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
                let ev = crate::space::sign_op(&secret, &op, vec![], &self.workspace_id);
                self.membership.add_space_event(&ev)?;
                self.persist_membership("dkg_install")?;
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
        new_key: &UserId,
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
        let events = self.membership.ceremony_events();
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
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.workspace_id);
                let id = crate::dkg::TranscriptId::of(&ev)
                    .ok_or_else(|| anyhow!("could not derive the request id"))?;
                self.membership.add_ceremony_event(&ev)?;
                self.persist_membership("rotate_request")?;
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
        let ev = crate::dkg::sign_ceremony(&self.seed, &op, &self.workspace_id);
        self.membership.add_ceremony_event(&ev)?;
        self.persist_membership("dkg_round")
    }
}
