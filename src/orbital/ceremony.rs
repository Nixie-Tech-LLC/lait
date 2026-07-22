//! LAIT's control adaptation of the mechanics ceremony engine.
//!
//! The generic ceremony state machine — break-glass recovery, FROST
//! elevation, threshold signing, custody export/import, artifact storage —
//! lives in [`mechanics::ceremony`]. This file only composes the engine over
//! the product's [`Inner`] mechanics state: it borrows the authority ledger,
//! injects the Body-key epoch fence (mint a fresh epoch when this device is an
//! admin holding none), and forwards the control-surface calls.

use anyhow::Result;

use mechanics::ceremony::{
    CeremonyEngine, CeremonyProgress, CustodyExport, CustodyImport, DegradedRecoveryHolder,
    Elevation, ElevationApproved, RecoveryApproved, RecoveryStatus, SpaceRecovery,
};
use mechanics::ledger::AuthorityLedger;

use super::mechanics::{fence_epoch, Inner, OrbitalMechanics};

impl Inner {
    /// Run one ceremony-engine operation over this Space's ledger, with the
    /// product's epoch fence injected (disjoint borrows via destructuring).
    pub(super) fn with_ceremony_engine<T>(
        &mut self,
        f: impl FnOnce(&mut CeremonyEngine<'_>) -> T,
    ) -> T {
        let Inner {
            ledger,
            keyring,
            seed,
            me,
            dir,
            ..
        } = self;
        let mut fence = |ledger: &mut AuthorityLedger| fence_epoch(ledger, keyring, seed, me);
        let mut engine = CeremonyEngine::new(ledger, *seed, me.clone(), dir.clone(), &mut fence);
        f(&mut engine)
    }
}

impl OrbitalMechanics {
    /// Break-glass space recovery: re-root the space to this device (solo key
    /// or FROST group signature).
    pub fn space_recover(&self) -> Result<SpaceRecovery> {
        self.lock().with_ceremony_engine(|e| e.space_recover())
    }

    /// Co-sign a pending break-glass recovery as a holder of the current group
    /// key.
    pub fn space_recover_approve(
        &self,
        session: String,
        expect: Vec<String>,
    ) -> Result<RecoveryApproved> {
        self.lock()
            .with_ceremony_engine(|e| e.space_recover_approve(session, expect))
    }

    /// Begin elevating the recovery authority to a `k`-of-N FROST group key.
    pub fn space_elevate(&self, cofounders: Vec<String>, k: u16) -> Result<Elevation> {
        self.lock()
            .with_ceremony_engine(|e| e.space_elevate(cofounders, k))
    }

    /// Co-sign a pending authority-grant request for a proposed arrangement.
    pub fn space_elevate_approve(
        &self,
        session: String,
        proposal: String,
    ) -> Result<ElevationApproved> {
        self.lock()
            .with_ceremony_engine(|e| e.space_elevate_approve(session, proposal))
    }

    /// Reshare the standing group key onto a new arrangement without changing
    /// the key (same-key redistribution / participant replacement).
    pub fn space_reshare(&self, participants: Vec<String>, k: u16) -> Result<Elevation> {
        self.lock()
            .with_ceremony_engine(|e| e.space_reshare(participants, k))
    }

    /// Export this device's share as a verified portable package and attest it.
    pub fn space_custody_export(&self, path: String, passphrase: String) -> Result<CustodyExport> {
        self.lock()
            .with_ceremony_engine(|e| e.space_custody_export(path, passphrase))
    }

    /// Restore a share from a portable package.
    pub fn space_custody_import(
        &self,
        path: String,
        passphrase: String,
        force: bool,
    ) -> Result<CustodyImport> {
        self.lock()
            .with_ceremony_engine(|e| e.space_custody_import(path, passphrase, force))
    }

    /// What this device can say about recovery readiness right now.
    pub fn recovery_status(&self) -> RecoveryStatus {
        self.lock().with_ceremony_engine(|e| e.recovery_status())
    }

    /// Holders on this device whose share exists but cannot be used.
    pub fn degraded_recovery(&self) -> Vec<DegradedRecoveryHolder> {
        self.lock()
            .with_ceremony_engine(|e| e.degraded_recovery_holders())
    }

    /// Drive every FROST ceremony this device participates in to a fixpoint.
    pub fn ceremony_advance(&self) -> Result<CeremonyProgress> {
        self.lock().with_ceremony_engine(|e| e.dkg_advance())
    }
}
