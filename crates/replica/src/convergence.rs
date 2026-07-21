//! Convergence outcomes.
//!
//! Contact reports transfer separately from Convergence. Convergence classifies
//! legitimacy, incorporates material through Fabric, advances the semantic
//! frontier, and reports what changed. Outcomes report bytes moved separately
//! from accepted, unchanged, rejected, and retryable material — a World never
//! overrides Space legitimacy, and unknown-World material stays opaque and
//! retained.

use serde::{Deserialize, Serialize};

use crate::frontier::ReplicaFrontier;

/// How a single incoming transaction was classified during Convergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncorporationClass {
    /// New, legitimate, and incorporated — advanced the frontier.
    Accepted,
    /// Already held; no frontier change.
    Unchanged,
    /// Illegitimate (bad Space binding, authority, or integrity) — rejected.
    Rejected,
    /// Legitimate but for an unknown World or unsupported schema: retained
    /// opaquely and transferable, not interpreted.
    UnsupportedButRetained,
    /// A transient/persistence failure; the material may be retried.
    Retryable,
}

/// The result of a Convergence pass over incoming material. The frontier fields
/// report the atomic boundary: recovery exposes the complete old or complete new
/// frontier, never a manifest pointing at absent material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceOutcome {
    /// The frontier before this pass.
    pub previous: ReplicaFrontier,
    /// The frontier after this pass (equal to `previous` when nothing changed).
    pub current: ReplicaFrontier,
    pub accepted: u32,
    pub unchanged: u32,
    pub rejected: u32,
    pub unsupported_retained: u32,
    pub retryable: u32,
}

impl ConvergenceOutcome {
    /// A no-op outcome that neither accepted nor changed anything.
    pub fn unchanged(frontier: ReplicaFrontier) -> Self {
        Self {
            previous: frontier,
            current: frontier,
            accepted: 0,
            unchanged: 0,
            rejected: 0,
            unsupported_retained: 0,
            retryable: 0,
        }
    }

    /// Whether the semantic frontier advanced.
    pub fn advanced(&self) -> bool {
        self.previous != self.current
    }
}

/// The staged material a completed Contact hands to validation — raw,
/// **untrusted** bytes exactly as received. The transport (Contact machine)
/// has proven only transcript completeness; every legitimacy property is
/// established by [`crate::Replica::validate_contact`].
#[derive(Debug, Clone)]
pub struct StagedContactMaterial {
    /// The authority-section records: mechanics authority material and the
    /// signed `BodyTransactionV1` records, byte-canonical.
    pub authority_records: Vec<Vec<u8>>,
    /// The signed manifest root, byte-canonical.
    pub manifest_root_bytes: Vec<u8>,
    /// The manifest pages, ordered by page index, byte-canonical.
    pub manifest_pages: Vec<Vec<u8>>,
    /// Received protected Body payloads: `(transaction id, key, envelope)`.
    pub bodies: Vec<([u8; 16], crate::ids::BodyKey, Vec<u8>)>,
}

/// The durable receipt of an authority-batch incorporation — the explicit
/// **first** durable phase of Convergence. Mechanics commits the canonical
/// authority batch idempotently and names the resulting historical frontier;
/// the Body/Manifest phase then requires this receipt, so Bodies never commit
/// under authority that is not durably established. A replay of the same
/// batch returns the same receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityReceipt {
    pub frontier: crate::frontier::AuthorityFrontier,
}

/// The mechanics-owned authority incorporation seam. The composition root
/// implements it over the durable signed-history store; the fixture
/// implementation for tests records batches in memory.
pub trait AuthorityIncorporator {
    /// Durably, idempotently commit a canonical authority batch. Legitimate
    /// authority advancement may survive a later Body failure — it is
    /// independently valid Space history.
    fn incorporate_authority(&mut self, records: &[Vec<u8>]) -> Result<AuthorityReceipt, String>;
}

/// A **sealed** validated Contact bundle: constructible only by
/// [`crate::Replica::validate_contact`], after every check passed — transcript
/// -complete staging, durable authority receipt, authority-verified manifest
/// root, complete verified pages, per-entry authorized transactions,
/// descriptor-bound payloads, and no received object outside the verified
/// graph. [`crate::Replica::incorporate_bundle`] accepts only this.
pub struct ValidatedContactBundle {
    pub(crate) authority_receipt: AuthorityReceipt,
    pub(crate) units: BundleUnits,
}

/// The bundle's validated transactions with their per-Body payloads.
pub(crate) type BundleUnits = Vec<(
    crate::transaction::BodyTransactionV1,
    Vec<(crate::ids::BodyKey, Vec<u8>)>,
)>;

impl ValidatedContactBundle {
    /// The durable authority receipt this bundle's Body phase rests on.
    pub fn authority_receipt(&self) -> &AuthorityReceipt {
        &self.authority_receipt
    }
    /// How many validated transactions the bundle carries.
    pub fn transaction_count(&self) -> usize {
        self.units.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unchanged_outcome_does_not_advance() {
        let f = ReplicaFrontier::new([2u8; 32], 7);
        let o = ConvergenceOutcome::unchanged(f);
        assert!(!o.advanced());
        assert_eq!(o.accepted, 0);
    }

    #[test]
    fn advancement_is_by_frontier_change() {
        let mut o = ConvergenceOutcome::unchanged(ReplicaFrontier::new([0u8; 32], 0));
        o.current = ReplicaFrontier::new([1u8; 32], 1);
        o.accepted = 1;
        assert!(o.advanced());
    }
}
