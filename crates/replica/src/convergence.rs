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
