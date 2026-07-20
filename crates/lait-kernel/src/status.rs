//! D6 — custody ledger, recovery status, and migration.
//!
//! The cryptographic backends (D1–D5) all produce the same shape of public
//! artifact: a per-leaf share and a generation-bound [`CustodyAck`] that a
//! custodian holds a usable, backed share. This module is the topology-independent
//! layer above them (§30):
//!
//! - [`CustodyLedger`] collects generation-bound acks and answers *which leaves
//!   are backed* at a given `(configuration, generation)` — ignoring stale acks
//!   (an earlier generation, a different configuration), so old-share backing
//!   never counts toward a newer arrangement.
//! - [`status`] projects the compiled access structure against the backed set to
//!   a [`RecoveryStatus`]: is a backed qualified set present (policy
//!   satisfiable), is quorum lost, is the arrangement merely degraded (satisfiable
//!   but not every configured leaf backed), and what would restore quorum.
//! - [`frost_to_policy`] migrates an existing flat k-of-n FROST arrangement to
//!   the equivalent [`OwnershipPolicy`], preserving exactly its qualified sets.
//!
//! Everything here is a **pure, deterministic projection** — no key material, no
//! signing — so every replica computes the same status, and a liveness failure
//! (withheld shares, an abandoned ceremony) yields an unambiguous `quorum_lost`
//! rather than an undefined state. This is the one D6 piece that lives entirely
//! in the kernel; wiring it to the tracker's `RecoveryStatus` surface and the
//! ceremony board is app-layer integration, deliberately not done here.

use std::collections::BTreeSet;

use crate::authority::{AuthorityConfigurationId, FrostThresholdConfig, LeafId};
use crate::compile::StructurallyValidatedCompiledPolicy;
use crate::policy::OwnershipPolicy;
use crate::transition::CustodyAck;

/// A grow-only log of custody attestations. Backing is answered per
/// `(configuration, generation)`, so a leaf backed under an old generation does
/// not count once the arrangement moves on.
#[derive(Debug, Clone, Default)]
pub struct CustodyLedger {
    acks: Vec<CustodyAck>,
}

impl CustodyLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attestation. Idempotent: a repeat for the same
    /// `(configuration, generation, leaf)` adds nothing to the backed set.
    pub fn record(&mut self, ack: CustodyAck) {
        self.acks.push(ack);
    }

    /// The leaves backed at exactly this configuration and share generation.
    /// Stale acks — a different configuration or an earlier/later generation —
    /// are excluded.
    pub fn backed_leaves(
        &self,
        configuration: &AuthorityConfigurationId,
        generation: u64,
    ) -> BTreeSet<LeafId> {
        self.acks
            .iter()
            .filter(|a| a.configuration == *configuration && a.share_generation == generation)
            .map(|a| a.leaf.clone())
            .collect()
    }
}

/// The readiness of a recovery arrangement — the kernel projection behind the
/// tracker's status surface (§30).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryStatus {
    pub configuration: AuthorityConfigurationId,
    pub generation: u64,
    /// Configured leaves that are backed at this generation, sorted.
    pub backed: Vec<LeafId>,
    /// A backed set qualifies under the policy — recovery can proceed now.
    pub satisfiable: bool,
    /// No backed set qualifies — recovery cannot proceed. The unambiguous
    /// outcome of a liveness failure, never an undefined state.
    pub quorum_lost: bool,
    /// Satisfiable, but not every configured leaf is backed — some branch is
    /// down even though quorum holds.
    pub degraded: bool,
    /// If quorum is lost, a set of currently-unbacked leaves whose backing would
    /// restore it (best-effort, not guaranteed minimal). Empty when satisfiable.
    pub missing_for_quorum: Vec<LeafId>,
}

/// Project the compiled policy against the ledger's backed leaves.
pub fn status(
    compiled: &StructurallyValidatedCompiledPolicy,
    configuration: AuthorityConfigurationId,
    generation: u64,
    ledger: &CustodyLedger,
) -> RecoveryStatus {
    // Only leaves that are actually in this policy can back it.
    let configured: BTreeSet<&LeafId> = compiled.leaves().iter().collect();
    let backed_set = ledger.backed_leaves(&configuration, generation);
    let backed: Vec<LeafId> = compiled
        .leaves()
        .iter()
        .filter(|l| backed_set.contains(*l))
        .cloned()
        .collect();

    let satisfiable = compiled.reconstruct(&backed).is_some();
    let degraded = satisfiable && backed.len() < configured.len();

    let mut missing_for_quorum = Vec::new();
    if !satisfiable {
        // Greedily add unbacked leaves until a qualified set forms. The full leaf
        // set is always qualified, so this terminates.
        let mut current = backed.clone();
        for leaf in compiled.leaves() {
            if compiled.reconstruct(&current).is_some() {
                break;
            }
            if !current.contains(leaf) {
                current.push(leaf.clone());
                missing_for_quorum.push(leaf.clone());
            }
        }
    }

    RecoveryStatus {
        configuration,
        generation,
        backed,
        satisfiable,
        quorum_lost: !satisfiable,
        degraded,
        missing_for_quorum,
    }
}

/// Migrate a flat k-of-n FROST arrangement to the equivalent ownership policy: a
/// `Threshold` over the same participants. The compiled policy's qualified sets
/// are exactly "any k of the n participants" — migration preserves authority.
pub fn frost_to_policy(frost: &FrostThresholdConfig) -> OwnershipPolicy {
    OwnershipPolicy::Threshold {
        k: frost.k,
        members: frost
            .participants
            .iter()
            .cloned()
            .map(OwnershipPolicy::Key)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::PrincipalId;
    use crate::compile::{compile, StructurallyValidatedCompiledPolicy};
    use crate::expand::{expand, PrincipalCustody, PrincipalDescriptor};
    use crate::policy::OwnershipPolicy;

    fn prin(n: u8) -> PrincipalId {
        PrincipalId::of_device(&crate::crypto::user_from_seed(&[n; 32]))
    }
    fn key(n: u8) -> OwnershipPolicy {
        OwnershipPolicy::Key(prin(n))
    }
    fn resolver() -> impl Fn(&PrincipalId) -> Option<PrincipalDescriptor> {
        |p: &PrincipalId| {
            Some(PrincipalDescriptor {
                id: p.clone(),
                custody: PrincipalCustody::Direct {
                    device: p.as_device()?,
                },
            })
        }
    }
    fn compiled(o: OwnershipPolicy) -> (StructurallyValidatedCompiledPolicy, Vec<LeafId>) {
        let canon = o.canonicalize().unwrap();
        let exp = expand(&canon, &resolver()).unwrap();
        let c = compile(&exp).unwrap();
        let leaves = c.leaves().to_vec();
        (c, leaves)
    }
    fn config() -> AuthorityConfigurationId {
        AuthorityConfigurationId::single()
    }
    fn ack(leaf: &LeafId, generation: u64) -> CustodyAck {
        CustodyAck {
            transition: crate::transition::TransitionId::parse_hex(
                &data_encoding::HEXLOWER.encode(&[0u8; 32]),
            )
            .unwrap(),
            configuration: config(),
            share_generation: generation,
            leaf: leaf.clone(),
            public_share_commitment: [0u8; 32],
            package_commitment: [0u8; 32],
        }
    }

    #[test]
    fn a_backed_qualified_set_is_satisfiable_and_not_degraded_when_all_backed() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        for l in &leaves {
            ledger.record(ack(l, 0));
        }
        let s = status(&c, config(), 0, &ledger);
        assert!(s.satisfiable && !s.quorum_lost);
        assert!(!s.degraded, "every configured leaf is backed");
        assert!(s.missing_for_quorum.is_empty());
    }

    #[test]
    fn a_partially_backed_but_qualified_set_is_degraded() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        // Only two of three backed: 2-of-3 is satisfiable, but a branch is down.
        ledger.record(ack(&leaves[0], 0));
        ledger.record(ack(&leaves[1], 0));
        let s = status(&c, config(), 0, &ledger);
        assert!(s.satisfiable);
        assert!(s.degraded, "not all leaves backed");
        assert_eq!(s.backed.len(), 2);
    }

    #[test]
    fn a_withheld_share_yields_unambiguous_quorum_loss() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        // Only one of three backed: 2-of-3 cannot be met.
        ledger.record(ack(&leaves[0], 0));
        let s = status(&c, config(), 0, &ledger);
        assert!(!s.satisfiable && s.quorum_lost);
        // Exactly one more leaf restores quorum.
        assert_eq!(s.missing_for_quorum.len(), 1);
    }

    #[test]
    fn stale_generation_acks_do_not_count() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        // Two leaves backed, but under the OLD generation 0.
        ledger.record(ack(&leaves[0], 0));
        ledger.record(ack(&leaves[1], 0));
        // Query generation 1 (e.g. after a refresh): no backing counts.
        let s = status(&c, config(), 1, &ledger);
        assert!(s.quorum_lost, "old-generation backing does not carry over");
        assert!(s.backed.is_empty());
    }

    #[test]
    fn wrong_configuration_acks_do_not_count() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        // An ack whose configuration is some *other* arrangement entirely.
        let mut other = ack(&leaves[0], 0);
        other.configuration =
            crate::authority::AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
                k: 2,
                participants: vec![prin(7), prin(8), prin(9)],
            })
            .id();
        ledger.record(other);
        ledger.record(ack(&leaves[1], 0));
        let s = status(&c, config(), 0, &ledger);
        assert_eq!(
            s.backed.len(),
            1,
            "only the matching-configuration ack counts"
        );
        assert!(s.quorum_lost);
    }

    #[test]
    fn duplicate_acks_are_idempotent() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        ledger.record(ack(&leaves[0], 0));
        ledger.record(ack(&leaves[0], 0)); // duplicate
        ledger.record(ack(&leaves[1], 0));
        let s = status(&c, config(), 0, &ledger);
        assert_eq!(
            s.backed.len(),
            2,
            "duplicate does not inflate the backed set"
        );
        assert!(s.satisfiable);
    }

    #[test]
    fn migration_from_flat_frost_preserves_the_qualified_sets() {
        let frost = FrostThresholdConfig {
            k: 2,
            participants: vec![prin(1), prin(2), prin(3)],
        };
        let policy = frost_to_policy(&frost);
        let (c, leaves) = compiled(policy);
        // Any 2 of 3 qualify; any 1 does not — exactly the FROST 2-of-3 semantics.
        assert!(c
            .reconstruct(&[leaves[0].clone(), leaves[1].clone()])
            .is_some());
        assert!(c
            .reconstruct(&[leaves[0].clone(), leaves[2].clone()])
            .is_some());
        assert!(c.reconstruct(&[leaves[0].clone()]).is_none());
    }
}
