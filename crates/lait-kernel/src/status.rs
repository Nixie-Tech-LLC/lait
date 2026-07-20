//! Custody ledger, recovery status, and migration.
//!
//! The signing, generation, handover, resharing, and refresh backends produce the same shape of public
//! artifact: a per-leaf share and a generation-bound [`CustodyAck`] that a
//! custodian holds a usable, backed share. This module is the topology-independent
//! layer above them:
//!
//! - [`CustodyLedger`] collects transition-bound acks and answers *which leaves
//!   are backed* for a given `(transition, configuration, generation)` — ignoring
//!   acks from another transition or a stale configuration/generation, so neither
//!   old-share backing nor a concurrent transition's acks count toward this one.
//! - [`status`] projects the compiled access structure against **durability**
//!   (the ledger) and **availability** (a session-bound readiness set), keeping
//!   the two apart: is the key recoverable in principle from the backups on
//!   record, recoverable *right now* from reachable holders, at risk of genuine
//!   loss, or merely degraded — and what would restore recovery.
//! - [`frost_to_policy`] migrates an existing flat k-of-n FROST arrangement to
//!   the equivalent [`OwnershipPolicy`], preserving exactly its qualified sets.
//!
//! Everything here is a **pure, deterministic projection** — no key material, no
//! signing — so every replica computes the same status. Crucially, a custody ack
//! proves a share was *backed up*, not that its holder is reachable or willing;
//! [`status`] therefore never derives live recoverability from the grow-only
//! ledger alone. Wiring it to the tracker's `RecoveryStatus` surface and the
//! ceremony board is app-layer integration, deliberately not done here.

use std::collections::BTreeSet;

use crate::authority::{AuthorityConfigurationId, FrostThresholdConfig, LeafId};
use crate::compile::StructurallyValidatedCompiledPolicy;
use crate::policy::OwnershipPolicy;
use crate::transition::{CustodyAck, TransitionId};

/// A grow-only log of custody attestations. Backing is answered per
/// `(transition, configuration, generation)`: a `CustodyAck` is bound to the
/// exact transition that requested it, so two concurrent transitions on the same
/// configuration and generation can never pool acknowledgments — neither could
/// otherwise complete, yet the ledger would report enough durability for one.
#[derive(Debug, Clone, Default)]
pub struct CustodyLedger {
    acks: Vec<CustodyAck>,
}

impl CustodyLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an attestation. Idempotent: a repeat for the same
    /// `(transition, configuration, generation, leaf)` adds nothing to the set.
    pub fn record(&mut self, ack: CustodyAck) {
        self.acks.push(ack);
    }

    /// The leaves backed for exactly this transition, at this configuration and
    /// share generation. An ack from a different transition — even one targeting
    /// the same configuration and generation — is excluded, as are stale
    /// configuration/generation acks.
    pub fn backed_leaves(
        &self,
        transition: TransitionId,
        configuration: &AuthorityConfigurationId,
        generation: u64,
    ) -> BTreeSet<LeafId> {
        self.acks
            .iter()
            .filter(|a| {
                a.transition == transition
                    && a.configuration == *configuration
                    && a.share_generation == generation
            })
            .map(|a| a.leaf.clone())
            .collect()
    }
}

/// The readiness of a recovery arrangement — the kernel projection behind the
/// tracker's status surface.
///
/// **Durability** (can recovery *ever* happen from the backups on record?) and
/// **availability** (can it happen *right now* with holders that are reachable?)
/// are kept strictly separate. A grow-only custody ledger proves the former, not
/// the latter: a holder that backed up its share long ago and is now offline —
/// or actively withholding — is durable but not available. Conflating the two
/// would report a recoverable arrangement while recovery is operationally
/// impossible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryStatus {
    /// The transition this status is computed for. Custody counts only when bound
    /// to this exact transition, so concurrent transitions never share backing.
    pub transition: TransitionId,
    pub configuration: AuthorityConfigurationId,
    pub generation: u64,
    /// Configured leaves with a qualifying custody ack for this transition and
    /// generation — a usable share exists somewhere. Sorted.
    pub durable: Vec<LeafId>,
    /// Durable leaves whose holder also provided fresh, session-bound readiness —
    /// usable *and* reachable now. Sorted. A subset of `durable`.
    pub available: Vec<LeafId>,
    /// The durable set satisfies the policy: recovery is possible in principle
    /// once enough holders come online. Says nothing about *now*.
    pub durable_qualifies: bool,
    /// The available set satisfies the policy: recovery can proceed right now.
    pub recoverable_now: bool,
    /// The durable set does **not** satisfy the policy — the backups on record
    /// cannot recover the key even with everyone online. The sharp, unambiguous
    /// signal of genuine loss, distinct from a transient availability gap.
    pub durability_at_risk: bool,
    /// Durable enough to recover, but not every configured leaf is durable —
    /// redundancy is reduced even though quorum's backups exist.
    pub degraded: bool,
    /// When recovery cannot proceed now, **one** set of not-yet-available leaves
    /// whose readiness would enable it — a hint, not the minimum set. Empty when
    /// `recoverable_now`.
    pub example_recovery_set: Vec<LeafId>,
}

/// Project the compiled policy against durability (the ledger) and availability
/// (`available_now`, a session-bound readiness set the app collects — e.g. fresh
/// signed readiness pings). A leaf counts as available only if it is *also*
/// durable: reachability without a usable share is not something recovery can
/// lean on.
pub fn status(
    compiled: &StructurallyValidatedCompiledPolicy,
    transition: TransitionId,
    configuration: AuthorityConfigurationId,
    generation: u64,
    ledger: &CustodyLedger,
    available_now: &BTreeSet<LeafId>,
) -> RecoveryStatus {
    let configured: BTreeSet<&LeafId> = compiled.leaves().iter().collect();
    let durable_set = ledger.backed_leaves(transition, &configuration, generation);

    let durable: Vec<LeafId> = compiled
        .leaves()
        .iter()
        .filter(|l| durable_set.contains(*l))
        .cloned()
        .collect();
    // Available = durable AND reachable now.
    let available: Vec<LeafId> = durable
        .iter()
        .filter(|l| available_now.contains(*l))
        .cloned()
        .collect();

    let durable_qualifies = compiled.reconstruct(&durable).is_some();
    let recoverable_now = compiled.reconstruct(&available).is_some();
    let degraded = durable_qualifies && durable.len() < configured.len();

    let mut example_recovery_set = Vec::new();
    if !recoverable_now {
        // Greedily add leaves that are not yet available until a qualified set
        // forms. The full leaf set always qualifies, so this terminates. This is
        // one such set, not the minimum (that is set-cover).
        let mut current = available.clone();
        for leaf in compiled.leaves() {
            if compiled.reconstruct(&current).is_some() {
                break;
            }
            if !current.contains(leaf) {
                current.push(leaf.clone());
                example_recovery_set.push(leaf.clone());
            }
        }
    }

    RecoveryStatus {
        transition,
        configuration,
        generation,
        durable,
        available,
        durable_qualifies,
        recoverable_now,
        durability_at_risk: !durable_qualifies,
        degraded,
        example_recovery_set,
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
    fn tid(byte: u8) -> TransitionId {
        TransitionId::parse_hex(&data_encoding::HEXLOWER.encode(&[byte; 32])).unwrap()
    }
    /// The default transition used by most tests.
    fn t0() -> TransitionId {
        tid(0)
    }
    fn ack_for(transition: TransitionId, leaf: &LeafId, generation: u64) -> CustodyAck {
        CustodyAck {
            transition,
            configuration: config(),
            share_generation: generation,
            leaf: leaf.clone(),
            public_share_commitment: [0u8; 32],
            package_commitment: [0u8; 32],
        }
    }
    fn ack(leaf: &LeafId, generation: u64) -> CustodyAck {
        ack_for(t0(), leaf, generation)
    }

    /// A readiness set from the given leaves.
    fn avail(leaves: &[LeafId]) -> BTreeSet<LeafId> {
        leaves.iter().cloned().collect()
    }

    #[test]
    fn fully_backed_and_all_available_is_recoverable_now_and_not_degraded() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        for l in &leaves {
            ledger.record(ack(l, 0));
        }
        let s = status(&c, t0(), config(), 0, &ledger, &avail(&leaves));
        assert!(s.durable_qualifies && s.recoverable_now);
        assert!(!s.durability_at_risk);
        assert!(!s.degraded, "every configured leaf is durable");
        assert!(s.example_recovery_set.is_empty());
    }

    #[test]
    fn a_withheld_but_backed_share_blocks_recovery_now_without_endangering_durability() {
        // The genuine "withheld share" case: every leaf is backed (durable), but
        // only one holder is reachable now. Data is safe; recovery cannot proceed
        // this instant. This is NOT durability loss.
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        for l in &leaves {
            ledger.record(ack(l, 0));
        }
        // Only leaf 0 is available; the other two withhold / are offline.
        let s = status(&c, t0(), config(), 0, &ledger, &avail(&leaves[0..1]));
        assert!(s.durable_qualifies, "backups can still recover the key");
        assert!(!s.durability_at_risk, "nothing was lost");
        assert!(!s.recoverable_now, "cannot act with one reachable holder");
        assert_eq!(s.durable.len(), 3);
        assert_eq!(s.available.len(), 1);
        // One more available holder would restore live recoverability.
        assert_eq!(s.example_recovery_set.len(), 1);
    }

    #[test]
    fn a_never_acknowledged_share_endangers_durability() {
        // Distinct from withholding: two leaves never backed up at all. Even with
        // everyone online, the backups on record cannot recover the key.
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        ledger.record(ack(&leaves[0], 0));
        // leaves 1 and 2 never acknowledged; all three are "reachable".
        let s = status(&c, t0(), config(), 0, &ledger, &avail(&leaves));
        assert!(!s.durable_qualifies && s.durability_at_risk);
        assert!(!s.recoverable_now);
        assert_eq!(s.durable.len(), 1);
    }

    #[test]
    fn a_partially_backed_but_qualified_set_is_degraded() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut ledger = CustodyLedger::new();
        // Two of three durable and available: 2-of-3 recoverable, but a branch is down.
        ledger.record(ack(&leaves[0], 0));
        ledger.record(ack(&leaves[1], 0));
        let s = status(&c, t0(), config(), 0, &ledger, &avail(&leaves[0..2]));
        assert!(s.recoverable_now);
        assert!(s.degraded, "not all leaves durable");
        assert_eq!(s.durable.len(), 2);
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
        let s = status(&c, t0(), config(), 1, &ledger, &avail(&leaves));
        assert!(
            s.durability_at_risk,
            "old-generation backing does not carry over"
        );
        assert!(s.durable.is_empty());
    }

    #[test]
    fn concurrent_transitions_cannot_pool_custody() {
        // Same configuration and generation, two racing transitions. Each backs
        // half of a qualified set. Neither may borrow the other's acks.
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let ta = tid(0xAA);
        let tb = tid(0xBB);
        let mut ledger = CustodyLedger::new();
        // Transition A backs leaf 0; transition B backs leaf 1 — pooled, that
        // would be a qualified 2-of-3, but they belong to different transitions.
        ledger.record(ack_for(ta, &leaves[0], 0));
        ledger.record(ack_for(tb, &leaves[1], 0));

        let sa = status(&c, ta, config(), 0, &ledger, &avail(&leaves));
        let sb = status(&c, tb, config(), 0, &ledger, &avail(&leaves));
        // Each transition sees only its own single ack — neither qualifies.
        assert_eq!(sa.durable, vec![leaves[0].clone()]);
        assert_eq!(sb.durable, vec![leaves[1].clone()]);
        assert!(sa.durability_at_risk && sb.durability_at_risk);

        // Adding A's second leaf completes A alone, and still not B.
        ledger.record(ack_for(ta, &leaves[1], 0));
        let sa2 = status(&c, ta, config(), 0, &ledger, &avail(&leaves));
        let sb2 = status(&c, tb, config(), 0, &ledger, &avail(&leaves));
        assert!(sa2.recoverable_now, "A now has its own qualified set");
        assert!(sb2.durability_at_risk, "B still has only one ack");
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
        let s = status(&c, t0(), config(), 0, &ledger, &avail(&leaves));
        assert_eq!(
            s.durable.len(),
            1,
            "only the matching-configuration ack counts"
        );
        assert!(s.durability_at_risk);
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
        let s = status(&c, t0(), config(), 0, &ledger, &avail(&leaves[0..2]));
        assert_eq!(
            s.durable.len(),
            2,
            "duplicate does not inflate the durable set"
        );
        assert!(s.recoverable_now);
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
