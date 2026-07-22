//! Share refresh and repair, kept as two distinct protocols.
//!
//! - **Refresh** ([`refresh`]) replaces every share while keeping the public key
//!   *and the policy*. Each contributor deals a fresh sharing of **zero** over
//!   the same matrix; adding it re-randomizes shares without moving the secret.
//!   Under a proactive-erasure model this invalidates the old shares.
//! - **Repair** ([`recover`]) restores one lost leaf's share *without
//!   reconstructing the secret*. A helper set whose rows span the lost leaf's row
//!   recomputes `s_lost = Σ_j μ_j s_j`; pairwise masks hide each helper's term, so
//!   the combiner learns only `s_lost` — never a helper's share, never `x`.
//!
//! Refresh keeps policy and key; resharing changes the policy; rotation
//! changes the key. Three different operations, three modules.
//!
//! ## Refresh algebra
//!
//! ```text
//! contributor p:  ρ^(p) ∈ F^d,  ρ^(p)_0 = 0        (a sharing of zero)
//!                 C^(p)_l = ρ^(p)_l · G             C^(p)_0 = 0·G = identity
//!                 δ_i^(p) = ⟨A_i, ρ^(p)⟩
//! new share:      s_i' = s_i + Σ_p δ_i^(p)          Σ_p ρ^(p)_0 = 0 ⇒ secret, key unchanged
//! ```
//!
//! `C^(p)_0 == identity` is what distinguishes a refresh (zero sub-secret) from a
//! key change; the verifier enforces it.
//!
//! ## Repair algebra
//!
//! [`crate::compile::StructurallyValidatedCompiledPolicy::repair_coefficients`]
//! yields `μ` with `A_lost = Σ_j μ_j A_{helper_j}`, so
//! `s_lost = ⟨A_lost, ρ⟩ = Σ_j μ_j s_j`. Each helper masks its term with
//! antisymmetric pairwise randomness that cancels in the sum:
//!
//! ```text
//! m_j = μ_j s_j + Σ_{k≠j} r_{jk},   r_{jk} = −r_{kj}   ⇒   Σ_j m_j = Σ_j μ_j s_j = s_lost
//! ```
//!
//! # Security status
//!
//! The [`crate::gaccess`]/[`crate::gdkg`] boundaries carry over. Refresh's
//! proactive guarantee is only as good as its erasure/epoch model — the same
//! requirement as proactive resharing; deleting old shares is an explicit operation
//! this prototype does not perform. Repair's masking here is generated in one
//! place to demonstrate the cancellation; the real protocol distributes the
//! pairwise randomness over authenticated channels and defends against a
//! malicious helper contributing a bad masked value (which this prototype
//! detects only in aggregate, via the final `s·G == S_lost` check). Wired into
//! nothing.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::authority::LeafId;
use crate::compile::StructurallyValidatedCompiledPolicy;
use crate::gaccess::KeyShares;
use crate::gdkg::GroupKey;

/// Errors refreshing a group key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshError {
    /// A contribution's commitment vector is not `d` long.
    WrongDimension { dealer: LeafId },
    /// A contribution's `C_0` is not the identity — it does not share zero, so it
    /// would move the secret. A refresh must not change the key.
    NonZeroSecret { dealer: LeafId },
    /// A dealt delta failed its Feldman check.
    InconsistentDelta { dealer: LeafId, leaf: LeafId },
    /// Two contributions claim the same dealer — a replayed zero-sharing.
    DuplicateDealer { dealer: LeafId },
    /// A stored point did not decode.
    BadPoint,
}

/// One contributor's zero-sharing used to re-randomize the shares.
#[derive(Debug, Clone)]
pub struct RefreshContribution {
    dealer: LeafId,
    commitments: Vec<EdwardsPoint>,
    deltas: BTreeMap<LeafId, Scalar>,
}

impl RefreshContribution {
    pub fn dealer(&self) -> &LeafId {
        &self.dealer
    }
}

fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    getrandom::fill(&mut wide).expect("getrandom");
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn row_of(compiled: &StructurallyValidatedCompiledPolicy, leaf: &LeafId) -> Option<Vec<Scalar>> {
    let idx = compiled.leaves().iter().position(|l| l == leaf)?;
    Some(
        compiled.inner().matrix.rows[idx]
            .iter()
            .map(|c| c.as_scalar().expect("validated field element"))
            .collect(),
    )
}

fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes).decompress()
}

/// Produce `dealer`'s zero-sharing: `ρ` with `ρ_0 = 0`, Feldman commitments (so
/// `C_0 = identity`), and a delta for every leaf.
pub fn refresh_contribution(
    compiled: &StructurallyValidatedCompiledPolicy,
    dealer: LeafId,
) -> RefreshContribution {
    let cols = compiled.cols();
    let mut rho = vec![Scalar::ZERO];
    rho.extend((1..cols).map(|_| random_scalar()));
    let commitments: Vec<EdwardsPoint> = rho.iter().map(|r| G * r).collect();
    let mut deltas = BTreeMap::new();
    for leaf in compiled.leaves() {
        let row = row_of(compiled, leaf).expect("leaf in policy");
        let d: Scalar = row.iter().zip(&rho).map(|(a, r)| a * r).sum();
        deltas.insert(leaf.clone(), d);
    }
    RefreshContribution {
        dealer,
        commitments,
        deltas,
    }
}

/// The point `Σ_l A_{leaf,l} · C_l` for a contribution — the commitment its delta
/// to `leaf` must open to.
fn delta_point(
    compiled: &StructurallyValidatedCompiledPolicy,
    leaf: &LeafId,
    commitments: &[EdwardsPoint],
) -> Option<EdwardsPoint> {
    let row = row_of(compiled, leaf)?;
    if row.len() != commitments.len() {
        return None;
    }
    Some(row.iter().zip(commitments).map(|(a, c)| c * a).sum())
}

/// A leaf's check of a refresh contribution: `C_0` is the identity (zero secret)
/// and every delta matches the commitments.
pub fn verify_refresh(
    compiled: &StructurallyValidatedCompiledPolicy,
    contribution: &RefreshContribution,
) -> bool {
    if contribution.commitments.len() != compiled.cols() {
        return false;
    }
    if contribution.commitments[0] != EdwardsPoint::identity() {
        return false;
    }
    for leaf in compiled.leaves() {
        let Some(expected) = delta_point(compiled, leaf, &contribution.commitments) else {
            return false;
        };
        let Some(&d) = contribution.deltas.get(leaf) else {
            return false;
        };
        if G * d != expected {
            return false;
        }
    }
    true
}

/// Refresh `old` with zero-sharings from `contributions`: same policy, same key,
/// new shares `s_i' = s_i + Σ_p δ_i^(p)`. Every contribution is re-verified
/// (including `C_0 == identity`) before use.
pub fn refresh(
    compiled: &StructurallyValidatedCompiledPolicy,
    old: &GroupKey,
    contributions: &[RefreshContribution],
) -> Result<GroupKey, RefreshError> {
    // Contributor identity is a set: a replayed zero-sharing must not be applied
    // twice, which would double its delta and re-randomize past the agreed epoch.
    let mut seen: BTreeSet<&LeafId> = BTreeSet::new();
    for c in contributions {
        if !seen.insert(&c.dealer) {
            return Err(RefreshError::DuplicateDealer {
                dealer: c.dealer.clone(),
            });
        }
    }
    for c in contributions {
        if c.commitments.len() != compiled.cols() {
            return Err(RefreshError::WrongDimension {
                dealer: c.dealer.clone(),
            });
        }
        if c.commitments[0] != EdwardsPoint::identity() {
            return Err(RefreshError::NonZeroSecret {
                dealer: c.dealer.clone(),
            });
        }
        for leaf in compiled.leaves() {
            let ok = delta_point(compiled, leaf, &c.commitments)
                .zip(c.deltas.get(leaf))
                .is_some_and(|(expected, &d)| G * d == expected);
            if !ok {
                return Err(RefreshError::InconsistentDelta {
                    dealer: c.dealer.clone(),
                    leaf: leaf.clone(),
                });
            }
        }
    }

    let mut shares = BTreeMap::new();
    let mut leaf_commitments = BTreeMap::new();
    for leaf in compiled.leaves() {
        let old_share = old.share(leaf).ok_or(RefreshError::BadPoint)?;
        let old_commit = decompress(&old.leaf_commitment(leaf).ok_or(RefreshError::BadPoint)?)
            .ok_or(RefreshError::BadPoint)?;
        let mut s = old_share;
        let mut commit = old_commit;
        for c in contributions {
            s += c.deltas[leaf];
            commit += delta_point(compiled, leaf, &c.commitments).ok_or(RefreshError::BadPoint)?;
        }
        shares.insert(leaf.clone(), s);
        leaf_commitments.insert(leaf.clone(), commit.compress().to_bytes());
    }

    GroupKey::from_verified_parts(old.public_key(), shares, leaf_commitments)
        .ok_or(RefreshError::BadPoint)
}

/// One helper's masked contribution toward repairing a lost share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairContribution {
    pub helper: LeafId,
    pub masked: Scalar,
}

/// Build every helper's masked contribution toward repairing a lost leaf's share.
///
/// `coeffs` are the repair coefficients `μ` (from `repair_coefficients`); `shares`
/// gives each helper's own share. Antisymmetric pairwise masks are added so the
/// individual `μ_j s_j` terms are hidden: `Σ` of the returned `masked` values is
/// `s_lost`, but no single value reveals a helper's share. Returns `None` if a
/// coefficient names a helper with no share.
///
/// In the real protocol each helper draws its own half of every pairwise mask
/// over an authenticated channel; here they are generated together to exercise
/// the cancellation.
pub fn masked_contributions(
    coeffs: &[(LeafId, Scalar)],
    shares: &BTreeMap<LeafId, Scalar>,
) -> Option<Vec<RepairContribution>> {
    let n = coeffs.len();
    // Antisymmetric mask matrix: r[j][k] = -r[k][j], r[j][j] = 0. Indexing is the
    // natural expression here — each draw fills a symmetric pair of cells.
    let mut r = vec![vec![Scalar::ZERO; n]; n];
    #[allow(clippy::needless_range_loop)]
    for j in 0..n {
        for k in (j + 1)..n {
            let m = random_scalar();
            r[j][k] = m;
            r[k][j] = -m;
        }
    }
    let mut out = Vec::with_capacity(n);
    for (j, (leaf, mu)) in coeffs.iter().enumerate() {
        let s = shares.get(leaf)?;
        let mask: Scalar = (0..n).map(|k| r[j][k]).sum();
        out.push(RepairContribution {
            helper: leaf.clone(),
            masked: mu * s + mask,
        });
    }
    Some(out)
}

/// Combine helpers' masked contributions into the repaired share, and verify it
/// against the lost leaf's known public commitment `S_lost`. Returns the share
/// only if `s·G == S_lost`, so a bad contribution is caught even though the
/// combiner never sees the unmasked terms.
pub fn recover(contributions: &[RepairContribution], lost_commitment: &[u8; 32]) -> Option<Scalar> {
    let s: Scalar = contributions.iter().map(|c| c.masked).sum();
    let expected = decompress(lost_commitment)?;
    (G * s == expected).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::PrincipalId;
    use crate::compile::compile;
    use crate::expand::{expand, PrincipalCustody, PrincipalDescriptor};
    use crate::gaccess::{commit, sign_qualified, verify, KeyShares, Nonce};
    use crate::gdkg::{aggregate, contribute};
    use crate::policy::OwnershipPolicy;

    fn prin(n: u8) -> PrincipalId {
        PrincipalId::of_device(&crate::crypto::device_from_seed(&[n; 32]))
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
    fn dkg(c: &StructurallyValidatedCompiledPolicy, leaves: &[LeafId]) -> GroupKey {
        let contribs: Vec<_> = leaves.iter().map(|l| contribute(c, l.clone())).collect();
        aggregate(c, &contribs).expect("aggregate")
    }
    fn sign_with<K: KeyShares>(
        c: &StructurallyValidatedCompiledPolicy,
        km: &K,
        signers: &[LeafId],
        msg: &[u8],
    ) -> bool {
        let witness = c.reconstruct(signers).expect("qualified");
        let mut nonces: BTreeMap<LeafId, Nonce> = BTreeMap::new();
        let mut commitments = Vec::new();
        for leaf in &witness.leaves {
            let (n, com) = commit();
            nonces.insert(leaf.clone(), n);
            commitments.push((leaf.clone(), com));
        }
        let sig = sign_qualified(&witness, km, &nonces, &commitments, msg).expect("sign");
        verify(&km.public_key(), msg, &sig)
    }

    #[test]
    fn refresh_keeps_key_and_policy_but_rerandomizes_shares() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&c, &leaves);
        let contribs: Vec<_> = leaves
            .iter()
            .map(|l| refresh_contribution(&c, l.clone()))
            .collect();
        for rc in &contribs {
            assert!(verify_refresh(&c, rc), "zero-sharing verifies");
        }
        let fresh = refresh(&c, &old, &contribs).expect("refresh");

        // Same public key.
        assert_eq!(fresh.public_key(), old.public_key(), "key preserved");
        // Shares actually changed.
        for l in &leaves {
            assert_ne!(fresh.share(l), old.share(l), "share re-randomized");
        }
        // The same policy's qualified set signs under the same key with new shares.
        assert!(sign_with(
            &c,
            &fresh,
            &[leaves[1].clone(), leaves[2].clone()],
            b"after refresh",
        ));
    }

    #[test]
    fn a_replayed_refresh_contribution_is_rejected() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&c, &leaves);
        let mut contribs: Vec<_> = leaves
            .iter()
            .map(|l| refresh_contribution(&c, l.clone()))
            .collect();
        // Replaying dealer 0's zero-sharing must not double-apply its delta.
        contribs.push(contribs[0].clone());
        assert_eq!(
            refresh(&c, &old, &contribs),
            Err(RefreshError::DuplicateDealer {
                dealer: leaves[0].clone(),
            })
        );
    }

    #[test]
    fn a_refresh_contribution_that_moves_the_secret_is_rejected() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&c, &leaves);
        // A non-zero-secret dealing is a gdkg contribution (C_0 = ρ_0·G ≠ id).
        let bad = {
            let good = refresh_contribution(&c, leaves[0].clone());
            // Turn it into a non-zero secret by using a normal DKG contribution's
            // shape: rebuild with ρ_0 ≠ 0 via the gdkg dealer, then adapt.
            let mut commitments = good.commitments.clone();
            commitments[0] = G * Scalar::from(5u64); // C_0 ≠ identity
            RefreshContribution {
                dealer: leaves[0].clone(),
                commitments,
                deltas: good.deltas.clone(),
            }
        };
        assert!(!verify_refresh(&c, &bad));
        assert_eq!(
            refresh(&c, &old, &[bad]),
            Err(RefreshError::NonZeroSecret {
                dealer: leaves[0].clone()
            })
        );
    }

    #[test]
    fn a_tampered_refresh_delta_is_rejected() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&c, &leaves);
        let mut contribs: Vec<_> = leaves
            .iter()
            .map(|l| refresh_contribution(&c, l.clone()))
            .collect();
        let victim = leaves[1].clone();
        *contribs[0].deltas.get_mut(&victim).unwrap() += Scalar::ONE;
        assert_eq!(
            refresh(&c, &old, &contribs),
            Err(RefreshError::InconsistentDelta {
                dealer: leaves[0].clone(),
                leaf: victim,
            })
        );
    }

    #[test]
    fn repair_recovers_a_lost_share_without_reconstructing_the_secret() {
        // 3-of-5: leaf 0 is lost; leaves 1..4 help.
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 3,
            members: vec![key(1), key(2), key(3), key(4), key(5)],
        });
        let group = dkg(&c, &leaves);
        let lost = leaves[0].clone();
        let helpers = vec![leaves[1].clone(), leaves[2].clone(), leaves[3].clone()];

        let coeffs = c
            .repair_coefficients(&helpers, &lost)
            .expect("helpers span the lost row");
        // Helper shares (each helper contributes only its own).
        let shares: BTreeMap<LeafId, Scalar> = helpers
            .iter()
            .map(|l| (l.clone(), group.share(l).unwrap()))
            .collect();
        let contribs = masked_contributions(&coeffs, &shares).unwrap();
        // No masked contribution equals the bare μ_j·s_j term (masking is real).
        for (rc, (leaf, mu)) in contribs.iter().zip(&coeffs) {
            assert_ne!(rc.masked, mu * shares[leaf], "term is masked");
        }
        let s_lost = group.leaf_commitment(&lost).unwrap();
        let recovered = recover(&contribs, &s_lost).expect("recovers and verifies");
        // The recovered share equals the original — and is NOT the secret x.
        assert_eq!(recovered, group.share(&lost).unwrap());
    }

    #[test]
    fn a_repaired_leaf_participates_in_signing() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let group = dkg(&c, &leaves);
        let lost = leaves[0].clone();
        let helpers = vec![leaves[1].clone(), leaves[2].clone()];
        let coeffs = c.repair_coefficients(&helpers, &lost).unwrap();
        let shares: BTreeMap<LeafId, Scalar> = helpers
            .iter()
            .map(|l| (l.clone(), group.share(l).unwrap()))
            .collect();
        let contribs = masked_contributions(&coeffs, &shares).unwrap();
        let recovered = recover(&contribs, &group.leaf_commitment(&lost).unwrap()).unwrap();
        // The recovered share matches, so a qualified set using leaf 0 signs.
        assert_eq!(recovered, group.share(&lost).unwrap());
        assert!(sign_with(
            &c,
            &group,
            &[lost, leaves[1].clone()],
            b"repaired signs"
        ));
    }

    #[test]
    fn helpers_that_do_not_span_the_lost_row_cannot_repair() {
        // 2-of-3: a single helper's one row cannot express a different leaf's row.
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        assert!(c
            .repair_coefficients(&[leaves[1].clone()], &leaves[0])
            .is_none());
    }
}
