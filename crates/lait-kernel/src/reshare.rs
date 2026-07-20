//! Proactive same-key resharing.
//!
//! ```text
//! Policy P1, shares S1, public key Y   →  authorized resharing  →  Policy P2, shares S2, public key Y
//! ```
//!
//! Move a secret from one access structure to another **without changing the
//! public key and without anyone ever reconstructing the secret `x`**. Each
//! member `i` of a qualified old set `Q` re-shares its *own* share `s_i` — a
//! value it legitimately holds — as the sub-secret of a fresh sharing over the
//! new matrix `A₂`:
//!
//! ```text
//! σ^(i) ∈ F^{d₂},  σ^(i)_0 = s_i        (dealer i knows s_i; nobody learns x)
//! C^(i)_l = σ^(i)_l · G                  Feldman commitments; C^(i)_0 = s_i·G = S_i
//! u_j^(i) = ⟨A₂_j, σ^(i)⟩                sub-share to new leaf j
//! ```
//!
//! New leaf `j` combines the sub-shares it received with the **old** witness
//! coefficients `λ_i`:
//!
//! ```text
//! t_j = Σ_{i∈Q} λ_i · u_j^(i) = ⟨A₂_j, Σ_i λ_i σ^(i)⟩ = ⟨A₂_j, ρ'⟩
//! ρ'_0 = Σ_i λ_i σ^(i)_0 = Σ_i λ_i s_i = x        ⇒   new key = x·G = Y (unchanged)
//! ```
//!
//! The recomputed key `Σ_i λ_i S_i` must equal the old `Y`, and each `C^(i)_0`
//! must equal the old public share `S_i` — so a dishonest old holder cannot
//! substitute a different sub-secret. The result is a fresh [`crate::gdkg::GroupKey`]
//! under the same `Y`, holding new shares over the new leaves.
//!
//! # Security status
//!
//! Beyond the [`crate::gaccess`]/[`crate::gdkg`] boundaries: resharing is **not
//! a revocation mechanism**. An old qualified coalition that kept its old
//! shares can still sign under the unchanged `Y`, and an ordinary Schnorr
//! verifier cannot tell which sharing produced a signature — the
//! `an_old_coalition_can_still_sign_after_resharing` test states this in code.
//! A governance change that must *remove* an old capability uses key rotation, not
//! this. Same-key resharing is legitimate only under an explicit proactive model
//! (secure erasure of old shares, bounded mobile corruption, authenticated
//! handoff) or a monotone change where every old qualified coalition stays
//! authorized — a classification this prototype does not enforce. A production
//! protocol also needs an epoch and secure-erasure model (for example,
//! CHURP-style); this module implements only the share-transfer algebra and is
//! not wired into the workspace authority path.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::authority::LeafId;
use crate::compile::{ReconstructionWitness, StructurallyValidatedCompiledPolicy};
use crate::gaccess::KeyShares;
use crate::gdkg::GroupKey;

/// Errors resharing onto a new access structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReshareError {
    /// The old witness does not verify against the standing configuration — the
    /// contributing leaves are not a qualified coalition of it.
    UnqualifiedOldSet,
    /// Two contributions claim the same old dealer.
    DuplicateDealer { dealer: LeafId },
    /// The contributions do not correspond exactly to the qualified old set.
    ContributorSetMismatch,
    /// A contribution's commitment vector is not `d₂` long.
    WrongDimension { dealer: LeafId },
    /// A sub-share failed its Feldman check against the contribution's commitments.
    InconsistentSubShare { dealer: LeafId, leaf: LeafId },
    /// A contribution's `C_0` is not the old public share `S_i` of its dealer —
    /// the dealer tried to reshare a sub-secret other than its real old share.
    WrongOldCommitment { dealer: LeafId },
    /// The recomputed public key `Σ λ_i S_i` is not the old `Y`. The witness and
    /// the old commitments are inconsistent; refuse rather than silently mint a
    /// different key.
    SameKeyViolated,
    /// A referenced old commitment or new-leaf point did not decode.
    BadPoint,
}

/// One old holder's resharing of its share into the new structure.
#[derive(Debug, Clone)]
pub struct ReshareContribution {
    dealer: LeafId,
    commitments: Vec<EdwardsPoint>,
    sub_shares: BTreeMap<LeafId, Scalar>,
}

impl ReshareContribution {
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

/// Old holder `dealer` reshares its `old_share` into `new_compiled`: draw a
/// sub-sharing with `old_share` as the sub-secret, commit to it, and deal a
/// sub-share to every new leaf. `C_0 = old_share·G` is, for an honest dealer,
/// exactly its known old public share `S_i`.
pub fn contribution(
    new_compiled: &StructurallyValidatedCompiledPolicy,
    dealer: LeafId,
    old_share: Scalar,
) -> ReshareContribution {
    let cols = new_compiled.cols();
    let mut sigma = vec![old_share];
    sigma.extend((1..cols).map(|_| random_scalar()));
    let commitments: Vec<EdwardsPoint> = sigma.iter().map(|s| G * s).collect();
    let mut sub_shares = BTreeMap::new();
    for leaf in new_compiled.leaves() {
        let row = row_of(new_compiled, leaf).expect("new leaf in policy");
        let u: Scalar = row.iter().zip(&sigma).map(|(a, s)| a * s).sum();
        sub_shares.insert(leaf.clone(), u);
    }
    ReshareContribution {
        dealer,
        commitments,
        sub_shares,
    }
}

/// A new leaf's check of one resharing contribution: every sub-share matches the
/// commitments (`u_j·G == Σ_l A₂_{jl} C_l`) and `C_0` is the dealer's old public
/// share `expected_old_commitment`.
pub fn verify_contribution(
    new_compiled: &StructurallyValidatedCompiledPolicy,
    contribution: &ReshareContribution,
    expected_old_commitment: &[u8; 32],
) -> bool {
    if contribution.commitments.len() != new_compiled.cols() {
        return false;
    }
    let Some(expected_s) = decompress(expected_old_commitment) else {
        return false;
    };
    if contribution.commitments[0] != expected_s {
        return false;
    }
    for leaf in new_compiled.leaves() {
        let Some(row) = row_of(new_compiled, leaf) else {
            return false;
        };
        let Some(&u) = contribution.sub_shares.get(leaf) else {
            return false;
        };
        let expected: EdwardsPoint = row
            .iter()
            .zip(&contribution.commitments)
            .map(|(a, c)| c * a)
            .sum();
        if G * u != expected {
            return false;
        }
    }
    true
}

/// Combine an old qualified set's resharing contributions into a new group key
/// under the **same** public key.
///
/// The old side is *authenticated*, not asserted: `old_compiled` is the standing
/// configuration's compiled policy, `old` is its generated key, and `old_witness`
/// must [`verify`](StructurallyValidatedCompiledPolicy::verify_witness) against
/// `old_compiled` — so the contributing leaves are proven to form a **qualified
/// coalition under the standing configuration**, not merely a set whose algebra
/// happens to reconstruct the key. Each old public share `S_i` is taken from
/// `old`, never from a caller-supplied map. Contributions must correspond exactly
/// (one per witness leaf, no duplicates, no strangers).
///
/// Every contribution is re-verified (Feldman + `C_0 == S_i`) before use, and the
/// recomputed `Σ λ_i S_i` must equal the old key.
pub fn reshare(
    new_compiled: &StructurallyValidatedCompiledPolicy,
    old_compiled: &StructurallyValidatedCompiledPolicy,
    old: &GroupKey,
    old_witness: &ReconstructionWitness,
    contributions: &[ReshareContribution],
) -> Result<GroupKey, ReshareError> {
    // The witness must prove a qualified coalition of the *standing* structure.
    if !old_compiled.verify_witness(old_witness) {
        return Err(ReshareError::UnqualifiedOldSet);
    }

    // Coefficients keyed by old leaf. verify_witness guarantees unique, ordered
    // leaves and canonical nonzero coefficients.
    let mut lambda: BTreeMap<LeafId, Scalar> = BTreeMap::new();
    for (leaf, coeff) in old_witness.leaves.iter().zip(&old_witness.coefficients) {
        lambda.insert(
            leaf.clone(),
            coeff.as_scalar().ok_or(ReshareError::BadPoint)?,
        );
    }

    // Contributions correspond exactly to the qualified set — a set, not a
    // multiset. Reject a repeated dealer before comparing membership, so a replay
    // cannot stand in for an absent dealer.
    let mut by_dealer: BTreeMap<&LeafId, &ReshareContribution> = BTreeMap::new();
    for c in contributions {
        if by_dealer.insert(&c.dealer, c).is_some() {
            return Err(ReshareError::DuplicateDealer {
                dealer: c.dealer.clone(),
            });
        }
    }
    let dealer_set: BTreeSet<&LeafId> = by_dealer.keys().copied().collect();
    let witness_set: BTreeSet<&LeafId> = lambda.keys().collect();
    if dealer_set != witness_set {
        return Err(ReshareError::ContributorSetMismatch);
    }

    // Verify each contribution against its dealer's authenticated old share `S_i`.
    for c in contributions {
        if c.commitments.len() != new_compiled.cols() {
            return Err(ReshareError::WrongDimension {
                dealer: c.dealer.clone(),
            });
        }
        let s_i = old
            .leaf_commitment(&c.dealer)
            .ok_or(ReshareError::WrongOldCommitment {
                dealer: c.dealer.clone(),
            })?;
        let expected_s = decompress(&s_i).ok_or(ReshareError::BadPoint)?;
        if c.commitments[0] != expected_s {
            return Err(ReshareError::WrongOldCommitment {
                dealer: c.dealer.clone(),
            });
        }
        for leaf in new_compiled.leaves() {
            if !leaf_ok(new_compiled, leaf, c) {
                return Err(ReshareError::InconsistentSubShare {
                    dealer: c.dealer.clone(),
                    leaf: leaf.clone(),
                });
            }
        }
    }

    // Recompute Y = Σ λ_i S_i and demand it equals the old key.
    let old_public_key = old.public_key();
    let mut recomputed = EdwardsPoint::identity();
    for c in contributions {
        recomputed += c.commitments[0] * lambda[&c.dealer];
    }
    let old_y = decompress(&old_public_key).ok_or(ReshareError::BadPoint)?;
    if recomputed != old_y {
        return Err(ReshareError::SameKeyViolated);
    }

    // New shares t_j = Σ_i λ_i u_j^(i), and their commitments T_j = t_j·G.
    let mut shares = BTreeMap::new();
    let mut leaf_commitments = BTreeMap::new();
    for leaf in new_compiled.leaves() {
        let mut t = Scalar::ZERO;
        for c in contributions {
            t += lambda[&c.dealer] * c.sub_shares[leaf];
        }
        shares.insert(leaf.clone(), t);
        leaf_commitments.insert(leaf.clone(), (G * t).compress().to_bytes());
    }

    GroupKey::from_verified_parts(old_public_key, shares, leaf_commitments)
        .ok_or(ReshareError::BadPoint)
}

fn leaf_ok(
    new_compiled: &StructurallyValidatedCompiledPolicy,
    leaf: &LeafId,
    c: &ReshareContribution,
) -> bool {
    let Some(row) = row_of(new_compiled, leaf) else {
        return false;
    };
    let Some(&u) = c.sub_shares.get(leaf) else {
        return false;
    };
    let expected: EdwardsPoint = row.iter().zip(&c.commitments).map(|(a, cm)| cm * a).sum();
    G * u == expected
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
    fn dkg(c: &StructurallyValidatedCompiledPolicy, leaves: &[LeafId]) -> GroupKey {
        let contribs: Vec<_> = leaves.iter().map(|l| contribute(c, l.clone())).collect();
        aggregate(c, &contribs).expect("aggregate")
    }
    /// Sign `msg` with a qualified set of `key_material` under `compiled`.
    fn sign_with<K: KeyShares>(
        c: &StructurallyValidatedCompiledPolicy,
        key_material: &K,
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
        let sig = sign_qualified(&witness, key_material, &nonces, &commitments, msg).expect("sign");
        verify(&key_material.public_key(), msg, &sig)
    }
    /// The old qualified set's honest contributions.
    fn honest_contributions(
        new_c: &StructurallyValidatedCompiledPolicy,
        old: &GroupKey,
        set: &[LeafId],
    ) -> Vec<ReshareContribution> {
        set.iter()
            .map(|l| contribution(new_c, l.clone(), old.share(l).unwrap()))
            .collect()
    }

    #[test]
    fn resharing_preserves_the_key_and_the_new_policy_signs() {
        // Old: 2-of-3. New: a wholly different 2-of-3 committee.
        let (old_c, old_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&old_c, &old_leaves);
        let old_set = vec![old_leaves[0].clone(), old_leaves[2].clone()];
        let old_witness = old_c.reconstruct(&old_set).unwrap();

        let (new_c, new_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(4), key(5), key(6)],
        });

        let contribs = honest_contributions(&new_c, &old, &old_set);
        // Each new leaf accepts every contribution.
        for c in &contribs {
            let s_i = old.leaf_commitment(&c.dealer).unwrap();
            assert!(verify_contribution(&new_c, c, &s_i));
        }
        let new_key = reshare(&new_c, &old_c, &old, &old_witness, &contribs).expect("reshare");

        // Same public key.
        assert_eq!(new_key.public_key(), old.public_key(), "key preserved");
        // The NEW committee signs under the SAME key.
        assert!(sign_with(
            &new_c,
            &new_key,
            &[new_leaves[0].clone(), new_leaves[1].clone()],
            b"post-reshare",
        ));
    }

    #[test]
    fn an_old_coalition_can_still_sign_after_resharing() {
        // The non-revocation property, in code: reshare, then the OLD set still
        // signs under the unchanged key. Resharing is not a revocation.
        let (old_c, old_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&old_c, &old_leaves);
        let old_set = vec![old_leaves[0].clone(), old_leaves[1].clone()];
        let old_witness = old_c.reconstruct(&old_set).unwrap();

        let (new_c, _new_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(4), key(5), key(6)],
        });
        let contribs = honest_contributions(&new_c, &old, &old_set);
        let _new_key = reshare(&new_c, &old_c, &old, &old_witness, &contribs).expect("reshare");

        // The old holders kept their old shares → they still sign under Y.
        assert!(sign_with(&old_c, &old, &old_set, b"still valid"));
    }

    #[test]
    fn a_dishonest_dealer_substituting_its_subsecret_is_caught() {
        let (old_c, old_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&old_c, &old_leaves);
        let old_set = vec![old_leaves[0].clone(), old_leaves[1].clone()];
        let old_witness = old_c.reconstruct(&old_set).unwrap();
        let (new_c, _) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(4), key(5), key(6)],
        });

        // Dealer old_set[1] reshares a *wrong* sub-secret (not its real share).
        let mut contribs = honest_contributions(&new_c, &old, &old_set);
        contribs[1] = contribution(
            &new_c,
            old_set[1].clone(),
            old.share(&old_set[1]).unwrap() + Scalar::ONE,
        );

        // The verifier rejects it: C_0 ≠ S_i.
        let s_i = old.leaf_commitment(&old_set[1]).unwrap();
        assert!(!verify_contribution(&new_c, &contribs[1], &s_i));
        // And reshare refuses the whole set.
        assert_eq!(
            reshare(&new_c, &old_c, &old, &old_witness, &contribs),
            Err(ReshareError::WrongOldCommitment {
                dealer: old_set[1].clone()
            })
        );
    }

    #[test]
    fn a_tampered_subshare_is_rejected() {
        let (old_c, old_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&old_c, &old_leaves);
        let old_set = vec![old_leaves[0].clone(), old_leaves[1].clone()];
        let old_witness = old_c.reconstruct(&old_set).unwrap();
        let (new_c, new_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(4), key(5), key(6)],
        });
        let mut contribs = honest_contributions(&new_c, &old, &old_set);
        // Corrupt a single dealt sub-share.
        let victim = new_leaves[0].clone();
        *contribs[0].sub_shares.get_mut(&victim).unwrap() += Scalar::ONE;
        assert_eq!(
            reshare(&new_c, &old_c, &old, &old_witness, &contribs),
            Err(ReshareError::InconsistentSubShare {
                dealer: old_set[0].clone(),
                leaf: victim,
            })
        );
    }

    #[test]
    fn contributions_must_match_the_qualified_set() {
        let (old_c, old_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&old_c, &old_leaves);
        let old_set = vec![old_leaves[0].clone(), old_leaves[1].clone()];
        let old_witness = old_c.reconstruct(&old_set).unwrap();
        let (new_c, _) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(4), key(5), key(6)],
        });
        // Only one contribution for a two-member qualified set.
        let contribs = honest_contributions(&new_c, &old, &old_set[0..1]);
        assert_eq!(
            reshare(&new_c, &old_c, &old, &old_witness, &contribs),
            Err(ReshareError::ContributorSetMismatch)
        );
    }

    #[test]
    fn a_witness_from_a_foreign_structure_is_rejected() {
        // A witness that reconstructs *some* key but is not a qualified coalition
        // of the standing configuration must not authorize a reshare.
        let (old_c, old_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&old_c, &old_leaves);
        let old_set = vec![old_leaves[0].clone(), old_leaves[1].clone()];

        // A witness produced against a *different* structure — its commitment does
        // not match old_c, so verify_witness rejects it.
        let (foreign_c, foreign_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(7), key(8), key(9)],
        });
        let foreign_witness = foreign_c
            .reconstruct(&[foreign_leaves[0].clone(), foreign_leaves[1].clone()])
            .unwrap();

        let (new_c, _) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(4), key(5), key(6)],
        });
        let contribs = honest_contributions(&new_c, &old, &old_set);
        assert_eq!(
            reshare(&new_c, &old_c, &old, &foreign_witness, &contribs),
            Err(ReshareError::UnqualifiedOldSet)
        );
    }

    #[test]
    fn a_duplicate_old_dealer_is_rejected() {
        let (old_c, old_leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let old = dkg(&old_c, &old_leaves);
        let old_set = vec![old_leaves[0].clone(), old_leaves[1].clone()];
        let old_witness = old_c.reconstruct(&old_set).unwrap();
        let (new_c, _) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(4), key(5), key(6)],
        });
        // Two contributions from dealer 0 (a replay), and none from dealer 1.
        let mut contribs = honest_contributions(&new_c, &old, &old_set[0..1]);
        contribs.push(contribs[0].clone());
        assert_eq!(
            reshare(&new_c, &old_c, &old, &old_witness, &contribs),
            Err(ReshareError::DuplicateDealer {
                dealer: old_set[0].clone(),
            })
        );
    }
}
