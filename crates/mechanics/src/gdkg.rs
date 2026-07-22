//! Dealer-free general-access key generation.
//!
//! [`crate::gaccess`] signs from shares a *trusted dealer* handed out. This module removes the
//! dealer: the key is generated so that no single party ever holds the secret
//! `x`, yet the resulting shares have the same MSP form the signer consumes.
//!
//! Construction — Feldman-VSS-per-contributor, aggregated over the span program.
//! Each contributor `p` samples its own distribution vector `ρ^(p) ∈ F^d`
//! (`d = cols`), publishes Feldman commitments `C^(p)_j = ρ^(p)_j · G`, and deals
//! leaf `i` the sub-share `s_i^(p) = ⟨A_i, ρ^(p)⟩`. Leaf `i` accepts dealer `p`
//! only if the sub-share matches the commitments:
//!
//! ```text
//! s_i^(p)·G  ?=  Σ_j A_{ij} · C^(p)_j
//! ```
//!
//! The group aggregates over accepted contributors:
//!
//! ```text
//! x   = Σ_p ρ^(p)_0            (nobody computes this — it is the secret)
//! Y   = Σ_p C^(p)_0 = x·G      (public key)
//! s_i = Σ_p s_i^(p)            (leaf i's aggregate share; only i learns it)
//! S_i = s_i·G                  (public per-leaf commitment)
//! ```
//!
//! Because each contributor's sub-shares are MSP-consistent with `ρ^(p)`, the
//! sum is MSP-consistent with `ρ = Σ_p ρ^(p)`: a qualified set's reconstruction witness
//! reconstructs `Σ λ_i s_i = x`, so the [`crate::gaccess`] signer produces a
//! signature under `Y`. The `dkg_output_signs_under_gaccess` test closes that
//! loop end to end.
//!
//! # Security status
//!
//! Everything the [`crate::gaccess`] header says applies here, plus DKG-specific
//! gaps this functional prototype does **not** address:
//!
//! - **Public-key biasing.** This is a Pedersen/Feldman-style DKG. A rushing
//!   adversary who chooses its contribution after seeing others' commitments can
//!   bias the distribution of `Y` (Gennaro–Jarecki–Krawczyk–Rabin). The hardened
//!   construction commits (hiding) before revealing; that round, and the
//!   complaint/disqualification protocol that makes aborts identifiable, are the
//!   production protocol must include — not implemented here.
//! - **Transport & authentication.** Sub-shares here are passed in-process. The
//!   private per-leaf channel, its authentication, and encrypted-share dealing
//!   are out of scope for the algebra.
//! - **Qualified-contributor set.** This aggregates whatever honest
//!   contributions it is given; agreeing on the accepted-contributor set under
//!   partial failure is outside this algebraic prototype.
//!
//! This module is not wired into the space authority path. It validates that
//! dealer-free generation yields shares the general-access signer accepts; that
//! functional result does not establish active-adversary security.

use std::collections::{BTreeMap, BTreeSet};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::authority::LeafId;
use crate::compile::StructurallyValidatedCompiledPolicy;
use crate::gaccess::KeyShares;

/// Errors aggregating a DKG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkgError {
    /// No contributions to aggregate.
    NoContributions,
    /// A contribution's commitment vector has the wrong dimension.
    WrongDimension { dealer: LeafId },
    /// A contribution's shares do not cover exactly the compiled leaf set.
    ShareSetMismatch { dealer: LeafId },
    /// A dealt sub-share failed its Feldman check against the commitments.
    InconsistentShare { dealer: LeafId, leaf: LeafId },
    /// Two contributions claim the same dealer. Contributor identity is a set;
    /// a repeat would change the aggregate without adding a distinct dealer.
    DuplicateDealer { dealer: LeafId },
    /// The aggregate public key is the identity — the contributions' secrets
    /// cancelled to zero. No signature verifies under it; refuse to mint it.
    DegenerateKey,
}

/// One contributor's dealing: Feldman commitments to its `ρ^(p)`, and the
/// sub-share it deals to every leaf. The commitments are broadcast; each
/// `shares[i]` is, in a real deployment, sent privately to leaf `i`.
#[derive(Debug, Clone)]
pub struct Contribution {
    dealer: LeafId,
    commitments: Vec<EdwardsPoint>,
    shares: BTreeMap<LeafId, Scalar>,
}

impl Contribution {
    /// The dealer this contribution is from.
    pub fn dealer(&self) -> &LeafId {
        &self.dealer
    }
}

fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    getrandom::fill(&mut wide).expect("getrandom");
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The matrix row for `leaf`, as scalars. `None` if the leaf is not in the
/// compiled policy.
fn row_of(compiled: &StructurallyValidatedCompiledPolicy, leaf: &LeafId) -> Option<Vec<Scalar>> {
    let idx = compiled.leaves().iter().position(|l| l == leaf)?;
    Some(
        compiled.inner().matrix.rows[idx]
            .iter()
            .map(|c| c.as_scalar().expect("validated field element"))
            .collect(),
    )
}

/// Produce `dealer`'s contribution to the key: sample `ρ^(p)`, commit to it, and
/// deal MSP sub-shares to every leaf. `dealer` need not itself be a leaf, but is
/// recorded so aggregation can attribute a bad dealing.
pub fn contribute(compiled: &StructurallyValidatedCompiledPolicy, dealer: LeafId) -> Contribution {
    let cols = compiled.cols();
    let rho: Vec<Scalar> = (0..cols).map(|_| random_scalar()).collect();
    let commitments: Vec<EdwardsPoint> = rho.iter().map(|r| G * r).collect();
    let mut shares = BTreeMap::new();
    for leaf in compiled.leaves() {
        let row = row_of(compiled, leaf).expect("leaf is in the compiled policy");
        // s_i = ⟨A_i, ρ⟩
        let s: Scalar = row.iter().zip(&rho).map(|(a, r)| a * r).sum();
        shares.insert(leaf.clone(), s);
    }
    Contribution {
        dealer,
        commitments,
        shares,
    }
}

/// Feldman check of one dealt sub-share against a contribution's commitments:
/// `s_i·G == Σ_j A_{ij} C_j`. This is what a receiving leaf runs before it
/// accepts a dealer.
pub fn verify_share(
    compiled: &StructurallyValidatedCompiledPolicy,
    leaf: &LeafId,
    contribution: &Contribution,
) -> bool {
    let Some(row) = row_of(compiled, leaf) else {
        return false;
    };
    if contribution.commitments.len() != row.len() {
        return false;
    }
    let Some(&share) = contribution.shares.get(leaf) else {
        return false;
    };
    // Σ_j A_{ij} C_j
    let expected: EdwardsPoint = row
        .iter()
        .zip(&contribution.commitments)
        .map(|(a, c)| c * a)
        .sum();
    G * share == expected
}

/// The generated key: the public key, and per-leaf aggregate shares plus their
/// public commitments. In a real run each leaf learns only its own scalar share;
/// the map here holds them all so a test can drive the whole group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupKey {
    public: EdwardsPoint,
    shares: BTreeMap<LeafId, Scalar>,
    leaf_commitments: BTreeMap<LeafId, EdwardsPoint>,
}

impl GroupKey {
    /// The public per-leaf share commitment `S_i = s_i·G`.
    pub fn leaf_commitment(&self, leaf: &LeafId) -> Option<[u8; 32]> {
        self.leaf_commitments
            .get(leaf)
            .map(|p| p.compress().to_bytes())
    }

    /// Assemble a group key from parts a *different* protocol has already
    /// verified — same-key resharing and refresh/repair each establish
    /// share/commitment consistency their own way, then hand the result here.
    /// The DKG path is [`aggregate`], not this. Rejects any non-canonical or
    /// non-prime-order point encoding, a public key that is the identity (a
    /// degenerate zero-secret key), and (as a last-line invariant) any share
    /// whose commitment is not `s·G`.
    pub fn from_verified_parts(
        public: [u8; 32],
        shares: BTreeMap<LeafId, Scalar>,
        leaf_commitments: BTreeMap<LeafId, [u8; 32]>,
    ) -> Option<Self> {
        // The public key crosses a trust boundary: non-identity, prime-order.
        let public = crate::gaccess::decompress_prime_order(&public)?;
        let mut points = BTreeMap::new();
        for (leaf, s) in &shares {
            // Subgroup membership on each commitment; `G*s == commit` then pins it.
            let commit = decompress(leaf_commitments.get(leaf)?)?;
            if !commit.is_torsion_free() || G * s != commit {
                return None;
            }
            points.insert(leaf.clone(), commit);
        }
        if points.len() != leaf_commitments.len() {
            return None;
        }
        Some(GroupKey {
            public,
            shares,
            leaf_commitments: points,
        })
    }
}

fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes).decompress()
}

impl KeyShares for GroupKey {
    fn public_key(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }
    fn share(&self, leaf: &LeafId) -> Option<Scalar> {
        self.shares.get(leaf).copied()
    }
}

/// Aggregate accepted contributions into the group key, re-running every
/// Feldman check so a caller cannot aggregate an inconsistent dealing. Rejects
/// dealings of the wrong dimension or leaf set, or with any bad sub-share.
pub fn aggregate(
    compiled: &StructurallyValidatedCompiledPolicy,
    contributions: &[Contribution],
) -> Result<GroupKey, DkgError> {
    if contributions.is_empty() {
        return Err(DkgError::NoContributions);
    }
    let cols = compiled.cols();
    let leaves = compiled.leaves();

    // Contributor identity is a *set*, not a multiset: two contributions from one
    // dealer (e.g. a replayed valid one) would silently change the aggregate key
    // and every share. Reject duplicates before aggregating anything.
    let mut seen: BTreeSet<&LeafId> = BTreeSet::new();
    for c in contributions {
        if !seen.insert(&c.dealer) {
            return Err(DkgError::DuplicateDealer {
                dealer: c.dealer.clone(),
            });
        }
    }

    // Validate every contribution before trusting any of it.
    for c in contributions {
        if c.commitments.len() != cols {
            return Err(DkgError::WrongDimension {
                dealer: c.dealer.clone(),
            });
        }
        if c.shares.len() != leaves.len() || leaves.iter().any(|l| !c.shares.contains_key(l)) {
            return Err(DkgError::ShareSetMismatch {
                dealer: c.dealer.clone(),
            });
        }
        for leaf in leaves {
            if !verify_share(compiled, leaf, c) {
                return Err(DkgError::InconsistentShare {
                    dealer: c.dealer.clone(),
                    leaf: leaf.clone(),
                });
            }
        }
    }

    // Y = Σ_p C^(p)_0
    let public = contributions
        .iter()
        .map(|c| c.commitments[0])
        .fold(EdwardsPoint::identity(), |a, b| a + b);

    // Individually valid contributions can still cancel to Y = identity (a zero
    // group secret) — a rushing final contributor can force it. Signing would refuse
    // to verify under such a key; reject it here rather than mint an unusable one.
    if public == EdwardsPoint::identity() {
        return Err(DkgError::DegenerateKey);
    }

    // s_i = Σ_p s_i^(p), and the aggregate column commitments for S_i.
    let agg_commitments: Vec<EdwardsPoint> = (0..cols)
        .map(|j| {
            contributions
                .iter()
                .map(|c| c.commitments[j])
                .fold(EdwardsPoint::identity(), |a, b| a + b)
        })
        .collect();

    let mut shares = BTreeMap::new();
    let mut leaf_commitments = BTreeMap::new();
    for leaf in leaves {
        let s: Scalar = contributions.iter().map(|c| c.shares[leaf]).sum();
        // S_i from aggregate commitments; must equal s_i·G.
        let row = row_of(compiled, leaf).expect("leaf in policy");
        let s_commit: EdwardsPoint = row.iter().zip(&agg_commitments).map(|(a, c)| c * a).sum();
        debug_assert_eq!(G * s, s_commit, "aggregate share/commitment consistency");
        shares.insert(leaf.clone(), s);
        leaf_commitments.insert(leaf.clone(), s_commit);
    }

    Ok(GroupKey {
        public,
        shares,
        leaf_commitments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::PrincipalId;
    use crate::compile::compile;
    use crate::expand::{expand, PrincipalCustody, PrincipalDescriptor};
    use crate::gaccess::{commit, sign_qualified, verify, Nonce};
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

    /// Every leaf acts as a contributor; a real DKG picks a contributor set, but
    /// leaves-as-contributors is the simplest complete instance.
    fn run_dkg(c: &StructurallyValidatedCompiledPolicy, leaves: &[LeafId]) -> Vec<Contribution> {
        leaves.iter().map(|l| contribute(c, l.clone())).collect()
    }

    #[test]
    fn honest_contributions_all_verify_and_aggregate() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let contribs = run_dkg(&c, &leaves);
        // Each leaf accepts every dealer.
        for leaf in &leaves {
            for contrib in &contribs {
                assert!(verify_share(&c, leaf, contrib), "leaf must accept dealer");
            }
        }
        let group = aggregate(&c, &contribs).expect("aggregate honest DKG");
        // Public key is the sum of each dealer's C_0.
        let expected_y = contribs
            .iter()
            .map(|c| c.commitments[0])
            .fold(EdwardsPoint::identity(), |a, b| a + b);
        assert_eq!(group.public_key(), expected_y.compress().to_bytes());
        // Every leaf has a share, and its public commitment is s_i·G.
        for leaf in &leaves {
            let s = group.share(leaf).unwrap();
            assert_eq!(
                group.leaf_commitment(leaf).unwrap(),
                (G * s).compress().to_bytes()
            );
        }
    }

    #[test]
    fn dkg_output_signs_under_gaccess() {
        // Verify that dealer-free shares produce a valid general-access signature.
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let contribs = run_dkg(&c, &leaves);
        let group = aggregate(&c, &contribs).expect("aggregate");

        // A qualified pair signs and the signature verifies under the DKG key.
        let signers = vec![leaves[0].clone(), leaves[2].clone()];
        let witness = c.reconstruct(&signers).expect("qualified");
        let mut nonces: BTreeMap<LeafId, Nonce> = BTreeMap::new();
        let mut commitments = Vec::new();
        for leaf in &witness.leaves {
            let (n, com) = commit();
            nonces.insert(leaf.clone(), n);
            commitments.push((leaf.clone(), com));
        }
        let msg = b"install candidate authority";
        let sig = sign_qualified(&witness, &group, &nonces, &commitments, msg).expect("sign");
        assert!(
            verify(&group.public_key(), msg, &sig),
            "DKG key signs and verifies"
        );
    }

    #[test]
    fn a_tampered_subshare_is_rejected() {
        let (c, leaves) = compiled(OwnershipPolicy::AnyOf(vec![key(1), key(2), key(3)]));
        let mut contribs = run_dkg(&c, &leaves);
        // Corrupt one dealer's sub-share to the first leaf.
        let victim = leaves[0].clone();
        *contribs[1].shares.get_mut(&victim).unwrap() += Scalar::ONE;
        // The victim leaf detects it, and aggregation refuses the whole set.
        assert!(!verify_share(&c, &victim, &contribs[1]));
        assert_eq!(
            aggregate(&c, &contribs),
            Err(DkgError::InconsistentShare {
                dealer: contribs[1].dealer.clone(),
                leaf: victim,
            })
        );
    }

    #[test]
    fn a_replayed_contribution_is_rejected() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut contribs = run_dkg(&c, &leaves);
        // Replay dealer 0's valid contribution as if it were a second dealer.
        let replay = contribs[0].clone();
        contribs.push(replay);
        assert_eq!(
            aggregate(&c, &contribs),
            Err(DkgError::DuplicateDealer {
                dealer: leaves[0].clone(),
            })
        );
    }

    #[test]
    fn contributions_cancelling_to_an_identity_key_are_rejected() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        // Dealer 0 contributes ρ; dealer 1 contributes −ρ. Each is individually
        // Feldman-valid, but Σ C_0 = C_0 + (−C_0) = identity.
        let a = contribute(&c, leaves[0].clone());
        let negated = Contribution {
            dealer: leaves[1].clone(),
            commitments: a.commitments.iter().map(|p| -p).collect(),
            shares: a.shares.iter().map(|(l, s)| (l.clone(), -s)).collect(),
        };
        // Both pass per-leaf verification.
        for leaf in &leaves {
            assert!(verify_share(&c, leaf, &a));
            assert!(verify_share(&c, leaf, &negated));
        }
        assert_eq!(
            aggregate(&c, &[a, negated]),
            Err(DkgError::DegenerateKey),
            "a zero group key must be refused"
        );
    }

    #[test]
    fn aggregation_is_invariant_under_contribution_order() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let contribs = run_dkg(&c, &leaves);
        let forward = aggregate(&c, &contribs).expect("aggregate");
        let mut reversed = contribs.clone();
        reversed.reverse();
        let backward = aggregate(&c, &reversed).expect("aggregate");
        assert_eq!(forward, backward, "sum aggregation is order-independent");
    }

    #[test]
    fn a_wrong_dimension_contribution_is_rejected() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let mut contribs = run_dkg(&c, &leaves);
        contribs[0].commitments.pop(); // drop a column commitment
        assert_eq!(
            aggregate(&c, &contribs),
            Err(DkgError::WrongDimension {
                dealer: contribs[0].dealer.clone(),
            })
        );
    }

    #[test]
    fn no_contributions_is_an_error() {
        let (c, _) = compiled(OwnershipPolicy::Key(prin(1)));
        assert_eq!(aggregate(&c, &[]), Err(DkgError::NoContributions));
    }
}
