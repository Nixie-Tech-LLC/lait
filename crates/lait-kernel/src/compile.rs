//! C3 — compiling a policy to a linear-secret-sharing access structure (§19).
//!
//! [`crate::expand`] gives a monotone tree over leaves. This module turns that
//! tree into a **monotone span program**: a matrix `A` over the Ed25519 scalar
//! field and a target vector `e1`, such that a set of leaves `S` is *qualified*
//! (authorized by the policy) **iff** `e1` lies in the row-span of `S`'s rows —
//! and only then can a reconstruction witness `λ` with `λ·A_S = e1` be found.
//!
//! The eventual DKG (Phase D) distributes shares `s_i = ⟨A_i, ρ⟩` for a random
//! `ρ` with secret `ρ_0`; a qualified set recovers the secret as `Σ λ_i s_i =
//! ⟨Σ λ_i A_i, ρ⟩ = ⟨e1, ρ⟩ = ρ_0`. So getting this matrix right *is* getting the
//! access control right. An unqualified set has no valid `λ`, so it can produce
//! no reconstruction — which is the whole security property.
//!
//! # Construction
//!
//! The standard threshold-formula → MSP construction. Column 0 is the secret.
//! Each `Threshold{k, …}` gate introduces `k-1` fresh columns and hands child `j`
//! a Vandermonde row `[…parent…, j¹, j², …, j^{k-1}]` — a Shamir polynomial of
//! degree `k-1` evaluated at `j`. Recursion composes the gates. The dimension is
//! `1 + Σ (k_gate − 1)`; the rows are the leaves.
//!
//! # The review boundary
//!
//! This is deterministic engineering, but its correctness *is* the access
//! control, so it is validated the strongest way available: `compile` is checked
//! against the boolean policy over **every** leaf subset — the MSP admits a
//! witness for a subset iff the monotone formula does. That is a direct,
//! exhaustive test of the security property for small policies. It is not a
//! substitute for the external cryptographic review the Phase D contract (§22)
//! requires before this feeds a live signing protocol.

use serde::{Deserialize, Serialize};

use curve25519_dalek::scalar::Scalar;

use crate::authority::LeafId;
use crate::expand::ExpandedPolicy;
use crate::policy::PolicyId;

const COMMITMENT_DOMAIN: &[u8] = b"lait/space/1/policy/1/access-structure";

/// Compiler version. A change in the construction bumps it, so an
/// [`AccessStructureCommitment`] from one version never collides with another.
pub const COMPILER_VERSION: u16 = 1;

/// A serialized field element (canonical 32-byte little-endian scalar). Stored
/// rather than a live `Scalar` so the matrix serializes and commits cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fe([u8; 32]);

impl Fe {
    fn from_scalar(s: &Scalar) -> Self {
        Fe(s.to_bytes())
    }
    fn to_scalar(self) -> Scalar {
        // Field elements we produce are always canonical.
        Scalar::from_canonical_bytes(self.0).expect("canonical field element")
    }
}

/// The access matrix: one row per leaf (leaf order matches [`CompiledPolicy::leaves`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessMatrix {
    pub rows: Vec<Vec<Fe>>,
    pub cols: usize,
}

/// The compiled access structure for a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub version: u16,
    pub policy: PolicyId,
    /// Leaves in row order.
    pub leaves: Vec<LeafId>,
    pub matrix: AccessMatrix,
    /// The target vector `e1 = (1, 0, …, 0)`.
    pub target: Vec<Fe>,
}

/// The content-address of a compiled access structure — the second of the three
/// identities (§17): the exact compiler output, distinct from the human
/// [`PolicyId`] and from the deployed `AuthorityConfigurationId`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AccessStructureCommitment([u8; 32]);

impl AccessStructureCommitment {
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }
}

/// The coefficients a qualified set applies to reconstruct the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructionWitness {
    pub policy: PolicyId,
    /// The leaves used (a qualified subset), in canonical order.
    pub leaves: Vec<LeafId>,
    /// `coefficients[i]` multiplies `leaves[i]`'s share; parallel arrays.
    pub coefficients: Vec<Fe>,
}

impl CompiledPolicy {
    /// The content-address, over the whole committed structure (§19): matrix,
    /// target, leaf order, policy id and compiler version.
    pub fn commitment(&self) -> AccessStructureCommitment {
        let mut h = blake3::Hasher::new();
        h.update(COMMITMENT_DOMAIN);
        h.update(&self.version.to_le_bytes());
        h.update(&postcard::to_stdvec(self).expect("encode compiled policy"));
        AccessStructureCommitment(*h.finalize().as_bytes())
    }

    /// The row index of a leaf, if present.
    fn index_of(&self, leaf: &LeafId) -> Option<usize> {
        self.leaves.iter().position(|l| l == leaf)
    }

    /// Reconstruction coefficients for `subset` — `Some` iff the subset is
    /// qualified. This is the qualification oracle: an unqualified subset has no
    /// `λ` with `λ·A_subset = e1`, so this returns `None`.
    pub fn reconstruct(&self, subset: &[LeafId]) -> Option<ReconstructionWitness> {
        // Deduplicate and canonically order the subset.
        let mut idxs: Vec<usize> = subset.iter().filter_map(|l| self.index_of(l)).collect();
        idxs.sort_unstable();
        idxs.dedup();
        let rows: Vec<Vec<Scalar>> = idxs
            .iter()
            .map(|&i| self.matrix.rows[i].iter().map(|f| f.to_scalar()).collect())
            .collect();
        let target: Vec<Scalar> = self.target.iter().map(|f| f.to_scalar()).collect();
        let lambda = solve_row_combination(&rows, &target)?;
        // Keep only leaves with a nonzero coefficient — the minimal used set.
        let mut leaves = Vec::new();
        let mut coefficients = Vec::new();
        for (pos, &i) in idxs.iter().enumerate() {
            if lambda[pos] != Scalar::ZERO {
                leaves.push(self.leaves[i].clone());
                coefficients.push(Fe::from_scalar(&lambda[pos]));
            }
        }
        Some(ReconstructionWitness {
            policy: self.policy,
            leaves,
            coefficients,
        })
    }

    /// Verify a witness: its leaves are ours, and `Σ coeff_i · A_{leaf_i} = e1`.
    ///
    /// Coordinator-provided coefficients are never trusted without this (§19): a
    /// witness over an unqualified set simply cannot satisfy the equation.
    pub fn verify_witness(&self, w: &ReconstructionWitness) -> bool {
        if w.policy != self.policy || w.leaves.len() != w.coefficients.len() {
            return false;
        }
        let mut acc = vec![Scalar::ZERO; self.matrix.cols];
        for (leaf, coeff) in w.leaves.iter().zip(&w.coefficients) {
            let Some(i) = self.index_of(leaf) else {
                return false;
            };
            let c = coeff.to_scalar();
            for (a, cell) in acc.iter_mut().zip(&self.matrix.rows[i]) {
                *a += c * cell.to_scalar();
            }
        }
        let target: Vec<Scalar> = self.target.iter().map(|f| f.to_scalar()).collect();
        acc == target
    }

    /// Choose a qualified subset from the leaves that are actually available and
    /// return its witness, or `None` if the available set is not qualified.
    ///
    /// Deterministic and availability-aware (§19): signing begins with whichever
    /// authenticated leaves posted commitments, and the selection is reproduced
    /// and re-verified by every signer, never trusted from the coordinator.
    pub fn select_signing_plan(&self, available: &[LeafId]) -> Option<ReconstructionWitness> {
        self.reconstruct(available)
    }
}

/// Compile an expanded policy into its access structure.
pub fn compile(policy: &ExpandedPolicy, policy_id: PolicyId) -> CompiledPolicy {
    let mut rows: Vec<(LeafId, Vec<Scalar>)> = Vec::new();
    let mut cols = 1usize; // column 0 is the secret
    build(policy, vec![Scalar::ONE], &mut cols, &mut rows);

    // Pad every row to the final width; a leaf's row is zero in columns owned by
    // gates off its root-path.
    let matrix_rows: Vec<Vec<Fe>> = rows
        .iter()
        .map(|(_, r)| {
            let mut r = r.clone();
            r.resize(cols, Scalar::ZERO);
            r.iter().map(Fe::from_scalar).collect()
        })
        .collect();
    let leaves: Vec<LeafId> = rows.into_iter().map(|(l, _)| l).collect();

    let mut target = vec![Fe::from_scalar(&Scalar::ZERO); cols];
    target[0] = Fe::from_scalar(&Scalar::ONE);

    CompiledPolicy {
        version: COMPILER_VERSION,
        policy: policy_id,
        leaves,
        matrix: AccessMatrix {
            rows: matrix_rows,
            cols,
        },
        target,
    }
}

fn build(
    node: &ExpandedPolicy,
    mut row: Vec<Scalar>,
    cols: &mut usize,
    out: &mut Vec<(LeafId, Vec<Scalar>)>,
) {
    match node {
        ExpandedPolicy::Leaf(id) => out.push((id.clone(), row)),
        ExpandedPolicy::Threshold { k, members } => {
            let new = (*k as usize).saturating_sub(1);
            let base = *cols;
            *cols += new;
            // The gate's own vector is zero in every column past its ancestors'.
            row.resize(base, Scalar::ZERO);
            for (j, child) in members.iter().enumerate() {
                let jj = Scalar::from(j as u64 + 1);
                let mut child_row = row.clone();
                let mut power = jj;
                for _ in 0..new {
                    child_row.push(power);
                    power *= jj;
                }
                build(child, child_row, cols, out);
            }
        }
    }
}

/// Solve `λ · rows = target` for `λ` (one coefficient per row), or `None` if no
/// solution exists (the rows do not span the target). Gaussian elimination over
/// the field: build the `cols × m` system `rowsᵀ λ = target`, reduce, check
/// consistency, and back-substitute with free variables set to zero.
fn solve_row_combination(rows: &[Vec<Scalar>], target: &[Scalar]) -> Option<Vec<Scalar>> {
    let m = rows.len();
    let d = target.len();
    if m == 0 {
        // Only the all-zero target is spanned by nothing.
        return target.iter().all(|t| *t == Scalar::ZERO).then(Vec::new);
    }
    // Equation c (for each column c): Σ_i λ_i rows[i][c] = target[c].
    // Augmented matrix: d rows, m unknown columns + 1 rhs.
    let mut aug: Vec<Vec<Scalar>> = (0..d)
        .map(|c| {
            let mut eq: Vec<Scalar> = (0..m).map(|i| rows[i][c]).collect();
            eq.push(target[c]);
            eq
        })
        .collect();

    // Forward elimination to reduced row echelon; record pivot column per row.
    let mut pivot_col = vec![usize::MAX; d];
    let mut r = 0usize;
    for col in 0..m {
        // Find a pivot at or below row r in this column.
        let Some(p) = (r..d).find(|&i| aug[i][col] != Scalar::ZERO) else {
            continue;
        };
        aug.swap(r, p);
        // Normalize the pivot row.
        let inv = aug[r][col].invert();
        for x in aug[r].iter_mut() {
            *x *= inv;
        }
        // Eliminate this column from every other row.
        let pivot = aug[r].clone();
        for (i, eq) in aug.iter_mut().enumerate() {
            if i != r && eq[col] != Scalar::ZERO {
                let factor = eq[col];
                for (cell, pv) in eq.iter_mut().zip(&pivot) {
                    *cell -= factor * *pv;
                }
            }
        }
        pivot_col[r] = col;
        r += 1;
        if r == d {
            break;
        }
    }

    // Consistency: a row [0 … 0 | nonzero] means no solution.
    for row in &aug {
        if row[..m].iter().all(|x| *x == Scalar::ZERO) && row[m] != Scalar::ZERO {
            return None;
        }
    }

    // Back-substitute: pivot variables from their rows, free variables = 0.
    let mut lambda = vec![Scalar::ZERO; m];
    for (i, &pc) in pivot_col.iter().enumerate() {
        if pc != usize::MAX {
            lambda[pc] = aug[i][m];
        }
    }
    Some(lambda)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::PrincipalId;
    use crate::expand::{expand, Expansion, PrincipalCustody, PrincipalDescriptor};
    use crate::policy::OwnershipPolicy;
    use std::collections::BTreeSet;

    fn dev(n: u8) -> crate::ids::UserId {
        crate::crypto::user_from_seed(&[n; 32])
    }
    fn prin(n: u8) -> PrincipalId {
        PrincipalId::of_device(&dev(n))
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

    fn compile_policy(o: OwnershipPolicy) -> (CompiledPolicy, Expansion) {
        let canon = o.canonicalize().unwrap();
        let pid = canon.id();
        let exp = expand(&canon, &resolver()).unwrap();
        (compile(&exp.policy, pid), exp)
    }

    /// Boolean evaluation of the expanded policy over a present-leaf set.
    fn satisfied(p: &ExpandedPolicy, present: &BTreeSet<LeafId>) -> bool {
        match p {
            ExpandedPolicy::Leaf(l) => present.contains(l),
            ExpandedPolicy::Threshold { k, members } => {
                members.iter().filter(|m| satisfied(m, present)).count() >= *k as usize
            }
        }
    }

    /// THE test: for every subset of leaves, the MSP admits a reconstruction
    /// witness iff the boolean policy is satisfied. This validates the access
    /// structure directly against the policy semantics — an unqualified set can
    /// never reconstruct, a qualified set always can.
    fn exhaustive_check(o: OwnershipPolicy) {
        let (compiled, exp) = compile_policy(o);
        let leaves: Vec<LeafId> = exp.policy.leaves().into_iter().cloned().collect();
        let n = leaves.len();
        assert!(n <= 12, "exhaustive check is for small policies");
        for mask in 0u32..(1u32 << n) {
            let subset: Vec<LeafId> = (0..n)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| leaves[i].clone())
                .collect();
            let present: BTreeSet<LeafId> = subset.iter().cloned().collect();
            let boolean = satisfied(&exp.policy, &present);
            let witness = compiled.reconstruct(&subset);
            assert_eq!(
                witness.is_some(),
                boolean,
                "subset mask {mask:b}: MSP-qualified={} but boolean={boolean}",
                witness.is_some()
            );
            // A produced witness must actually verify.
            if let Some(w) = witness {
                assert!(compiled.verify_witness(&w), "witness must verify");
            }
        }
    }

    #[test]
    fn single_key_reconstructs_alone() {
        exhaustive_check(key(1));
    }

    #[test]
    fn allof_needs_everyone() {
        exhaustive_check(OwnershipPolicy::AllOf(vec![key(1), key(2), key(3)]));
    }

    #[test]
    fn anyof_needs_one() {
        exhaustive_check(OwnershipPolicy::AnyOf(vec![key(1), key(2), key(3)]));
    }

    #[test]
    fn plain_threshold() {
        exhaustive_check(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
    }

    #[test]
    fn nested_compartments() {
        // "2 of {A}, and 1 of {B}" — two from team A (of three) AND one from B.
        exhaustive_check(OwnershipPolicy::AllOf(vec![
            OwnershipPolicy::Threshold {
                k: 2,
                members: vec![key(1), key(2), key(3)],
            },
            OwnershipPolicy::AnyOf(vec![key(4), key(5)]),
        ]));
    }

    #[test]
    fn a_larger_number_from_one_team_cannot_replace_the_absence_of_another() {
        // The federated-governance property the doc calls out: extra weight in
        // team A must not compensate for the total absence of team B.
        let policy = OwnershipPolicy::AllOf(vec![
            OwnershipPolicy::Threshold {
                k: 1,
                members: vec![key(1), key(2), key(3)],
            },
            OwnershipPolicy::Key(prin(4)), // team B, a single required principal
        ]);
        let (compiled, exp) = compile_policy(policy);
        // Team B is principal 4; find its leaf by provenance, not position.
        let team_b: BTreeSet<LeafId> = exp
            .leaves
            .iter()
            .filter(|d| d.principal == prin(4))
            .map(|d| d.leaf.clone())
            .collect();
        let team_a: Vec<LeafId> = exp
            .leaves
            .iter()
            .filter(|d| !team_b.contains(&d.leaf))
            .map(|d| d.leaf.clone())
            .collect();
        assert_eq!(team_a.len(), 3, "all of team A present");
        assert!(
            compiled.reconstruct(&team_a).is_none(),
            "all of team A cannot substitute for the absent team B"
        );
    }

    #[test]
    fn a_forged_witness_over_an_unqualified_set_fails_verification() {
        let (compiled, exp) = compile_policy(OwnershipPolicy::AllOf(vec![key(1), key(2)]));
        let leaves: Vec<LeafId> = exp.policy.leaves().into_iter().cloned().collect();
        // Fabricate a witness naming only leaf 0 with coefficient 1 — an
        // unqualified set for an AND.
        let forged = ReconstructionWitness {
            policy: compiled.policy,
            leaves: vec![leaves[0].clone()],
            coefficients: vec![Fe::from_scalar(&Scalar::ONE)],
        };
        assert!(
            !compiled.verify_witness(&forged),
            "a witness over an unqualified set cannot verify"
        );
    }

    #[test]
    fn compilation_is_deterministic_and_committed() {
        let (a, _) = compile_policy(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let (b, _) = compile_policy(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(3), key(1), key(2)],
        });
        assert_eq!(a, b, "member order does not change the compiled structure");
        assert_eq!(a.commitment(), b.commitment());
    }

    #[test]
    fn distinct_structures_have_distinct_commitments() {
        let (a, _) = compile_policy(OwnershipPolicy::Threshold {
            k: 1,
            members: vec![key(1), key(2)],
        });
        let (b, _) = compile_policy(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2)],
        });
        assert_ne!(a.commitment(), b.commitment());
    }
}
