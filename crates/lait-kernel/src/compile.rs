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
//! # The validation boundary
//!
//! [`CompiledPolicy`] is `Deserialize` and therefore **untrusted**: future
//! ceremony/configuration material carries it in over the wire. Reconstruction
//! and witness verification live only on [`ValidatedCompiledPolicy`], which is
//! reachable solely through [`CompiledPolicy::validate`]. Validation rejects
//! non-canonical scalars, dimension mismatches, a target that is not `e1`,
//! duplicate leaves and over-limit structures — so the arithmetic paths never see
//! hostile shapes and cannot panic on them.
//!
//! # The review boundary
//!
//! This is deterministic engineering, but its correctness *is* the access
//! control, so it is validated the strongest way available: `compile` is checked
//! against the boolean policy over **every** leaf subset — the MSP admits a
//! witness for a subset iff the monotone formula does. That is not a substitute
//! for the external cryptographic review the Phase D contract (§22) requires
//! before this feeds a live signing protocol.

use serde::{Deserialize, Serialize};

use curve25519_dalek::scalar::Scalar;

use crate::authority::LeafId;
use crate::expand::{ExpandedPolicy, Expansion};
use crate::policy::PolicyId;

const COMMITMENT_DOMAIN: &[u8] = b"lait/space/1/policy/1/access-structure";

/// Compiler version. A change in the construction bumps it, so an
/// [`AccessStructureCommitment`] from one version never collides with another.
pub const COMPILER_VERSION: u16 = 1;

/// Consensus limits on the compiled artifact cryptography actually consumes.
/// C1/C2 bound the policy and its expansion; these bound the matrix, so a large
/// but in-bounds expansion cannot become a solve/memory exhaustion path.
pub const MAX_MATRIX_ROWS: usize = 512;
pub const MAX_MATRIX_COLS: usize = 512;
pub const MAX_MATRIX_CELLS: usize = MAX_MATRIX_ROWS * MAX_MATRIX_COLS;

/// A serialized field element (canonical 32-byte little-endian scalar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fe([u8; 32]);

impl Fe {
    fn from_scalar(s: &Scalar) -> Self {
        Fe(s.to_bytes())
    }
    /// The scalar this element encodes, or `None` if the bytes are not a
    /// canonical field element. Fallible on purpose — a deserialized matrix is
    /// untrusted, so nothing calls this without validation having first proven
    /// canonicality.
    fn to_scalar(self) -> Option<Scalar> {
        Scalar::from_canonical_bytes(self.0).into_option()
    }
}

/// The access matrix: one row per leaf (leaf order matches [`CompiledPolicy::leaves`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessMatrix {
    pub rows: Vec<Vec<Fe>>,
    pub cols: usize,
}

/// A compiled access structure. **Untrusted** when deserialized — validate before
/// use.
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

/// A [`CompiledPolicy`] that has passed [`CompiledPolicy::validate`]. Only this
/// type exposes reconstruction and witness verification, so those paths are never
/// reached with an unvalidated (possibly hostile) structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCompiledPolicy(CompiledPolicy);

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

/// The coefficients a qualified set applies to reconstruct the secret. Bound to
/// the exact [`AccessStructureCommitment`], not merely the policy id, so a witness
/// cannot be replayed against a different compilation of the same policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructionWitness {
    pub structure: AccessStructureCommitment,
    /// The leaves used, strictly ordered by row index and unique.
    pub leaves: Vec<LeafId>,
    /// `coefficients[i]` multiplies `leaves[i]`'s share; parallel, all nonzero.
    pub coefficients: Vec<Fe>,
}

/// Why a [`CompiledPolicy`] failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    UnsupportedVersion(u16),
    /// A row length, the target length, or the leaf count disagrees with `cols`.
    DimensionMismatch,
    /// A stored element is not a canonical field scalar.
    NoncanonicalScalar,
    /// The target vector is not `e1 = (1, 0, …, 0)`.
    BadTarget,
    /// Two rows name the same leaf.
    DuplicateLeaf,
    /// The matrix exceeds a consensus limit.
    TooLarge,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::UnsupportedVersion(v) => write!(f, "unsupported compiler version {v}"),
            ValidationError::DimensionMismatch => write!(f, "matrix dimensions are inconsistent"),
            ValidationError::NoncanonicalScalar => {
                write!(f, "a matrix entry is not a canonical field element")
            }
            ValidationError::BadTarget => write!(f, "the target vector is not e1"),
            ValidationError::DuplicateLeaf => write!(f, "a leaf appears in two rows"),
            ValidationError::TooLarge => write!(f, "the access matrix exceeds a consensus limit"),
        }
    }
}
impl std::error::Error for ValidationError {}

impl CompiledPolicy {
    /// Check every structural invariant, returning a [`ValidatedCompiledPolicy`]
    /// that alone exposes the arithmetic paths. Consumes `self` so an unvalidated
    /// value cannot linger.
    pub fn validate(self) -> Result<ValidatedCompiledPolicy, ValidationError> {
        if self.version != COMPILER_VERSION {
            return Err(ValidationError::UnsupportedVersion(self.version));
        }
        let cols = self.matrix.cols;
        let rows = self.matrix.rows.len();
        if cols == 0
            || rows != self.leaves.len()
            || self.target.len() != cols
            || self.matrix.rows.iter().any(|r| r.len() != cols)
        {
            return Err(ValidationError::DimensionMismatch);
        }
        if rows > MAX_MATRIX_ROWS
            || cols > MAX_MATRIX_COLS
            || rows.saturating_mul(cols) > MAX_MATRIX_CELLS
        {
            return Err(ValidationError::TooLarge);
        }
        // Every stored element is a canonical scalar.
        let canonical = self
            .matrix
            .rows
            .iter()
            .flatten()
            .chain(self.target.iter())
            .all(|f| f.to_scalar().is_some());
        if !canonical {
            return Err(ValidationError::NoncanonicalScalar);
        }
        // Target is exactly e1.
        let one = Fe::from_scalar(&Scalar::ONE);
        let zero = Fe::from_scalar(&Scalar::ZERO);
        if self.target[0] != one || self.target[1..].iter().any(|f| *f != zero) {
            return Err(ValidationError::BadTarget);
        }
        // Leaves are unique.
        let distinct: std::collections::BTreeSet<&LeafId> = self.leaves.iter().collect();
        if distinct.len() != self.leaves.len() {
            return Err(ValidationError::DuplicateLeaf);
        }
        Ok(ValidatedCompiledPolicy(self))
    }
}

impl ValidatedCompiledPolicy {
    pub fn inner(&self) -> &CompiledPolicy {
        &self.0
    }
    pub fn policy(&self) -> PolicyId {
        self.0.policy
    }
    pub fn leaves(&self) -> &[LeafId] {
        &self.0.leaves
    }

    /// The content-address, over the whole committed structure (§19).
    pub fn commitment(&self) -> AccessStructureCommitment {
        let mut h = blake3::Hasher::new();
        h.update(COMMITMENT_DOMAIN);
        h.update(&self.0.version.to_le_bytes());
        h.update(&postcard::to_stdvec(&self.0).expect("encode compiled policy"));
        AccessStructureCommitment(*h.finalize().as_bytes())
    }

    fn index_of(&self, leaf: &LeafId) -> Option<usize> {
        self.0.leaves.iter().position(|l| l == leaf)
    }

    fn scalar_rows(&self, idxs: &[usize]) -> Vec<Vec<Scalar>> {
        idxs.iter()
            .map(|&i| {
                self.0.matrix.rows[i]
                    .iter()
                    // Validation proved canonicality.
                    .map(|f| f.to_scalar().expect("validated scalar"))
                    .collect()
            })
            .collect()
    }

    fn target_scalars(&self) -> Vec<Scalar> {
        self.0
            .target
            .iter()
            .map(|f| f.to_scalar().expect("validated scalar"))
            .collect()
    }

    /// Reconstruction coefficients for `subset` — `Some` iff the subset is
    /// qualified. The qualification oracle: an unqualified subset has no `λ` with
    /// `λ·A_subset = e1`.
    pub fn reconstruct(&self, subset: &[LeafId]) -> Option<ReconstructionWitness> {
        let mut idxs: Vec<usize> = subset.iter().filter_map(|l| self.index_of(l)).collect();
        idxs.sort_unstable();
        idxs.dedup();
        let rows = self.scalar_rows(&idxs);
        let target = self.target_scalars();
        let lambda = solve_row_combination(&rows, &target)?;
        // Keep only nonzero coefficients — the minimal used set, in row order.
        let mut leaves = Vec::new();
        let mut coefficients = Vec::new();
        for (pos, &i) in idxs.iter().enumerate() {
            if lambda[pos] != Scalar::ZERO {
                leaves.push(self.0.leaves[i].clone());
                coefficients.push(Fe::from_scalar(&lambda[pos]));
            }
        }
        Some(ReconstructionWitness {
            structure: self.commitment(),
            leaves,
            coefficients,
        })
    }

    /// Verify a witness against this structure. Requires, beyond the linear
    /// equation, a single canonical interpretation (§19 finding 5): the witness
    /// binds this exact commitment, its leaves are ours, strictly ordered by row
    /// index and unique, and every coefficient is a canonical nonzero scalar.
    /// Without those, a repeated leaf with split coefficients could satisfy the
    /// algebra while being ambiguous input to a signing plan.
    pub fn verify_witness(&self, w: &ReconstructionWitness) -> bool {
        if w.structure != self.commitment() || w.leaves.len() != w.coefficients.len() {
            return false;
        }
        let mut acc = vec![Scalar::ZERO; self.0.matrix.cols];
        let mut prev: Option<usize> = None;
        for (leaf, coeff) in w.leaves.iter().zip(&w.coefficients) {
            let Some(i) = self.index_of(leaf) else {
                return false;
            };
            // Strictly increasing row index ⇒ ordered and unique.
            if prev.is_some_and(|p| i <= p) {
                return false;
            }
            prev = Some(i);
            let Some(c) = coeff.to_scalar() else {
                return false;
            };
            if c == Scalar::ZERO {
                return false;
            }
            for (a, cell) in acc.iter_mut().zip(&self.0.matrix.rows[i]) {
                *a += c * cell.to_scalar().expect("validated scalar");
            }
        }
        acc == self.target_scalars()
    }

    /// Choose a qualified subset from the leaves that actually committed and
    /// return its witness, or `None` if the available set is not qualified.
    /// Deterministic and reproduced by every signer (§19).
    pub fn select_signing_plan(&self, available: &[LeafId]) -> Option<ReconstructionWitness> {
        self.reconstruct(available)
    }
}

/// Compile an expansion into its validated access structure. Identity is taken
/// from the expansion (finding 4), so no mismatched policy id can be asserted.
pub fn compile(expansion: &Expansion) -> Result<ValidatedCompiledPolicy, ValidationError> {
    let mut rows: Vec<(LeafId, Vec<Scalar>)> = Vec::new();
    let mut cols = 1usize; // column 0 is the secret
    build(&expansion.tree, vec![Scalar::ONE], &mut cols, &mut rows);

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
        policy: expansion.id,
        leaves,
        matrix: AccessMatrix {
            rows: matrix_rows,
            cols,
        },
        target,
    }
    .validate()
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

/// Solve `λ · rows = target` for `λ`, or `None` if the rows do not span the
/// target. Gaussian elimination over the field.
fn solve_row_combination(rows: &[Vec<Scalar>], target: &[Scalar]) -> Option<Vec<Scalar>> {
    let m = rows.len();
    let d = target.len();
    if m == 0 {
        return target.iter().all(|t| *t == Scalar::ZERO).then(Vec::new);
    }
    let mut aug: Vec<Vec<Scalar>> = (0..d)
        .map(|c| {
            let mut eq: Vec<Scalar> = (0..m).map(|i| rows[i][c]).collect();
            eq.push(target[c]);
            eq
        })
        .collect();

    let mut pivot_col = vec![usize::MAX; d];
    let mut r = 0usize;
    for col in 0..m {
        let Some(p) = (r..d).find(|&i| aug[i][col] != Scalar::ZERO) else {
            continue;
        };
        aug.swap(r, p);
        let inv = aug[r][col].invert();
        for x in aug[r].iter_mut() {
            *x *= inv;
        }
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

    for row in &aug {
        if row[..m].iter().all(|x| *x == Scalar::ZERO) && row[m] != Scalar::ZERO {
            return None;
        }
    }

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

    fn compile_policy(o: OwnershipPolicy) -> (ValidatedCompiledPolicy, Expansion) {
        let canon = o.canonicalize().unwrap();
        let exp = expand(&canon, &resolver()).unwrap();
        (compile(&exp).unwrap(), exp)
    }

    fn satisfied(p: &ExpandedPolicy, present: &BTreeSet<LeafId>) -> bool {
        match p {
            ExpandedPolicy::Leaf(l) => present.contains(l),
            ExpandedPolicy::Threshold { k, members } => {
                members.iter().filter(|m| satisfied(m, present)).count() >= *k as usize
            }
        }
    }

    /// THE test: for every subset of leaves, the MSP admits a reconstruction
    /// witness iff the boolean policy is satisfied — validated against the policy
    /// semantics directly.
    fn exhaustive_check(o: OwnershipPolicy) {
        let (compiled, exp) = compile_policy(o);
        let leaves: Vec<LeafId> = exp.tree.leaves().into_iter().cloned().collect();
        let n = leaves.len();
        assert!(n <= 12);
        for mask in 0u32..(1u32 << n) {
            let subset: Vec<LeafId> = (0..n)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| leaves[i].clone())
                .collect();
            let present: BTreeSet<LeafId> = subset.iter().cloned().collect();
            let boolean = satisfied(&exp.tree, &present);
            let witness = compiled.reconstruct(&subset);
            assert_eq!(witness.is_some(), boolean, "subset {mask:b}");
            if let Some(w) = witness {
                assert!(compiled.verify_witness(&w));
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
        let policy = OwnershipPolicy::AllOf(vec![
            OwnershipPolicy::Threshold {
                k: 1,
                members: vec![key(1), key(2), key(3)],
            },
            OwnershipPolicy::Key(prin(4)),
        ]);
        let (compiled, exp) = compile_policy(policy);
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
        assert_eq!(team_a.len(), 3);
        assert!(compiled.reconstruct(&team_a).is_none());
    }

    #[test]
    fn a_forged_witness_over_an_unqualified_set_fails_verification() {
        let (compiled, exp) = compile_policy(OwnershipPolicy::AllOf(vec![key(1), key(2)]));
        let leaves: Vec<LeafId> = exp.tree.leaves().into_iter().cloned().collect();
        let forged = ReconstructionWitness {
            structure: compiled.commitment(),
            leaves: vec![leaves[0].clone()],
            coefficients: vec![Fe::from_scalar(&Scalar::ONE)],
        };
        assert!(!compiled.verify_witness(&forged));
    }

    #[test]
    fn a_witness_bound_to_a_different_structure_fails() {
        let (compiled, _) = compile_policy(OwnershipPolicy::AnyOf(vec![key(1), key(2)]));
        let leaves = compiled.leaves().to_vec();
        let good = compiled.reconstruct(&[leaves[0].clone()]).unwrap();
        // Same coefficients, but claim a different structure commitment.
        let (other, _) = compile_policy(OwnershipPolicy::AllOf(vec![key(3), key(4)]));
        let mut cross = good.clone();
        cross.structure = other.commitment();
        assert!(!compiled.verify_witness(&cross));
    }

    #[test]
    fn a_witness_with_a_zero_or_repeated_leaf_fails() {
        let (compiled, _) = compile_policy(OwnershipPolicy::AnyOf(vec![key(1), key(2)]));
        let leaves = compiled.leaves().to_vec();
        let base = compiled.reconstruct(&[leaves[0].clone()]).unwrap();
        // Inject a zero coefficient.
        let mut zeroed = base.clone();
        zeroed.leaves.push(leaves[1].clone());
        zeroed.coefficients.push(Fe::from_scalar(&Scalar::ZERO));
        assert!(
            !compiled.verify_witness(&zeroed),
            "zero coefficient rejected"
        );
        // A repeated leaf (not strictly increasing) is rejected.
        let mut repeated = base.clone();
        repeated.leaves.push(base.leaves[0].clone());
        repeated.coefficients.push(Fe::from_scalar(&Scalar::ONE));
        assert!(
            !compiled.verify_witness(&repeated),
            "repeated leaf rejected"
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
        assert_eq!(a, b);
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

    #[test]
    fn hostile_deserialized_structures_are_rejected_not_panicked() {
        let (good, _) = compile_policy(OwnershipPolicy::AllOf(vec![key(1), key(2)]));
        let base = good.inner().clone();

        // Non-canonical scalar in a row.
        let mut bad = base.clone();
        bad.matrix.rows[0][0] = Fe([0xff; 32]);
        assert_eq!(bad.validate(), Err(ValidationError::NoncanonicalScalar));

        // Inconsistent row length.
        let mut bad = base.clone();
        bad.matrix.rows[0].push(Fe::from_scalar(&Scalar::ONE));
        assert_eq!(bad.validate(), Err(ValidationError::DimensionMismatch));

        // Target that is not e1.
        let mut bad = base.clone();
        bad.target[0] = Fe::from_scalar(&Scalar::from(5u64));
        assert_eq!(bad.validate(), Err(ValidationError::BadTarget));

        // Duplicate leaf.
        let mut bad = base.clone();
        bad.leaves[1] = bad.leaves[0].clone();
        assert_eq!(bad.validate(), Err(ValidationError::DuplicateLeaf));

        // Wrong version.
        let mut bad = base;
        bad.version = 99;
        assert_eq!(bad.validate(), Err(ValidationError::UnsupportedVersion(99)));
    }
}
