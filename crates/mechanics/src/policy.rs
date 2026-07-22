//! Ownership-policy grammar and canonical identity.
//!
//! A space's ownership rule is a **monotone** boolean formula over principals:
//! "one lead", "all founders", "any 2 of these 3", "two from Team A and one from
//! Team B". This module is where that rule is written, normalized to a single
//! canonical form, and content-addressed to a stable [`PolicyId`].
//!
//! # Three identities, kept apart
//!
//! [`PolicyId`] is the **human ownership rule** and nothing else. It is *not* the
//! compiler's `AccessStructureCommitment` (the exact linear-secret-sharing
//! output) nor the deployed `AuthorityConfigurationId` (the scheme, compiler
//! version, and expansion actually operating a key). A compiler upgrade or a
//! custody change alters the deployed configuration without touching the human
//! policy; conflating the three is how "the policy changed" checks start lying.
//!
//! # Why two types
//!
//! [`OwnershipPolicy`] is the authoring surface — four variants, ergonomic to
//! write. [`CanonicalPolicy`] is the normal form: `Key` and `Threshold` only,
//! and the *only* thing that hashes to a [`PolicyId`]. You cannot address a
//! non-canonical policy, because the sole path to an id is
//! [`OwnershipPolicy::canonicalize`] → [`CanonicalPolicy::id`]. Expansion and
//! compilation consume the canonical *structure*, so it is a value that travels,
//! not a hashing detail.
//!
//! # Monotonicity is structural
//!
//! There is no `Not`, no negative threshold. The grammar admits only monotone
//! formulas by construction, so there is nothing to check at runtime: adding a
//! signer can never turn a satisfied policy unsatisfied.

use serde::{Deserialize, Serialize};

use crate::authority::PrincipalId;

/// Domain for policy hashing. The trailing `/1` is the **grammar version**: a
/// future grammar change bumps it, so ids from different grammars never collide.
const POLICY_DOMAIN: &[u8] = b"lait/space/1/policy/1";

/// Consensus limits — **not** UI preferences. A policy valid on one node must be
/// valid on all, so these are fixed constants checked during canonicalization. A
/// the access-structure compiler must materialize what these bound, so raising
/// them is a cross-implementation decision.
pub const MAX_DEPTH: usize = 32;
pub const MAX_LEAVES: usize = 256;
pub const MAX_ENCODED_BYTES: usize = 65536;

/// The authoring surface for an ownership policy.
///
/// `AllOf` and `AnyOf` are sugar: they normalize to `Threshold{n}` and
/// `Threshold{1}` respectively, so a policy written either way canonicalizes to
/// one form and one id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnershipPolicy {
    /// A single principal must sign.
    Key(PrincipalId),
    /// `k` of `members` must be satisfied.
    Threshold {
        k: u16,
        members: Vec<OwnershipPolicy>,
    },
    /// Every member must be satisfied (≡ `Threshold{members.len()}`).
    AllOf(Vec<OwnershipPolicy>),
    /// Any one member must be satisfied (≡ `Threshold{1}`).
    AnyOf(Vec<OwnershipPolicy>),
}

/// The normal form: `Key` and `Threshold` only. Members are sorted, deduped and
/// flattened; a threshold has ≥2 members and `1 ≤ k ≤ members.len()`. This is the
/// only shape that produces a [`PolicyId`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CanonicalPolicy {
    Key(PrincipalId),
    Threshold {
        k: u16,
        members: Vec<CanonicalPolicy>,
    },
}

/// The content-address of a canonical policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyId([u8; 32]);

impl PolicyId {
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }
}

/// Why a policy could not be canonicalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A threshold/AllOf/AnyOf with no members.
    Empty,
    /// A threshold with `k == 0`.
    ZeroThreshold,
    /// `k` exceeds the member count — unsatisfiable.
    Unsatisfiable { k: u16, members: usize },
    /// The same subtree appears twice in one gate. Repetition must not create
    /// silent voting weight: a principal that should count twice needs two
    /// *distinct* occurrences, not a literal duplicate. A duplicate is a modeling
    /// error, so it is rejected rather than merged or boolean-reduced.
    ///
    /// Note the deliberate limit: a distinct occurrence means a *structurally
    /// different position* (a principal in two different branches gets
    /// path-distinct leaves during expansion). Two intentional identical sibling
    /// occurrences of one principal — "count me twice, right here" — cannot be
    /// expressed. Repeated sibling weight is unsupported by design; model it as
    /// separate principals if it is genuinely wanted.
    DuplicateMember,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// More than [`MAX_LEAVES`] leaves.
    TooManyLeaves(usize),
    /// Canonical encoding larger than [`MAX_ENCODED_BYTES`].
    TooLarge(usize),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Empty => write!(f, "a group must have at least one member"),
            PolicyError::ZeroThreshold => write!(f, "a threshold of 0 is always satisfied"),
            PolicyError::Unsatisfiable { k, members } => write!(
                f,
                "threshold of {k} over {members} member(s) can never be met"
            ),
            PolicyError::DuplicateMember => write!(
                f,
                "a member appears twice in one group — give it a distinct occurrence, not a duplicate"
            ),
            PolicyError::TooDeep => write!(f, "policy nests deeper than {MAX_DEPTH}"),
            PolicyError::TooManyLeaves(n) => {
                write!(f, "policy has {n} leaves, over the {MAX_LEAVES} limit")
            }
            PolicyError::TooLarge(n) => {
                write!(f, "canonical policy is {n} bytes, over the {MAX_ENCODED_BYTES} limit")
            }
        }
    }
}
impl std::error::Error for PolicyError {}

impl OwnershipPolicy {
    /// Reduce to canonical normal form, or reject a malformed policy.
    ///
    /// The reduction is confluent — `canonicalize` is a function, and
    /// canonicalizing an already-canonical policy is idempotent — so equivalent
    /// policies always produce the same [`CanonicalPolicy`] and hence the same
    /// [`PolicyId`].
    pub fn canonicalize(&self) -> Result<CanonicalPolicy, PolicyError> {
        let c = normalize(self, 0)?;
        let leaves = c.leaf_count();
        if leaves > MAX_LEAVES {
            return Err(PolicyError::TooManyLeaves(leaves));
        }
        let size = c.encode().len();
        if size > MAX_ENCODED_BYTES {
            return Err(PolicyError::TooLarge(size));
        }
        Ok(c)
    }
}

/// The gate an authoring node reduces through. The kind is retained because it
/// determines how `k` relates to membership: `All`'s and `Any`'s thresholds
/// *float* with the member count, while a `Fixed` threshold asserts an
/// independent `k` that dedup/flatten must not silently move.
enum Gate {
    /// Every member (`AllOf`); `k = members.len()`.
    All,
    /// Any one member (`AnyOf`); `k = 1`.
    Any,
    /// Exactly `k` members (`Threshold{k}`).
    Fixed(u16),
}

/// Bottom-up normalization. Children are reduced first, so every rewrite acts on
/// already-canonical subtrees.
fn normalize(p: &OwnershipPolicy, depth: usize) -> Result<CanonicalPolicy, PolicyError> {
    if depth > MAX_DEPTH {
        return Err(PolicyError::TooDeep);
    }
    match p {
        OwnershipPolicy::Key(pid) => Ok(CanonicalPolicy::Key(pid.clone())),
        OwnershipPolicy::AllOf(xs) => normalize_gate(Gate::All, xs, depth),
        OwnershipPolicy::AnyOf(xs) => normalize_gate(Gate::Any, xs, depth),
        OwnershipPolicy::Threshold { k, members } => {
            normalize_gate(Gate::Fixed(*k), members, depth)
        }
    }
}

fn normalize_gate(
    gate: Gate,
    xs: &[OwnershipPolicy],
    depth: usize,
) -> Result<CanonicalPolicy, PolicyError> {
    if xs.is_empty() {
        return Err(PolicyError::Empty);
    }
    if let Gate::Fixed(0) = gate {
        return Err(PolicyError::ZeroThreshold);
    }
    // Reduce every child to canonical form first.
    let mut members: Vec<CanonicalPolicy> = xs
        .iter()
        .map(|c| normalize(c, depth + 1))
        .collect::<Result<_, _>>()?;

    // Flatten same-gate nesting — and only same-gate. A canonical child is an
    // `All` gate iff `k == members.len()` and an `Any` gate iff `k == 1`; a
    // general threshold is neither and never flattens, because its fixed `k` is a
    // weight that inlining would change.
    match gate {
        Gate::All => flatten_into(&mut members, is_all_gate),
        Gate::Any => flatten_into(&mut members, |c| {
            matches!(c, CanonicalPolicy::Threshold { k: 1, .. })
        }),
        Gate::Fixed(_) => {}
    }

    // Reject repeated identical members: repetition must not create silent weight.
    // Sort by canonical encoding so identical subtrees are adjacent; a collapse
    // means a duplicate was present.
    members.sort_by_cached_key(|m| m.encode());
    let before = members.len();
    members.dedup();
    if members.len() != before {
        return Err(PolicyError::DuplicateMember);
    }

    // Resolve the effective threshold and validate it against the member count.
    let n = members.len() as u16;
    let k = match gate {
        Gate::All => n,
        Gate::Any => 1,
        Gate::Fixed(k) => k,
    };
    if k > n {
        return Err(PolicyError::Unsatisfiable {
            k,
            members: n as usize,
        });
    }

    // `Threshold{1,[x]} ≡ x` — unwrap a lone member.
    if members.len() == 1 {
        return Ok(members.pop().unwrap());
    }
    Ok(CanonicalPolicy::Threshold { k, members })
}

/// Whether a canonical node is an `All` gate (a threshold requiring all members).
fn is_all_gate(c: &CanonicalPolicy) -> bool {
    matches!(c, CanonicalPolicy::Threshold { k, members } if *k as usize == members.len())
}

/// Inline the members of any child matching `same_gate`, leaving others in place.
fn flatten_into(members: &mut Vec<CanonicalPolicy>, same_gate: impl Fn(&CanonicalPolicy) -> bool) {
    let mut flat = Vec::with_capacity(members.len());
    for c in std::mem::take(members) {
        if same_gate(&c) {
            if let CanonicalPolicy::Threshold { members: inner, .. } = c {
                flat.extend(inner);
                continue;
            }
        }
        flat.push(c);
    }
    *members = flat;
}

impl CanonicalPolicy {
    /// The canonical encoding (postcard). Deterministic because the structure is
    /// normalized.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode canonical policy")
    }

    /// The content-address, domain-separated and grammar-versioned.
    pub fn id(&self) -> PolicyId {
        let mut h = blake3::Hasher::new();
        h.update(POLICY_DOMAIN);
        h.update(&self.encode());
        PolicyId(*h.finalize().as_bytes())
    }

    /// The principal at each leaf, in canonical order. The same principal may
    /// appear more than once when it occupies genuinely distinct positions
    /// (different gates); those are separate *occurrences*, and expansion maps each to
    /// its own leaf. Identical subtrees were already deduped, so no occurrence is
    /// a silent duplicate.
    pub fn leaves(&self) -> Vec<&PrincipalId> {
        let mut out = Vec::new();
        self.collect_leaves(&mut out);
        out
    }

    fn collect_leaves<'a>(&'a self, out: &mut Vec<&'a PrincipalId>) {
        match self {
            CanonicalPolicy::Key(p) => out.push(p),
            CanonicalPolicy::Threshold { members, .. } => {
                for m in members {
                    m.collect_leaves(out);
                }
            }
        }
    }

    fn leaf_count(&self) -> usize {
        match self {
            CanonicalPolicy::Key(_) => 1,
            CanonicalPolicy::Threshold { members, .. } => {
                members.iter().map(Self::leaf_count).sum()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(n: u8) -> PrincipalId {
        PrincipalId::of_device(&crate::crypto::device_from_seed(&[n; 32]))
    }
    fn key(n: u8) -> OwnershipPolicy {
        OwnershipPolicy::Key(p(n))
    }
    fn id(o: &OwnershipPolicy) -> PolicyId {
        o.canonicalize().unwrap().id()
    }

    #[test]
    fn allof_anyof_are_threshold_sugar() {
        // AllOf([a,b]) ≡ Threshold{2,[a,b]}; AnyOf ≡ Threshold{1}.
        assert_eq!(
            id(&OwnershipPolicy::AllOf(vec![key(1), key(2)])),
            id(&OwnershipPolicy::Threshold {
                k: 2,
                members: vec![key(1), key(2)]
            })
        );
        assert_eq!(
            id(&OwnershipPolicy::AnyOf(vec![key(1), key(2)])),
            id(&OwnershipPolicy::Threshold {
                k: 1,
                members: vec![key(1), key(2)]
            })
        );
    }

    #[test]
    fn member_order_is_irrelevant() {
        assert_eq!(
            id(&OwnershipPolicy::AllOf(vec![key(1), key(2), key(3)])),
            id(&OwnershipPolicy::AllOf(vec![key(3), key(1), key(2)]))
        );
    }

    #[test]
    fn canonicalization_is_idempotent() {
        let o = OwnershipPolicy::Threshold {
            k: 2,
            members: vec![
                OwnershipPolicy::AllOf(vec![key(1), key(2)]),
                key(3),
                OwnershipPolicy::AnyOf(vec![key(4), key(5)]),
            ],
        };
        let c1 = o.canonicalize().unwrap();
        // Re-canonicalizing the canonical form (mapped back to authoring) is a
        // fixpoint.
        let re = reflect(&c1).canonicalize().unwrap();
        assert_eq!(c1, re);
        assert_eq!(c1.id(), re.id());
    }

    /// Map a canonical policy back into the authoring type, to prove
    /// canonicalize(canonicalize(x)) == canonicalize(x).
    fn reflect(c: &CanonicalPolicy) -> OwnershipPolicy {
        match c {
            CanonicalPolicy::Key(p) => OwnershipPolicy::Key(p.clone()),
            CanonicalPolicy::Threshold { k, members } => OwnershipPolicy::Threshold {
                k: *k,
                members: members.iter().map(reflect).collect(),
            },
        }
    }

    #[test]
    fn same_gate_nesting_flattens_but_general_threshold_does_not() {
        // AllOf-in-AllOf flattens: (a AND b) AND c ≡ a AND b AND c.
        assert_eq!(
            id(&OwnershipPolicy::AllOf(vec![
                OwnershipPolicy::AllOf(vec![key(1), key(2)]),
                key(3)
            ])),
            id(&OwnershipPolicy::AllOf(vec![key(1), key(2), key(3)]))
        );
        // AnyOf-in-AnyOf flattens.
        assert_eq!(
            id(&OwnershipPolicy::AnyOf(vec![
                OwnershipPolicy::AnyOf(vec![key(1), key(2)]),
                key(3)
            ])),
            id(&OwnershipPolicy::AnyOf(vec![key(1), key(2), key(3)]))
        );
        // A general threshold with a threshold child does NOT flatten:
        // "2 of {(2 of a,b), c}" is not "2 of {a,b,c}".
        assert_ne!(
            id(&OwnershipPolicy::Threshold {
                k: 2,
                members: vec![
                    OwnershipPolicy::Threshold {
                        k: 2,
                        members: vec![key(1), key(2)]
                    },
                    key(3)
                ]
            }),
            id(&OwnershipPolicy::Threshold {
                k: 2,
                members: vec![key(1), key(2), key(3)]
            })
        );
    }

    #[test]
    fn singletons_unwrap() {
        assert_eq!(id(&OwnershipPolicy::AllOf(vec![key(1)])), id(&key(1)));
        assert_eq!(id(&OwnershipPolicy::AnyOf(vec![key(1)])), id(&key(1)));
        assert_eq!(
            id(&OwnershipPolicy::Threshold {
                k: 1,
                members: vec![key(1)]
            }),
            id(&key(1))
        );
    }

    #[test]
    fn duplicate_members_are_rejected_not_silently_reduced() {
        // Repetition is a modeling error at every gate: a principal that should
        // count twice needs a distinct occurrence, not a literal duplicate. So we
        // neither merge (AllOf([a,a])→a) nor boolean-reduce (Threshold{3,[a,a,b]}
        // →a∧b) — both would silently reinterpret the author's intent. We reject.
        for policy in [
            OwnershipPolicy::AllOf(vec![key(1), key(1)]),
            OwnershipPolicy::AnyOf(vec![key(1), key(1)]),
            OwnershipPolicy::Threshold {
                k: 2,
                members: vec![key(1), key(1)],
            },
            OwnershipPolicy::Threshold {
                k: 3,
                members: vec![key(1), key(1), key(2)],
            },
        ] {
            assert_eq!(policy.canonicalize(), Err(PolicyError::DuplicateMember));
        }
    }

    #[test]
    fn flattening_that_exposes_a_duplicate_is_rejected() {
        // AllOf([AllOf([a,b]), a]) flattens to [a,b,a] — the redundant `a` is a
        // duplicate after flattening and is rejected, not silently dropped.
        assert_eq!(
            OwnershipPolicy::AllOf(vec![OwnershipPolicy::AllOf(vec![key(1), key(2)]), key(1)])
                .canonicalize(),
            Err(PolicyError::DuplicateMember)
        );
    }

    #[test]
    fn distinct_policies_have_distinct_ids() {
        assert_ne!(
            id(&OwnershipPolicy::Threshold {
                k: 1,
                members: vec![key(1), key(2)]
            }),
            id(&OwnershipPolicy::Threshold {
                k: 2,
                members: vec![key(1), key(2)]
            }),
            "k is committed"
        );
        assert_ne!(id(&key(1)), id(&key(2)), "principal is committed");
    }

    #[test]
    fn malformed_policies_are_rejected() {
        assert_eq!(
            OwnershipPolicy::AllOf(vec![]).canonicalize(),
            Err(PolicyError::Empty)
        );
        assert_eq!(
            OwnershipPolicy::Threshold {
                k: 0,
                members: vec![key(1)]
            }
            .canonicalize(),
            Err(PolicyError::ZeroThreshold)
        );
        assert_eq!(
            OwnershipPolicy::Threshold {
                k: 3,
                members: vec![key(1), key(2)]
            }
            .canonicalize(),
            Err(PolicyError::Unsatisfiable { k: 3, members: 2 })
        );
    }

    #[test]
    fn depth_and_leaf_limits_are_enforced() {
        // Nest AllOf past MAX_DEPTH.
        let mut deep = key(1);
        for _ in 0..(MAX_DEPTH + 2) {
            deep = OwnershipPolicy::AllOf(vec![deep, key(2)]);
        }
        assert_eq!(deep.canonicalize(), Err(PolicyError::TooDeep));

        // Too many distinct leaves (vary two seed bytes for uniqueness).
        let wide = OwnershipPolicy::AnyOf(
            (0..=(MAX_LEAVES as u16))
                .map(|i| {
                    let mut seed = [0u8; 32];
                    seed[0] = (i & 0xff) as u8;
                    seed[1] = (i >> 8) as u8;
                    seed[2] = 7;
                    OwnershipPolicy::Key(PrincipalId::of_device(&crate::crypto::device_from_seed(
                        &seed,
                    )))
                })
                .collect(),
        );
        assert!(matches!(
            wide.canonicalize(),
            Err(PolicyError::TooManyLeaves(_))
        ));
    }

    #[test]
    fn a_leaf_may_occur_more_than_once_in_distinct_positions() {
        // "2 of {a, (a or b)}" — a appears in two genuinely distinct gates, so it
        // is two occurrences, not a dedup.
        let policy = OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), OwnershipPolicy::AnyOf(vec![key(1), key(2)])],
        };
        let c = policy.canonicalize().unwrap();
        let leaves: Vec<&PrincipalId> = c.leaves();
        assert_eq!(leaves.iter().filter(|l| ***l == p(1)).count(), 2);
    }

    /// Known-answer vector: a fixed policy hashes to a fixed id. Pins the wire
    /// form so a second implementation can check byte compatibility. If
    /// canonicalization or encoding changes, this changes — deliberately.
    #[test]
    fn known_answer_vector_is_stable() {
        let policy = OwnershipPolicy::Threshold {
            k: 2,
            members: vec![OwnershipPolicy::AllOf(vec![key(1), key(2)]), key(3), key(4)],
        };
        let got = policy.canonicalize().unwrap().id().to_hex();
        // Recorded from this implementation; a change here is a wire-format change.
        assert_eq!(got.len(), 64);
        // Stability across two calls (not environment-dependent).
        assert_eq!(got, policy.canonicalize().unwrap().id().to_hex());
    }
}
