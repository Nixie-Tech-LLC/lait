//! Principal-to-leaf expansion.
//!
//! [`crate::policy`] gives a canonical policy over **principals** (ownership identities). Before
//! it can become a cryptographic access structure, each principal must expand to
//! the **leaves** that actually hold shares:
//!
//! - a **Direct** principal is one leaf, operated by one device;
//! - a **Federated** principal expands into a whole sub-policy — a founder that
//!   is itself a group — which inlines into the global tree rather than becoming
//!   an opaque nested key. (Treating a founder's internal group as an opaque
//!   leaf would require nested signing orchestration and a separate backend.)
//!
//! # Immutable, configuration-bound
//!
//! Expansion is a pure function of `(CanonicalPolicy, resolver)`. It never reads
//! mutable "current profile" state, so the same inputs always yield the same
//! leaves and the same provenance — the snapshot a deployed configuration binds.
//!
//! # No silent weight; distinct occurrences get distinct leaves
//!
//! One principal may own several rows: if `a` occupies two *genuinely distinct*
//! positions in the policy (canonicalization already rejected literal duplicates), each
//! position expands to its own leaf with its own id. The leaf id is derived from
//! the **occurrence path**, so two occurrences of one principal — or one device
//! backing two leaves — never collapse. Additional weight thus requires distinct
//! occurrences and never appears by accident.

use serde::{Deserialize, Serialize};

use crate::authority::{LeafId, PrincipalId};
use crate::ids::UserId;
use crate::policy::{CanonicalPolicy, OwnershipPolicy, PolicyError, PolicyId};

/// Domain for leaf-id derivation, separate from policy hashing.
const LEAF_DOMAIN: &[u8] = b"lait/space/1/policy/1/leaf";

/// Bound on federation nesting, so a chain of federated principals cannot expand
/// without limit. A consensus input like the policy limits.
pub const MAX_FEDERATION_DEPTH: usize = 16;

/// Bound on the **expanded** leaf count. [`crate::policy::MAX_LEAVES`] bounds the
/// *unexpanded* policy, but every federated principal can expand into another
/// full policy, so a 256-principal root could otherwise reach tens of thousands
/// of leaves — a compile/solve exhaustion path. This bounds the artifact
/// cryptography actually consumes, checked incrementally so a hostile policy
/// cannot build a huge structure before the check fires.
pub const MAX_EXPANDED_LEAVES: usize = 512;

/// Bound on the **expanded** tree depth (federation inlines lengthen paths).
pub const MAX_EXPANDED_DEPTH: usize = 64;

/// How a principal is realized cryptographically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalCustody {
    /// One leaf, operated by `device`. For a plain device-principal this is the
    /// principal's own key; it is carried explicitly so an organizational
    /// principal can name the device that acts for it.
    Direct { device: UserId },
    /// The principal is itself a group: expand this sub-policy in place.
    Federated(OwnershipPolicy),
}

/// A principal and how it expands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalDescriptor {
    pub id: PrincipalId,
    pub custody: PrincipalCustody,
}

/// A single cryptographic row's stable provenance: the leaf, the principal
/// that owns it, the device that operates it, and the occurrence path that makes
/// it distinct from every other leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafDescriptor {
    pub leaf: LeafId,
    pub principal: PrincipalId,
    pub device: UserId,
    /// Child-index path from the expanded root to this leaf. Unique per leaf.
    pub path: Vec<u32>,
}

/// A policy expanded to leaves: the same monotone structure as [`CanonicalPolicy`]
/// but with cryptographic leaves in place of principals.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ExpandedPolicy {
    Leaf(LeafId),
    Threshold {
        k: u16,
        members: Vec<ExpandedPolicy>,
    },
}

/// The result of expanding a policy: the source policy's identity, the leaf-level
/// structure, and every leaf's provenance, in canonical (tree) order.
///
/// `id` is stamped from the [`CanonicalPolicy`] that was expanded, so the
/// compiler cannot be handed a tree under a mismatched policy id — the identity
/// travels with the expansion rather than being asserted alongside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expansion {
    // Private: an Expansion can only be produced by `expand`, which stamps `id`
    // from the very policy whose tree it built. Public fields would let a caller
    // pair policy A's id with policy B's tree — the exact mismatch this binding
    // exists to forbid (finding 1).
    id: PolicyId,
    tree: ExpandedPolicy,
    leaves: Vec<LeafDescriptor>,
}

impl Expansion {
    /// The canonical policy this expansion is of.
    pub fn id(&self) -> PolicyId {
        self.id
    }
    /// The leaf-level structure.
    pub fn tree(&self) -> &ExpandedPolicy {
        &self.tree
    }
    /// Each leaf's provenance, in canonical order.
    pub fn leaves(&self) -> &[LeafDescriptor] {
        &self.leaves
    }
}

/// Why expansion failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    /// A principal named in the policy has no descriptor.
    UnknownPrincipal(PrincipalId),
    /// A federated principal reaches itself, directly or through a chain.
    Cycle(PrincipalId),
    /// Federation nests past [`MAX_FEDERATION_DEPTH`].
    TooDeep,
    /// Expansion produced more than [`MAX_EXPANDED_LEAVES`] leaves.
    TooManyLeaves,
    /// The expanded tree is deeper than [`MAX_EXPANDED_DEPTH`].
    TooDeepExpanded,
    /// A federated sub-policy is itself malformed.
    Policy(PolicyError),
}

impl std::fmt::Display for ExpandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpandError::UnknownPrincipal(p) => {
                write!(f, "no descriptor for principal {}", p.as_str())
            }
            ExpandError::Cycle(p) => write!(f, "principal {} federates to itself", p.as_str()),
            ExpandError::TooDeep => write!(f, "federation nests past {MAX_FEDERATION_DEPTH}"),
            ExpandError::TooManyLeaves => {
                write!(f, "expansion exceeds {MAX_EXPANDED_LEAVES} leaves")
            }
            ExpandError::TooDeepExpanded => {
                write!(f, "expanded tree deeper than {MAX_EXPANDED_DEPTH}")
            }
            ExpandError::Policy(e) => write!(f, "federated sub-policy is malformed: {e}"),
        }
    }
}
impl std::error::Error for ExpandError {}

/// Expand `policy` to leaves, resolving each principal through `resolve`.
///
/// `resolve` returns a principal's descriptor, or `None` if unknown. It is a
/// borrow of an immutable snapshot: expansion must be reproducible, so `resolve`
/// must be a pure function of the configuration, never of live state.
pub fn expand(
    policy: &CanonicalPolicy,
    resolve: &impl Fn(&PrincipalId) -> Option<PrincipalDescriptor>,
) -> Result<Expansion, ExpandError> {
    let mut leaves = Vec::new();
    let mut stack = Vec::new();
    let tree = expand_rec(policy, resolve, &mut Vec::new(), &mut stack, &mut leaves)?;
    Ok(Expansion {
        id: policy.id(),
        tree,
        leaves,
    })
}

fn expand_rec(
    policy: &CanonicalPolicy,
    resolve: &impl Fn(&PrincipalId) -> Option<PrincipalDescriptor>,
    path: &mut Vec<u32>,
    // Principals currently being expanded on this descent, for cycle detection.
    stack: &mut Vec<PrincipalId>,
    leaves: &mut Vec<LeafDescriptor>,
) -> Result<ExpandedPolicy, ExpandError> {
    if stack.len() > MAX_FEDERATION_DEPTH {
        return Err(ExpandError::TooDeep);
    }
    if path.len() > MAX_EXPANDED_DEPTH {
        return Err(ExpandError::TooDeepExpanded);
    }
    match policy {
        CanonicalPolicy::Key(principal) => {
            let descriptor = resolve(principal)
                .ok_or_else(|| ExpandError::UnknownPrincipal(principal.clone()))?;
            match descriptor.custody {
                PrincipalCustody::Direct { device } => {
                    if leaves.len() >= MAX_EXPANDED_LEAVES {
                        return Err(ExpandError::TooManyLeaves);
                    }
                    let leaf = leaf_id(path, principal, &device);
                    leaves.push(LeafDescriptor {
                        leaf: leaf.clone(),
                        principal: principal.clone(),
                        device,
                        path: path.clone(),
                    });
                    Ok(ExpandedPolicy::Leaf(leaf))
                }
                PrincipalCustody::Federated(sub) => {
                    if stack.contains(principal) {
                        return Err(ExpandError::Cycle(principal.clone()));
                    }
                    let canon = sub.canonicalize().map_err(ExpandError::Policy)?;
                    stack.push(principal.clone());
                    let out = expand_rec(&canon, resolve, path, stack, leaves)?;
                    stack.pop();
                    Ok(out)
                }
            }
        }
        CanonicalPolicy::Threshold { k, members } => {
            let mut expanded = Vec::with_capacity(members.len());
            for (i, m) in members.iter().enumerate() {
                path.push(i as u32);
                expanded.push(expand_rec(m, resolve, path, stack, leaves)?);
                path.pop();
            }
            Ok(ExpandedPolicy::Threshold {
                k: *k,
                members: expanded,
            })
        }
    }
}

/// A leaf id bound to its occurrence path and provenance. The path makes it
/// distinct per occurrence; principal and device bind provenance into the id so
/// a descriptor cannot be swapped without changing the leaf it names.
fn leaf_id(path: &[u32], principal: &PrincipalId, device: &UserId) -> LeafId {
    let mut h = blake3::Hasher::new();
    h.update(LEAF_DOMAIN);
    h.update(&(path.len() as u64).to_le_bytes());
    for step in path {
        h.update(&step.to_le_bytes());
    }
    h.update(principal.as_str().as_bytes());
    h.update(device.as_str().as_bytes());
    LeafId::from_string(data_encoding::HEXLOWER.encode(h.finalize().as_bytes()))
}

impl ExpandedPolicy {
    /// The leaves of this expanded policy, in tree order.
    pub fn leaves(&self) -> Vec<&LeafId> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }
    fn collect<'a>(&'a self, out: &mut Vec<&'a LeafId>) {
        match self {
            ExpandedPolicy::Leaf(l) => out.push(l),
            ExpandedPolicy::Threshold { members, .. } => {
                for m in members {
                    m.collect(out);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn dev(n: u8) -> UserId {
        crate::crypto::user_from_seed(&[n; 32])
    }
    fn prin(n: u8) -> PrincipalId {
        PrincipalId::of_device(&dev(n))
    }
    fn key(n: u8) -> OwnershipPolicy {
        OwnershipPolicy::Key(prin(n))
    }

    /// A resolver where each named principal is Direct on its own device, unless
    /// overridden with a federation.
    fn resolver(
        federations: BTreeMap<PrincipalId, OwnershipPolicy>,
    ) -> impl Fn(&PrincipalId) -> Option<PrincipalDescriptor> {
        move |p: &PrincipalId| {
            let custody = match federations.get(p) {
                Some(sub) => PrincipalCustody::Federated(sub.clone()),
                None => PrincipalCustody::Direct {
                    device: p.as_device()?,
                },
            };
            Some(PrincipalDescriptor {
                id: p.clone(),
                custody,
            })
        }
    }

    #[test]
    fn a_flat_policy_expands_one_leaf_per_principal() {
        let policy = OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        }
        .canonicalize()
        .unwrap();
        let e = expand(&policy, &resolver(BTreeMap::new())).unwrap();
        assert_eq!(e.leaves().len(), 3);
        // Each leaf's provenance points at its principal and device.
        for d in &e.leaves {
            assert_eq!(d.device, d.principal.as_device().unwrap());
        }
        // The structure is preserved, over leaves.
        assert!(matches!(e.tree(), ExpandedPolicy::Threshold { k: 2, .. }));
    }

    #[test]
    fn a_federated_principal_inlines_its_subtree() {
        // Founder `1` is really a 2-of-3 of devices {10,11,12}.
        let mut fed = BTreeMap::new();
        fed.insert(
            prin(1),
            OwnershipPolicy::Threshold {
                k: 2,
                members: vec![key(10), key(11), key(12)],
            },
        );
        // Top policy: AllOf(founder1, device2).
        let policy = OwnershipPolicy::AllOf(vec![key(1), key(2)])
            .canonicalize()
            .unwrap();
        let e = expand(&policy, &resolver(fed)).unwrap();
        // Four leaves: the 3 sub-devices of founder 1, plus device 2.
        assert_eq!(e.leaves().len(), 4);
        // The federation flattened in — the top gate now has a threshold child,
        // not an opaque leaf for founder 1.
        let ExpandedPolicy::Threshold { members, .. } = e.tree() else {
            panic!("expected a threshold root");
        };
        assert!(members
            .iter()
            .any(|m| matches!(m, ExpandedPolicy::Threshold { k: 2, .. })));
    }

    #[test]
    fn distinct_occurrences_of_one_principal_get_distinct_leaves() {
        // `a` appears in two genuinely distinct positions; canonicalization permits this.
        let policy = OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), OwnershipPolicy::AnyOf(vec![key(1), key(2)])],
        }
        .canonicalize()
        .unwrap();
        let e = expand(&policy, &resolver(BTreeMap::new())).unwrap();
        // Three leaf rows: two occurrences of principal 1, one of principal 2.
        let ones: Vec<&LeafDescriptor> = e
            .leaves()
            .iter()
            .filter(|d| d.principal == prin(1))
            .collect();
        assert_eq!(ones.len(), 2, "one principal, two rows");
        assert_ne!(ones[0].leaf, ones[1].leaf, "distinct leaf ids");
        assert_ne!(ones[0].path, ones[1].path, "distinct occurrence paths");
        // Same device operates both rows — legitimate multi-row ownership.
        assert_eq!(ones[0].device, ones[1].device);
    }

    #[test]
    fn expansion_is_deterministic() {
        let policy = OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        }
        .canonicalize()
        .unwrap();
        let a = expand(&policy, &resolver(BTreeMap::new())).unwrap();
        let b = expand(&policy, &resolver(BTreeMap::new())).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn an_unknown_principal_is_rejected() {
        let policy = OwnershipPolicy::AnyOf(vec![key(1), key(2)])
            .canonicalize()
            .unwrap();
        // Resolver that knows no one.
        let empty = |_: &PrincipalId| None;
        assert!(matches!(
            expand(&policy, &empty),
            Err(ExpandError::UnknownPrincipal(_))
        ));
    }

    #[test]
    fn a_federation_cycle_is_rejected() {
        // Principal 1 federates to a policy that references principal 1.
        let mut fed = BTreeMap::new();
        fed.insert(prin(1), OwnershipPolicy::AnyOf(vec![key(1), key(2)]));
        let policy = key(1).canonicalize().unwrap();
        assert!(matches!(
            expand(&policy, &resolver(fed)),
            Err(ExpandError::Cycle(_))
        ));
    }

    /// Federation can multiply the unexpanded policy beyond its leaf bound:
    /// leaves — three federated principals, each a 200-key group, blow past
    /// MAX_EXPANDED_LEAVES even though each sub-policy is individually valid. The
    /// incremental check fires instead of building the whole structure.
    #[test]
    fn federation_that_exceeds_the_expanded_leaf_limit_is_rejected() {
        let group = |base: u16| {
            OwnershipPolicy::AnyOf(
                (0..200u16)
                    .map(|i| {
                        let mut seed = [0u8; 32];
                        seed[0] = (base & 0xff) as u8;
                        seed[1] = (base >> 8) as u8;
                        seed[2] = (i & 0xff) as u8;
                        seed[3] = (i >> 8) as u8;
                        OwnershipPolicy::Key(PrincipalId::of_device(
                            &crate::crypto::user_from_seed(&seed),
                        ))
                    })
                    .collect(),
            )
        };
        let mut fed = BTreeMap::new();
        fed.insert(prin(1), group(1));
        fed.insert(prin(2), group(2));
        fed.insert(prin(3), group(3));
        let policy = OwnershipPolicy::AnyOf(vec![key(1), key(2), key(3)])
            .canonicalize()
            .unwrap();
        assert!(matches!(
            expand(&policy, &resolver(fed)),
            Err(ExpandError::TooManyLeaves)
        ));
    }

    #[test]
    fn nested_federation_expands_transitively() {
        // 1 → group of {2, 3}; 2 → group of {20, 21}.
        let mut fed = BTreeMap::new();
        fed.insert(prin(1), OwnershipPolicy::AllOf(vec![key(2), key(3)]));
        fed.insert(prin(2), OwnershipPolicy::AnyOf(vec![key(20), key(21)]));
        let policy = key(1).canonicalize().unwrap();
        let e = expand(&policy, &resolver(fed)).unwrap();
        // Leaves: 20, 21 (from 2), and 3.
        assert_eq!(e.leaves().len(), 3);
        let principals: Vec<&PrincipalId> = e.leaves().iter().map(|d| &d.principal).collect();
        assert!(principals.contains(&&prin(20)));
        assert!(principals.contains(&&prin(21)));
        assert!(principals.contains(&&prin(3)));
    }
}
