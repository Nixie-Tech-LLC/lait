//! Membership / ACL — a signed ed25519 op-graph validated by deterministic
//! replay (S§6, A§11). The ops ride in the plaintext membership layer
//! ([`crate::membership`]) and propagate as a grow-only set; **trust is computed
//! by app-layer replay**, never by Loro. Roles are `admin`/`member`; revocation
//! is **remove-wins**.
//!
//! Authority: an op is honored only if its author is an admin as of the op's
//! causal history. Sequential admin actions (the common path) validate exactly;
//! the remove-wins membership resolution uses the causal ancestor closure so a
//! concurrent add cannot override a remove.
//!
//! > **Research-grade** (A§2): a proven design implemented by hand, unaudited.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::ids::UserId;
use crate::store::Genesis;

/// A member role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Member,
}

/// A membership operation (S§6). Canonically encoded (postcard) and signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclOp {
    AddMember { key: UserId, role: Role },
    RemoveMember { key: UserId },
    SetRole { key: UserId, role: Role },
}

impl AclOp {
    fn key(&self) -> &UserId {
        match self {
            AclOp::AddMember { key, .. }
            | AclOp::RemoveMember { key }
            | AclOp::SetRole { key, .. } => key,
        }
    }
    fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode acl op")
    }
}

/// A signed op with its causal parents (S§6). `op` is the canonical `AclOp`
/// bytes; `sig` is ed25519 over `op` by `author`; `parents` are op hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOp {
    pub op: Vec<u8>,
    pub author: UserId,
    pub sig: Vec<u8>,
    pub parents: Vec<String>,
}

impl SignedOp {
    /// The content-address of this op (its hash-DAG node id).
    pub fn hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(&self.op);
        h.update(self.author.as_str().as_bytes());
        let mut ps = self.parents.clone();
        ps.sort();
        for p in ps {
            h.update(p.as_bytes());
        }
        h.finalize().to_hex().to_string()
    }
    fn decode_op(&self) -> Option<AclOp> {
        postcard::from_bytes(&self.op).ok()
    }
    fn verify_sig(&self) -> bool {
        let Some(pk_bytes) = hex32(self.author.as_str()) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.sig) else {
            return false;
        };
        vk.verify(&self.op, &sig).is_ok()
    }
}

/// Sign an [`AclOp`] with the author's ed25519 seed, given the current heads as
/// parents (S§6). The author is derived from the seed.
pub fn sign_op(seed: &[u8; 32], op: &AclOp, parents: Vec<String>) -> SignedOp {
    let sk = SigningKey::from_bytes(seed);
    let author =
        UserId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()));
    let op_bytes = op.encode();
    let sig: Signature = sk.sign(&op_bytes);
    SignedOp {
        op: op_bytes,
        author,
        sig: sig.to_bytes().to_vec(),
        parents,
    }
}

/// The materialized ACL state after replay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AclState {
    members: BTreeMap<UserId, Role>,
}

impl AclState {
    pub fn is_member(&self, u: &UserId) -> bool {
        self.members.contains_key(u)
    }
    pub fn is_admin(&self, u: &UserId) -> bool {
        matches!(self.members.get(u), Some(Role::Admin))
    }
    pub fn role(&self, u: &UserId) -> Option<Role> {
        self.members.get(u).copied()
    }
    /// All current members, sorted by key.
    pub fn members(&self) -> Vec<(UserId, Role)> {
        self.members.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Deterministically replay a signed op-graph from the genesis (S§6). Founding
/// admins seed the admin set; each op is honored only if signature-valid and
/// authored by an admin as of its causal history; membership resolves
/// **remove-wins** over the causal ancestor closure.
pub fn replay(genesis: &Genesis, ops: &[SignedOp]) -> AclState {
    // Index valid-signed ops by hash.
    let mut by_hash: HashMap<String, (&SignedOp, AclOp)> = HashMap::new();
    for so in ops {
        if !so.verify_sig() {
            continue;
        }
        if let Some(op) = so.decode_op() {
            by_hash.insert(so.hash(), (so, op));
        }
    }

    // Transitive causal ancestors of each op (over present parents only).
    let ancestors = compute_ancestors(&by_hash);

    // Topological order (ancestors before descendants; ties by hash for
    // determinism).
    let order = topo_order(&by_hash, &ancestors);

    // Founding admins are the trust root.
    let mut admins: BTreeSet<UserId> = genesis.founding_admins.iter().cloned().collect();

    // First pass (topo): decide which ops are authorized, growing the admin set
    // so later ops authored by freshly-added admins validate. This is exact for
    // sequential admin grants; concurrent grants are resolved by topo tie-break.
    let mut authorized: Vec<String> = Vec::new();
    for h in &order {
        let (so, op) = &by_hash[h];
        let author_ok = admins.contains(&so.author);
        if !author_ok {
            continue;
        }
        authorized.push(h.clone());
        // grow the admin set from authorized ops so downstream authors validate.
        match op {
            AclOp::AddMember { key, role } | AclOp::SetRole { key, role } => {
                if *role == Role::Admin {
                    admins.insert(key.clone());
                } else {
                    admins.remove(key);
                }
            }
            AclOp::RemoveMember { key } => {
                admins.remove(key);
            }
        }
    }
    // Membership: seed with the founding admins, apply authorized ops in topo
    // order, then apply the remove-wins override for concurrency.
    let mut members: BTreeMap<UserId, Role> = genesis
        .founding_admins
        .iter()
        .map(|a| (a.clone(), Role::Admin))
        .collect();

    for h in &authorized {
        match &by_hash[h].1 {
            AclOp::AddMember { key, role } | AclOp::SetRole { key, role } => {
                members.insert(key.clone(), *role);
            }
            AclOp::RemoveMember { key } => {
                members.remove(key);
            }
        }
    }

    // remove-wins override: a key with an authorized remove that is NOT
    // causally-succeeded by an authorized add is removed even if a concurrent
    // add appeared later in topo order.
    let keys: BTreeSet<UserId> = authorized
        .iter()
        .map(|h| by_hash[h].1.key().clone())
        .collect();
    for key in keys {
        let adds: Vec<&String> = authorized
            .iter()
            .filter(|h| matches!(&by_hash[*h].1, AclOp::AddMember { key: k, .. } | AclOp::SetRole { key: k, .. } if k == &key))
            .collect();
        let removes: Vec<&String> = authorized
            .iter()
            .filter(|h| matches!(&by_hash[*h].1, AclOp::RemoveMember { key: k } if k == &key))
            .collect();
        if removes.is_empty() {
            continue;
        }
        let removed = removes.iter().any(|r| {
            !adds.iter().any(|a| {
                ancestors
                    .get(*a)
                    .map(|anc| anc.contains(*r))
                    .unwrap_or(false)
            })
        });
        if removed {
            members.remove(&key);
        }
    }

    AclState { members }
}

fn compute_ancestors(
    by_hash: &HashMap<String, (&SignedOp, AclOp)>,
) -> HashMap<String, HashSet<String>> {
    let mut out: HashMap<String, HashSet<String>> = HashMap::new();
    for h in by_hash.keys() {
        let mut anc = HashSet::new();
        let mut stack: Vec<String> = by_hash[h].0.parents.clone();
        while let Some(p) = stack.pop() {
            if by_hash.contains_key(&p) && anc.insert(p.clone()) {
                stack.extend(by_hash[&p].0.parents.clone());
            }
        }
        out.insert(h.clone(), anc);
    }
    out
}

fn topo_order(
    by_hash: &HashMap<String, (&SignedOp, AclOp)>,
    ancestors: &HashMap<String, HashSet<String>>,
) -> Vec<String> {
    let mut order: Vec<String> = by_hash.keys().cloned().collect();
    // Sort so ancestors precede descendants; break ties by hash (determinism).
    order.sort_by(|a, b| {
        let a_before_b = ancestors.get(b).map(|s| s.contains(a)).unwrap_or(false);
        let b_before_a = ancestors.get(a).map(|s| s.contains(b)).unwrap_or(false);
        match (a_before_b, b_before_a) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.cmp(b),
        }
    });
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn user(n: u8) -> UserId {
        let pk = SigningKey::from_bytes(&seed(n)).verifying_key();
        UserId::from_key_string(data_encoding::HEXLOWER.encode(pk.as_bytes()))
    }
    fn genesis(admins: &[u8]) -> Genesis {
        Genesis {
            workspace_id: crate::ids::WorkspaceId::mint(&crate::ids::SystemUlidSource),
            founding_admins: admins.iter().map(|n| user(*n)).collect(),
        }
    }

    #[test]
    fn founder_is_admin_and_can_add_members() {
        let g = genesis(&[1]);
        let add = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![],
        );
        let st = replay(&g, &[add]);
        assert!(st.is_admin(&user(1)));
        assert!(st.is_member(&user(2)));
        assert!(!st.is_admin(&user(2)));
        assert_eq!(st.len(), 2);
    }

    #[test]
    fn non_admin_ops_are_rejected() {
        let g = genesis(&[1]);
        // user 2 (not a member) tries to add user 3 — unauthorized, ignored.
        let forged = sign_op(
            &seed(2),
            &AclOp::AddMember {
                key: user(3),
                role: Role::Admin,
            },
            vec![],
        );
        let st = replay(&g, &[forged]);
        assert!(
            !st.is_member(&user(3)),
            "an unauthorized op must not take effect"
        );
        assert!(!st.is_member(&user(2)));
    }

    #[test]
    fn forged_signature_is_rejected() {
        let g = genesis(&[1]);
        let mut op = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![],
        );
        op.sig[0] ^= 0xff; // tamper
        let st = replay(&g, &[op]);
        assert!(!st.is_member(&user(2)), "a bad signature must be rejected");
    }

    #[test]
    fn remove_wins_over_concurrent_add() {
        // Founder adds B (op1). Then two concurrent branches off op1: admin
        // removes B (rm), and admin re-adds B (add2) — both children of op1, so
        // concurrent. Remove-wins ⇒ B is not a member.
        let g = genesis(&[1]);
        let op1 = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![],
        );
        let h1 = op1.hash();
        let rm = sign_op(
            &seed(1),
            &AclOp::RemoveMember { key: user(2) },
            vec![h1.clone()],
        );
        let add2 = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![h1.clone()],
        );
        let st = replay(&g, &[op1, rm, add2]);
        assert!(!st.is_member(&user(2)), "remove-wins over a concurrent add");
    }

    #[test]
    fn re_add_after_remove_restores_membership() {
        // Sequential: add, remove, then re-add whose parent is the remove.
        let g = genesis(&[1]);
        let op1 = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![],
        );
        let rm = sign_op(
            &seed(1),
            &AclOp::RemoveMember { key: user(2) },
            vec![op1.hash()],
        );
        let readd = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![rm.hash()],
        );
        let st = replay(&g, &[op1, rm, readd]);
        assert!(
            st.is_member(&user(2)),
            "a causally-later re-add restores membership"
        );
    }

    #[test]
    fn replay_is_order_independent() {
        let g = genesis(&[1]);
        let op1 = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Admin,
            },
            vec![],
        );
        let op2 = sign_op(
            &seed(2), // user 2 is now an admin
            &AclOp::AddMember {
                key: user(3),
                role: Role::Member,
            },
            vec![op1.hash()],
        );
        let a = replay(&g, &[op1.clone(), op2.clone()]);
        let b = replay(&g, &[op2, op1]);
        assert_eq!(a, b, "replay is deterministic regardless of delivery order");
        assert!(a.is_member(&user(3)));
    }
}
