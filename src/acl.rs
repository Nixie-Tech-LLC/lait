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

use crate::ids::{UserId, WorkspaceId};
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
/// bytes; `sig` is ed25519 by `author` over a payload that binds the op bytes,
/// the author, the (sorted) `parents`, **and** the workspace id — so a valid
/// signature cannot be re-parented (which would defeat remove-wins revocation)
/// or replayed into another workspace. `parents` are op hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOp {
    pub op: Vec<u8>,
    pub author: UserId,
    pub sig: Vec<u8>,
    pub parents: Vec<String>,
}

/// The canonical bytes an op's signature covers: domain ‖ op ‖ author ‖
/// sorted(parents) ‖ workspaceId. Binding `parents` closes the revocation
/// bypass (a re-parented copy of a valid op no longer verifies); binding the
/// workspace id prevents cross-workspace op replay. `workspace_id` is supplied
/// by context (the signer's / genesis's workspace) and is not transmitted in
/// `SignedOp`, so this does not change the op's wire shape.
fn signing_payload(op: &[u8], author: &UserId, parents: &[String], workspace_id: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"groupchat/aclop/1");
    h.update(op);
    h.update(author.as_str().as_bytes());
    let mut ps = parents.to_vec();
    ps.sort();
    for p in &ps {
        h.update(p.as_bytes());
    }
    h.update(workspace_id.as_bytes());
    *h.finalize().as_bytes()
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
    /// Verify the signature against the canonical payload (op ‖ author ‖
    /// sorted(parents) ‖ `workspace_id`). Fails if the op was re-parented,
    /// re-authored, or lifted from another workspace.
    fn verify_sig(&self, workspace_id: &str) -> bool {
        let Some(pk_bytes) = hex32(self.author.as_str()) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.sig) else {
            return false;
        };
        let payload = signing_payload(&self.op, &self.author, &self.parents, workspace_id);
        vk.verify(&payload, &sig).is_ok()
    }
}

/// Sign an [`AclOp`] with the author's ed25519 seed, given the current heads as
/// parents and the workspace id (S§6). The signature binds all of them, so a
/// valid op cannot be re-parented or replayed across workspaces. The author is
/// derived from the seed.
pub fn sign_op(
    seed: &[u8; 32],
    op: &AclOp,
    parents: Vec<String>,
    workspace_id: &WorkspaceId,
) -> SignedOp {
    let sk = SigningKey::from_bytes(seed);
    let author =
        UserId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()));
    let op_bytes = op.encode();
    let payload = signing_payload(&op_bytes, &author, &parents, workspace_id.as_str());
    let sig: Signature = sk.sign(&payload);
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
    let ws = genesis.workspace_id.as_str();
    for so in ops {
        if !so.verify_sig(ws) {
            continue;
        }
        if let Some(op) = so.decode_op() {
            by_hash.insert(so.hash(), (so, op));
        }
    }

    // Transitive causal ancestors of each op (over present parents only).
    let ancestors = compute_ancestors(&by_hash);

    // Topological order (ancestors before descendants; concurrent ops ordered by
    // hash). Deterministic and independent of `by_hash`'s (randomized) iteration
    // order, so every honest node computes the same membership from the same op
    // set — required for E2EE (all nodes must seal the next epoch key to the same
    // recipient set).
    let order = topo_order(&by_hash);

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

/// Deterministic topological sort (Kahn's algorithm) over the present-parent
/// DAG. Ready nodes are emitted in hash order, so the result is a total order
/// that depends only on the op set — never on `by_hash`'s randomized iteration
/// order. A previous `sort_by` comparator here was non-transitive on mixed
/// ancestry/hash pairs, which — combined with the HashMap-seeded input order —
/// let two honest nodes derive different orders (and thus different membership).
fn topo_order(by_hash: &HashMap<String, (&SignedOp, AclOp)>) -> Vec<String> {
    // Indegree over PRESENT parents only; children adjacency for decrement.
    let mut indeg: HashMap<String, usize> = by_hash.keys().map(|h| (h.clone(), 0)).collect();
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for (h, (so, _)) in by_hash {
        for p in &so.parents {
            if by_hash.contains_key(p) {
                *indeg.get_mut(h).unwrap() += 1;
                children.entry(p.clone()).or_default().push(h.clone());
            }
        }
    }
    // Ready set kept sorted by hash (BTreeSet) for a deterministic tie-break.
    let mut ready: BTreeSet<String> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(h, _)| h.clone())
        .collect();
    let mut order: Vec<String> = Vec::with_capacity(by_hash.len());
    while let Some(h) = ready.iter().next().cloned() {
        ready.remove(&h);
        order.push(h.clone());
        if let Some(cs) = children.get(&h) {
            let mut cs = cs.clone();
            cs.sort();
            for c in cs {
                let d = indeg.get_mut(&c).unwrap();
                *d -= 1;
                if *d == 0 {
                    ready.insert(c);
                }
            }
        }
    }
    // Any remaining nodes sit on a parent-cycle (malformed input); append them in
    // hash order so the result stays deterministic and total.
    if order.len() < by_hash.len() {
        let mut rest: Vec<String> = by_hash
            .keys()
            .filter(|h| !order.contains(*h))
            .cloned()
            .collect();
        rest.sort();
        order.extend(rest);
    }
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
            &g.workspace_id,
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
            &g.workspace_id,
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
            &g.workspace_id,
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
            &g.workspace_id,
        );
        let h1 = op1.hash();
        let rm = sign_op(
            &seed(1),
            &AclOp::RemoveMember { key: user(2) },
            vec![h1.clone()],
            &g.workspace_id,
        );
        let add2 = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![h1.clone()],
            &g.workspace_id,
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
            &g.workspace_id,
        );
        let rm = sign_op(
            &seed(1),
            &AclOp::RemoveMember { key: user(2) },
            vec![op1.hash()],
            &g.workspace_id,
        );
        let readd = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![rm.hash()],
            &g.workspace_id,
        );
        let st = replay(&g, &[op1, rm, readd]);
        assert!(
            st.is_member(&user(2)),
            "a causally-later re-add restores membership"
        );
    }

    #[test]
    fn revocation_holds_against_reparented_signed_add() {
        // Regression for the validation-found CRITICAL: an evicted member (no
        // admin key) tries to defeat remove-wins by lifting the admin's still-
        // valid signed AddMember op and re-parenting the copy to descend from the
        // removal. Because the signature now binds `parents` (+ workspace id), the
        // re-parented copy fails verification and is dropped by replay.
        let g = genesis(&[1]); // user1 = founding admin
        let add_orig = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Member,
            },
            vec![],
            &g.workspace_id,
        );
        let rm = sign_op(
            &seed(1),
            &AclOp::RemoveMember { key: user(2) },
            vec![add_orig.hash()],
            &g.workspace_id,
        );
        // Baseline: after add + remove, B is correctly gone.
        let base = replay(&g, &[add_orig.clone(), rm.clone()]);
        assert!(!base.is_member(&user(2)), "baseline: B removed");

        // ATTACK — reuse the admin's op bytes/author/sig verbatim; only mutate the
        // `parents` to point AFTER the removal.
        let add_replay = SignedOp {
            op: add_orig.op.clone(),
            author: add_orig.author.clone(),
            sig: add_orig.sig.clone(),
            parents: vec![rm.hash()],
        };
        assert!(
            !add_replay.verify_sig(g.workspace_id.as_str()),
            "re-parented copy must FAIL signature verification (sig binds parents)"
        );
        let st = replay(&g, &[add_orig, rm, add_replay]);
        assert!(
            !st.is_member(&user(2)),
            "revocation must hold: the re-parented op is rejected and B stays removed"
        );
    }

    #[test]
    fn op_from_another_workspace_is_rejected() {
        // Regression: a valid op signed for workspace A must not be honored when
        // replayed against workspace B's genesis (the signature binds the ws id).
        let g_a = genesis(&[1]);
        let mut g_b = genesis(&[1]);
        // Distinct workspace id, same founding admin key.
        while g_b.workspace_id == g_a.workspace_id {
            g_b.workspace_id = crate::ids::WorkspaceId::mint(&crate::ids::SystemUlidSource);
        }
        let op = sign_op(
            &seed(1),
            &AclOp::AddMember {
                key: user(2),
                role: Role::Admin,
            },
            vec![],
            &g_a.workspace_id, // signed for A
        );
        let st_b = replay(&g_b, &[op]);
        assert!(
            !st_b.is_member(&user(2)),
            "an op signed for workspace A must not take effect in workspace B"
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
            &g.workspace_id,
        );
        let op2 = sign_op(
            &seed(2), // user 2 is now an admin
            &AclOp::AddMember {
                key: user(3),
                role: Role::Member,
            },
            vec![op1.hash()],
            &g.workspace_id,
        );
        let a = replay(&g, &[op1.clone(), op2.clone()]);
        let b = replay(&g, &[op2, op1]);
        assert_eq!(a, b, "replay is deterministic regardless of delivery order");
        assert!(a.is_member(&user(3)));
    }
}
