//! The shared **signed hash-DAG envelope** — the Regime-C primitive
//! (`docs/DATA-CONTRACT.md`) the authority planes ride:
//!
//! * membership / ACL ([`crate::acl`], domain `lait/aclop/1`, plaintext-synced),
//! * content authority ([`crate::authz`], domain `lait/authz/1`, encrypted).
//!
//! One node = one signed op: ed25519 by `author` over
//! `blake3(domain ‖ op-bytes ‖ author ‖ sorted(parents) ‖ workspace-id)`.
//! Binding `parents` closes the re-parent revocation bypass; binding the
//! workspace id closes cross-workspace replay; the domain string keeps the two
//! planes' signatures mutually unusable. The content-address (`hash`) is
//! deliberately domain- and workspace-free so it stays stable for DAG linking.
//!
//! Wire compatibility: [`SignedNode`] is field-for-field the shape `acl.rs`
//! shipped as `SignedOp` (postcard positional), and the `lait/aclop/1` payload
//! is byte-identical — every op signed before this module existed still
//! verifies.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::ids::UserId;

/// A signed op with its causal parents. `op` is the plane's canonical op bytes
/// (postcard); `parents` are op hashes within the same plane's DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedNode {
    pub op: Vec<u8>,
    pub author: UserId,
    pub sig: Vec<u8>,
    pub parents: Vec<String>,
}

/// The 32-byte message a node's signature covers — public so a **threshold
/// group** (FROST) can sign the exact bytes [`SignedNode::verify_sig`] checks,
/// then assemble the node with [`assemble_signed`].
pub fn payload_to_sign(
    domain: &[u8],
    op: &[u8],
    author: &UserId,
    parents: &[String],
    workspace_id: &str,
) -> [u8; 32] {
    signing_payload(domain, op, author, parents, workspace_id)
}

/// Assemble a [`SignedNode`] from an externally produced signature (e.g. a FROST
/// group signature) over [`payload_to_sign`], with the group public key as author.
pub fn assemble_signed(
    op: Vec<u8>,
    author: UserId,
    sig: Vec<u8>,
    parents: Vec<String>,
) -> SignedNode {
    SignedNode {
        op,
        author,
        sig,
        parents,
    }
}

/// The canonical bytes a node's signature covers.
fn signing_payload(
    domain: &[u8],
    op: &[u8],
    author: &UserId,
    parents: &[String],
    workspace_id: &str,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
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

impl SignedNode {
    /// The content-address of this node (its hash-DAG id): op ‖ author ‖
    /// sorted(parents). Stable across domains/workspaces by design — the
    /// signature, not the address, carries those bindings.
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

    /// Verify the signature under `domain` for `workspace_id`. Fails if the op
    /// was re-parented, re-authored, lifted from another workspace, or moved
    /// between planes.
    pub fn verify_sig(&self, domain: &[u8], workspace_id: &str) -> bool {
        let Some(pk_bytes) = hex32(self.author.as_str()) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.sig) else {
            return false;
        };
        let payload = signing_payload(domain, &self.op, &self.author, &self.parents, workspace_id);
        vk.verify(&payload, &sig).is_ok()
    }
}

/// Sign canonical op bytes with the author's ed25519 seed, given the plane's
/// current heads as parents. The author is derived from the seed.
pub fn sign_node(
    domain: &[u8],
    seed: &[u8; 32],
    op_bytes: Vec<u8>,
    parents: Vec<String>,
    workspace_id: &str,
) -> SignedNode {
    let sk = SigningKey::from_bytes(seed);
    let author =
        UserId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()));
    let payload = signing_payload(domain, &op_bytes, &author, &parents, workspace_id);
    let sig: Signature = sk.sign(&payload);
    SignedNode {
        op: op_bytes,
        author,
        sig: sig.to_bytes().to_vec(),
        parents,
    }
}

/// The preimage a detached message signature covers:
/// `blake3(domain ‖ workspace_id ‖ author ‖ msg)`. Same discipline as
/// [`signing_payload`]: the `domain` makes each use-site's signatures mutually
/// unusable (a gossip signature can never verify as an invite, regardless of
/// postcard layout), and `workspace_id` closes cross-workspace replay (a message
/// signed for one topic fails verification on another).
fn message_payload(domain: &[u8], workspace_id: &str, author: &UserId, msg: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(workspace_id.as_bytes());
    h.update(author.as_str().as_bytes());
    h.update(msg);
    *h.finalize().as_bytes()
}

/// Sign arbitrary bytes with an ed25519 seed — a **detached** signature for the
/// transport-authenticity plane (signed gossip, invite grants) that does not ride
/// the hash-DAG. `domain` separates use-sites and `workspace_id` binds the message
/// to its topic (see the private `message_payload` helper). Returns the seed's `author` and the
/// 64-byte signature. lait's own primitive — no scaffold signing type involved.
pub fn sign_message(
    domain: &[u8],
    workspace_id: &str,
    seed: &[u8; 32],
    msg: &[u8],
) -> (UserId, [u8; 64]) {
    let sk = SigningKey::from_bytes(seed);
    let author =
        UserId::from_key_string(data_encoding::HEXLOWER.encode(sk.verifying_key().as_bytes()));
    let payload = message_payload(domain, workspace_id, &author, msg);
    (author, sk.sign(&payload).to_bytes())
}

/// Verify a [`sign_message`] detached signature under the same `domain` and
/// `workspace_id`: `sig` covers `msg` by `author`. Rejects a malformed author or
/// signature without panicking, and any mismatch of domain or workspace.
pub fn verify_message(
    domain: &[u8],
    workspace_id: &str,
    author: &UserId,
    msg: &[u8],
    sig: &[u8; 64],
) -> bool {
    let Some(pk) = hex32(author.as_str()) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let payload = message_payload(domain, workspace_id, author, msg);
    vk.verify(&payload, &Signature::from_bytes(sig)).is_ok()
}

/// Transitive causal ancestors of each node, over present parents only.
pub fn compute_ancestors(
    nodes: &std::collections::HashMap<String, &SignedNode>,
) -> std::collections::HashMap<String, std::collections::HashSet<String>> {
    let mut out = std::collections::HashMap::new();
    for (h, node) in nodes {
        let mut anc = std::collections::HashSet::new();
        let mut stack: Vec<String> = node.parents.clone();
        while let Some(p) = stack.pop() {
            if let Some(pn) = nodes.get(&p) {
                if anc.insert(p.clone()) {
                    stack.extend(pn.parents.clone());
                }
            }
        }
        out.insert(h.clone(), anc);
    }
    out
}

/// Deterministic topological order (Kahn) over the present-parent DAG; ready
/// nodes emit in hash order, so the result depends only on the node set —
/// required for E2EE (every honest node must derive the same state).
/// Parent-cycle remnants (malformed input) append in hash order to keep the
/// order total and deterministic.
pub fn topo_order(nodes: &std::collections::HashMap<String, &SignedNode>) -> Vec<String> {
    use std::collections::{BTreeSet, HashMap};
    let mut indeg: HashMap<String, usize> = nodes.keys().map(|h| (h.clone(), 0)).collect();
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for (h, node) in nodes {
        for p in &node.parents {
            if nodes.contains_key(p) {
                *indeg.get_mut(h).unwrap() += 1;
                children.entry(p.clone()).or_default().push(h.clone());
            }
        }
    }
    let mut ready: BTreeSet<String> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(h, _)| h.clone())
        .collect();
    let mut order: Vec<String> = Vec::with_capacity(nodes.len());
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
    if order.len() < nodes.len() {
        let mut rest: Vec<String> = nodes
            .keys()
            .filter(|h| !order.contains(*h))
            .cloned()
            .collect();
        rest.sort();
        order.extend(rest);
    }
    order
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    // Reject non-hex bytes before slicing: `author` is an unvalidated String on
    // an attacker-supplied node, and a 64-byte non-ASCII value would panic on a
    // char-boundary slice — crashing `verify_sig` on every replica that syncs it.
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &[u8] = b"lait/test/1";

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn sign_verify_roundtrip_and_bindings() {
        let node = sign_node(DOMAIN, &seed(1), b"op".to_vec(), vec!["p1".into()], "ws_a");
        assert!(node.verify_sig(DOMAIN, "ws_a"));
        assert!(!node.verify_sig(DOMAIN, "ws_b"), "workspace-bound");
        assert!(!node.verify_sig(b"lait/other/1", "ws_a"), "domain-bound");
        let mut reparented = node.clone();
        reparented.parents = vec!["p2".into()];
        assert!(!reparented.verify_sig(DOMAIN, "ws_a"), "parent-bound");
    }

    #[test]
    fn aclop_v1_payload_is_byte_identical() {
        // The envelope must keep verifying every op acl.rs signed before the
        // extraction: same domain, same field order, same payload bytes.
        let node = sign_node(
            b"lait/aclop/1",
            &seed(1),
            b"legacy-op-bytes".to_vec(),
            vec![],
            "ws_x",
        );
        assert!(node.verify_sig(b"lait/aclop/1", "ws_x"));
    }

    #[test]
    fn detached_message_signing_roundtrips_and_binds_domain_and_workspace() {
        const G: &[u8] = b"lait/gossip/1";
        const I: &[u8] = b"lait/invite/1";
        let msg = b"announce: head moved";
        let (author, sig) = sign_message(G, "ws_a", &seed(5), msg);
        assert!(verify_message(G, "ws_a", &author, msg, &sig));
        // Wrong message, author, or a flipped byte fail.
        assert!(!verify_message(G, "ws_a", &author, b"other", &sig));
        let (other, _) = sign_message(G, "ws_a", &seed(6), msg);
        assert!(!verify_message(G, "ws_a", &other, msg, &sig));
        let mut bad = sig;
        bad[0] ^= 0xff;
        assert!(!verify_message(G, "ws_a", &author, msg, &bad));
        // Domain separation: a gossip signature is not usable as an invite …
        assert!(!verify_message(I, "ws_a", &author, msg, &sig));
        // … and cross-workspace replay fails: same bytes, different topic.
        assert!(!verify_message(G, "ws_b", &author, msg, &sig));
    }

    #[test]
    fn topo_is_deterministic_and_respects_ancestry() {
        let a = sign_node(DOMAIN, &seed(1), b"a".to_vec(), vec![], "ws");
        let b = sign_node(DOMAIN, &seed(1), b"b".to_vec(), vec![a.hash()], "ws");
        let c = sign_node(DOMAIN, &seed(1), b"c".to_vec(), vec![a.hash()], "ws");
        let mut nodes = std::collections::HashMap::new();
        for n in [&a, &b, &c] {
            nodes.insert(n.hash(), n);
        }
        let order = topo_order(&nodes);
        assert_eq!(order.len(), 3);
        assert_eq!(order[0], a.hash(), "root first");
        let anc = compute_ancestors(&nodes);
        assert!(anc[&b.hash()].contains(&a.hash()));
        assert!(
            !anc[&b.hash()].contains(&c.hash()),
            "siblings not ancestors"
        );
    }
}
