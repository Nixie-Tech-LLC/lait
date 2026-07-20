//! Content authority — the second signed hash-DAG plane
//! (`docs/DATA-CONTRACT.md`), domain `lait/authz/1`. Where the membership plane
//! ([`crate::acl`]) answers *who is here*, this plane answers *which
//! high-consequence content actions were validly taken* — starting with issue
//! tombstones (delete/restore).
//!
//! **Placement.** These ops ride an **encrypted** catalog container, not the
//! plaintext membership doc: (a) content references must not leak to blind
//! relays, and (b) old builds never parse the container at all, so new op
//! kinds cannot diverge their replay (the membership-DAG hazard this plane
//! exists to avoid).
//!
//! **At-position authorization.** Each op embeds the membership heads its
//! author observed (`asof`); validation replays membership *up to that frontier*
//! and requires the author to hold **content-write standing** then — `can_write`
//! (Admin or Write grant). A grant-less viewer and an agent are both sealed the
//! key but hold no content authority, so neither can tombstone.
//! Offboarding therefore never resurrects a departed teammate's legitimate
//! deletes.
//!
//! **Why self-declared `asof` is safe here.** At-position authorization alone
//! would let a removed member sign a *new* tombstone against a pre-removal
//! frontier. The **E2EE epoch** is the recency fence:
//! Removal always rotates the workspace key (the app layer's `tracker::member_remove`
//! → `rotate_key`); post-rotation a removed member cannot produce a payload any
//! member will decrypt, so their forged tombstone never enters any member's
//! catalog. The epoch plane is the recency anchor for the authority plane
//! ("encryption is the access control", composed) — strictly stronger than a
//! and it keeps replay a *pure, deterministic* function of
//! the op sets (a live current-membership gate would make two nodes at
//! different sync points disagree). The residual window — a tombstone gossiped
//! *concurrently* with the removal, before rotation propagates — is bounded by
//! that concurrency and remediated with an explicit restore. `asof` head count
//! is capped ([`MAX_ASOF`]) so the embedded frontier can't grow unbounded
//! (Matrix caps `auth_events` at ≤10 for the same reason).
//!
//! **Restore-wins.** Concurrent delete/restore of the same doc resolves to
//! *visible* (a visible issue is recoverable; a hidden one is silent) — the
//! same safety bias as membership's remove-wins, pointed at the safe side.
//! Sequential ops resolve causally as usual, preserving convergence.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::acl::{self, SignedOp};
use crate::genesis::Genesis;
use crate::ids::{DocId, WorkspaceId};
use crate::sigdag::{self, SignedNode};

/// The signing domain for content-authority ops (see [`crate::sigdag`]).
pub const AUTHZ_DOMAIN: &[u8] = b"lait/authz/1";

/// Cap on embedded `asof` membership heads (cf. Matrix's ≤10 `auth_events`).
/// A well-formed op observes a small frontier; more is treated as malformed
/// and the op is ignored (it never authorizes against a padded frontier).
pub const MAX_ASOF: usize = 16;

/// What a content-authority op does. Variants are **append-only** (postcard).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthzAction {
    /// Set (or clear) an issue's deletion tombstone. The catalog row
    /// flag becomes a *cache* of this plane's replay.
    Tombstone { doc: DocId, on: bool },
}

/// A content-authority op: the action plus its advisory wall-clock and the
/// membership frontier it was authorized against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthzOp {
    pub action: AuthzAction,
    /// Advisory unix seconds (non-goal 6: self-asserted, for rendering).
    pub ts: u64,
    /// The membership-plane heads the author observed at signing — the
    /// at-position anchor for the *actor's* standing (module docs).
    pub asof: Vec<String>,
    /// The actor the signing device claims to speak for.
    pub by: crate::ids::ActorId,
    /// The heads of `by`'s actor key-event log the author observed — the
    /// at-position anchor for the *device→actor* binding (lait/actor/1).
    pub actor_asof: Vec<String>,
}

impl AuthzOp {
    fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode authz op")
    }
}

/// Sign an [`AuthzOp`] against this plane's current heads.
pub fn sign_authz(
    seed: &[u8; 32],
    op: &AuthzOp,
    parents: Vec<String>,
    workspace_id: &WorkspaceId,
) -> SignedNode {
    sigdag::sign_node(
        AUTHZ_DOMAIN,
        seed,
        op.encode(),
        parents,
        workspace_id.as_str(),
    )
}

/// The materialized content-authority state after replay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthzState {
    /// Docs whose current resolved tombstone is set.
    tombstoned: BTreeSet<DocId>,
    /// Docs this plane has any authorized verdict for (set or cleared) — used
    /// to distinguish "restored" from "never governed" (legacy adoption).
    governed: BTreeSet<DocId>,
}

impl AuthzState {
    pub fn is_tombstoned(&self, doc: &DocId) -> bool {
        self.tombstoned.contains(doc)
    }
    /// Whether any authorized op governs this doc at all.
    pub fn governs(&self, doc: &DocId) -> bool {
        self.governed.contains(doc)
    }
    pub fn tombstoned(&self) -> impl Iterator<Item = &DocId> {
        self.tombstoned.iter()
    }
}

/// Deterministically replay the content-authority DAG. Verdicts are a pure
/// function of (genesis, membership op set, authz op set): every honest node
/// with the same sets derives the same state.
pub fn replay(
    genesis: &Genesis,
    actor_events: &[crate::actor::SignedEvent],
    membership_ops: &[SignedOp],
    authz_ops: &[SignedNode],
) -> AuthzState {
    let ws = genesis.workspace_id.as_str();
    // Signature-valid nodes; undecodable ops stay as opaque ancestry (the same
    // forward-compat rule as the membership plane).
    let mut nodes: HashMap<String, &SignedNode> = HashMap::new();
    let mut decoded: HashMap<String, Option<AuthzOp>> = HashMap::new();
    for so in authz_ops {
        if !so.verify_sig(AUTHZ_DOMAIN, ws) {
            continue;
        }
        let h = so.hash();
        decoded.insert(h.clone(), postcard::from_bytes(&so.op).ok());
        nodes.insert(h, so);
    }
    let ancestors = sigdag::compute_ancestors(&nodes);
    let order = sigdag::topo_order(&nodes);

    // Membership-at-frontier cache: distinct `asof` sets are few (they only
    // move when membership does), so replaying membership per unique frontier
    // stays cheap at issue-tracker scale.
    let membership_nodes: HashMap<String, &SignedOp> =
        membership_ops.iter().map(|op| (op.hash(), op)).collect();
    let membership_anc = sigdag::compute_ancestors(&membership_nodes);
    let mut at_cache: HashMap<BTreeSet<String>, acl::AclState> = HashMap::new();
    let mut membership_at = |asof: &[String]| -> acl::AclState {
        let key: BTreeSet<String> = asof.iter().cloned().collect();
        if let Some(st) = at_cache.get(&key) {
            return st.clone();
        }
        // The frontier's causal closure over PRESENT membership ops: heads we
        // have not synced yet simply narrow the state (deterministic given the
        // same sets; membership ships first in sync, so this is rare).
        let mut include: BTreeSet<String> = BTreeSet::new();
        for h in &key {
            if membership_nodes.contains_key(h) {
                include.insert(h.clone());
                if let Some(anc) = membership_anc.get(h) {
                    include.extend(anc.iter().cloned());
                }
            }
        }
        let subset: Vec<SignedOp> = membership_ops
            .iter()
            .filter(|op| include.contains(&op.hash()))
            .cloned()
            .collect();
        let st = acl::replay(genesis, actor_events, &subset);
        at_cache.insert(key, st.clone());
        st
    };

    // Actor-plane-at-frontier cache: the device→actor binding resolves
    // identically everywhere for a given `actor_asof`, so replay the actor plane
    // once per distinct frontier rather than once per op (the acl.rs shape).
    let mut actor_cache: HashMap<BTreeSet<String>, crate::actor::ActorPlane> = HashMap::new();
    let mut speaks_for = |device: &crate::ids::UserId,
                          by: &crate::ids::ActorId,
                          asof: &[String]|
     -> bool {
        let key: BTreeSet<String> = asof.iter().cloned().collect();
        actor_cache
            .entry(key)
            .or_insert_with(|| crate::actor::replay_at(&genesis.workspace_id, actor_events, asof))
            .is_device_of(by, device)
    };

    // Authorize + apply in topo order (last-writer per doc), remembering the
    // per-doc authorized ops for the restore-wins override.
    let mut value: BTreeMap<DocId, bool> = BTreeMap::new();
    let mut governed: BTreeSet<DocId> = BTreeSet::new();
    let mut deletes: BTreeMap<DocId, Vec<String>> = BTreeMap::new();
    let mut restores: BTreeMap<DocId, Vec<String>> = BTreeMap::new();
    for h in &order {
        let Some(op) = &decoded[h] else { continue };
        if op.asof.len() > MAX_ASOF || op.actor_asof.len() > crate::actor::MAX_ACTOR_ASOF {
            continue; // malformed padded frontier — ignored, never authorized
        }
        // The signing device must speak for the claimed actor at the declared
        // actor-log frontier (device→actor binding at position)...
        let author = &nodes[h].author;
        if !speaks_for(author, &op.by, &op.actor_asof) {
            continue;
        }
        // ...and that actor must hold **content-write standing** at the op's
        // membership position (`can_write` = Admin or Write grant). This is the
        // cross-replica enforcement of the view-only member: a grant-less viewer
        // — like an agent or a non-member-at-position — has no content
        // authority, so its tombstone is void on every replica, not merely
        // refused on the author's own node.
        let st = membership_at(&op.asof);
        if !st.can_write(&op.by) {
            continue;
        }
        match &op.action {
            AuthzAction::Tombstone { doc, on } => {
                value.insert(doc.clone(), *on);
                governed.insert(doc.clone());
                if *on {
                    deletes.entry(doc.clone()).or_default().push(h.clone());
                } else {
                    restores.entry(doc.clone()).or_default().push(h.clone());
                }
            }
        }
    }

    // Restore-wins override: a doc with an authorized restore that no
    // authorized delete causally succeeds stays visible, even if a concurrent
    // delete landed later in topo order.
    for (doc, rs) in &restores {
        let ds = deletes.get(doc).cloned().unwrap_or_default();
        let alive = rs.iter().any(|r| {
            !ds.iter()
                .any(|d| ancestors.get(d).map(|anc| anc.contains(r)).unwrap_or(false))
        });
        if alive {
            value.insert(doc.clone(), false);
        }
    }

    let tombstoned = value
        .into_iter()
        .filter(|(_, on)| *on)
        .map(|(d, _)| d)
        .collect();
    AuthzState {
        tombstoned,
        governed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{sign_op, AclAction, AclOp, Grant};
    use crate::actor::{self, SignedEvent};
    use crate::ids::{ActorId, SystemUlidSource, WorkspaceId};
    use std::collections::BTreeMap;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn doc() -> DocId {
        DocId::mint(&SystemUlidSource)
    }
    fn incept(n: u8, w: &WorkspaceId) -> (SignedEvent, ActorId) {
        actor::incept_single(&seed(n), w, [n; 16], [n ^ 0x55; 16], None)
    }

    /// A fixture: a genesis founded by actor(founder), plus inceptions for each
    /// listed seed available on the actor plane. Each seed n → its actor + the
    /// actor's inception head (its single-device `actor_asof` frontier).
    struct Fx {
        g: Genesis,
        events: Vec<SignedEvent>,
        actors: BTreeMap<u8, (ActorId, String)>,
    }
    fn fx(founder: u8, others: &[u8]) -> Fx {
        let w = WorkspaceId::mint(&SystemUlidSource);
        let mut events = Vec::new();
        let mut actors = BTreeMap::new();
        for n in std::iter::once(founder).chain(others.iter().copied()) {
            let (ev, id) = incept(n, &w);
            actors.insert(n, (id, ev.hash()));
            events.push(ev);
        }
        Fx {
            g: Genesis {
                workspace_id: w,
                founding_actors: vec![actors[&founder].0.clone()],
                salt: [0u8; 16],
                recovery_root: [0u8; 32],
            },
            events,
            actors,
        }
    }
    impl Fx {
        fn ws(&self) -> &WorkspaceId {
            &self.g.workspace_id
        }
        fn actor(&self, n: u8) -> ActorId {
            self.actors[&n].0.clone()
        }
        fn acl(&self, author: u8, by: u8, action: AclAction, parents: Vec<String>) -> SignedOp {
            let (by_actor, head) = self.actors[&by].clone();
            sign_op(
                &seed(author),
                &AclOp {
                    action,
                    by: by_actor,
                    actor_asof: vec![head],
                    nonce: None,
                },
                parents,
                self.ws(),
            )
        }
        fn add_member(&self, subject: u8, grants: Vec<Grant>, parents: Vec<String>) -> SignedOp {
            self.acl(
                1,
                1,
                AclAction::AddMember {
                    actor: self.actor(subject),
                    grants,
                },
                parents,
            )
        }
        /// A tombstone op authored by device `author` claiming actor `by`, whose
        /// device→actor binding resolves at `by`'s inception frontier.
        fn tomb(
            &self,
            author: u8,
            by: u8,
            doc: &DocId,
            on: bool,
            asof: Vec<String>,
            parents: Vec<String>,
        ) -> SignedNode {
            let (by_actor, head) = self.actors[&by].clone();
            sign_authz(
                &seed(author),
                &AuthzOp {
                    action: AuthzAction::Tombstone {
                        doc: doc.clone(),
                        on,
                    },
                    ts: 100,
                    asof,
                    by: by_actor,
                    actor_asof: vec![head],
                },
                parents,
                self.ws(),
            )
        }
        fn replay(&self, membership: &[SignedOp], authz: &[SignedNode]) -> AuthzState {
            replay(&self.g, &self.events, membership, authz)
        }
    }

    #[test]
    fn member_delete_is_honored_stranger_and_agent_are_not() {
        // founder=1, member=2, agent=10, stranger=9.
        let f = fx(1, &[2, 10, 9]);
        let add_b = f.add_member(2, vec![Grant::Write], vec![]);
        let add_agent = f.acl(
            2,
            2,
            AclAction::AddAgent { actor: f.actor(10) },
            vec![add_b.hash()],
        );
        let heads = vec![add_agent.hash()];
        let membership = vec![add_b, add_agent];

        let d1 = doc();
        let d2 = doc();
        let d3 = doc();
        let by_member = f.tomb(2, 2, &d1, true, heads.clone(), vec![]);
        let by_stranger = f.tomb(9, 9, &d2, true, heads.clone(), vec![]);
        let by_agent = f.tomb(10, 10, &d3, true, heads, vec![]);
        let st = f.replay(&membership, &[by_member, by_stranger, by_agent]);
        assert!(st.is_tombstoned(&d1), "a member's delete stands");
        assert!(!st.is_tombstoned(&d2), "a stranger's delete is void");
        assert!(
            !st.is_tombstoned(&d3),
            "an agent holds no content authority"
        );
        assert!(st.governs(&d1) && !st.governs(&d2) && !st.governs(&d3));
    }

    #[test]
    fn a_view_only_member_cannot_tombstone() {
        // A member with empty grants (a viewer) is sealed the key but holds no
        // content authority: `can_write` is false, so its tombstone is void on
        // every replica — not merely refused on its own node.
        let f = fx(1, &[2]);
        let add_viewer = f.add_member(2, vec![], vec![]); // sealed in, zero grants
        let d = doc();
        let del = f.tomb(2, 2, &d, true, vec![add_viewer.hash()], vec![]);
        let st = f.replay(&[add_viewer], &[del]);
        assert!(
            !st.is_tombstoned(&d) && !st.governs(&d),
            "a viewer's delete carries no content authority"
        );

        // Control: the same actor, granted Write, deletes validly.
        let f = fx(1, &[2]);
        let add_writer = f.add_member(2, vec![Grant::Write], vec![]);
        let d = doc();
        let del = f.tomb(2, 2, &d, true, vec![add_writer.hash()], vec![]);
        let st = f.replay(&[add_writer], &[del]);
        assert!(
            st.is_tombstoned(&d),
            "a Write-granted member's delete stands"
        );
    }

    #[test]
    fn offboarding_does_not_resurrect_past_deletes() {
        let f = fx(1, &[2]);
        let add_b = f.add_member(2, vec![Grant::Write], vec![]);
        let rm_b = f.acl(
            1,
            1,
            AclAction::RemoveMember { actor: f.actor(2) },
            vec![add_b.hash()],
        );
        let d = doc();
        let del = f.tomb(2, 2, &d, true, vec![add_b.hash()], vec![]);
        let st = f.replay(&[add_b, rm_b], &[del]);
        assert!(
            st.is_tombstoned(&d),
            "a delete authorized at its causal position survives the author's later removal"
        );
    }

    #[test]
    fn an_asof_where_the_author_was_never_valid_is_void() {
        let f = fx(1, &[9]);
        let d = doc();
        let del = f.tomb(9, 9, &d, true, vec![], vec![]);
        let st = f.replay(&[], &[del]);
        assert!(!st.is_tombstoned(&d));
    }

    #[test]
    fn restore_wins_over_concurrent_delete() {
        let f = fx(1, &[]);
        let d = doc();
        let del1 = f.tomb(1, 1, &d, true, vec![], vec![]);
        let restore = f.tomb(1, 1, &d, false, vec![], vec![del1.hash()]);
        let redelete = f.tomb(1, 1, &d, true, vec![], vec![del1.hash()]);
        let st = f.replay(&[], &[del1, restore, redelete]);
        assert!(
            !st.is_tombstoned(&d),
            "concurrent delete/restore resolves to visible (restore-wins)"
        );
    }

    #[test]
    fn sequential_redelete_after_restore_stands() {
        let f = fx(1, &[]);
        let d = doc();
        let del1 = f.tomb(1, 1, &d, true, vec![], vec![]);
        let restore = f.tomb(1, 1, &d, false, vec![], vec![del1.hash()]);
        let del2 = f.tomb(1, 1, &d, true, vec![], vec![restore.hash()]);
        let st = f.replay(&[], &[del1, restore, del2]);
        assert!(
            st.is_tombstoned(&d),
            "a causally-later delete succeeds the restore"
        );
    }

    #[test]
    fn replay_is_order_independent() {
        let f = fx(1, &[]);
        let d = doc();
        let del = f.tomb(1, 1, &d, true, vec![], vec![]);
        let restore = f.tomb(1, 1, &d, false, vec![], vec![del.hash()]);
        let a = f.replay(&[], &[del.clone(), restore.clone()]);
        let b = f.replay(&[], &[restore, del]);
        assert_eq!(a, b);
        assert!(!a.is_tombstoned(&d));
    }

    #[test]
    fn device_not_speaking_for_claimed_actor_is_void() {
        // Device 9 authors a tombstone CLAIMING the founder's actor: the
        // device→actor binding fails, so the op is void even though the claimed
        // actor is a member.
        let f = fx(1, &[9]);
        let d = doc();
        let (founder_actor, founder_head) = f.actors[&1].clone();
        let forged = sign_authz(
            &seed(9),
            &AuthzOp {
                action: AuthzAction::Tombstone {
                    doc: d.clone(),
                    on: true,
                },
                ts: 100,
                asof: vec![],
                by: founder_actor,
                actor_asof: vec![founder_head],
            },
            vec![],
            f.ws(),
        );
        let st = f.replay(&[], &[forged]);
        assert!(
            !st.is_tombstoned(&d),
            "a device that is not the actor's is void"
        );
    }

    #[test]
    fn cross_plane_signature_reuse_is_rejected() {
        let f = fx(1, &[2]);
        let acl_node = f.acl(1, 1, AclAction::RemoveMember { actor: f.actor(2) }, vec![]);
        assert!(acl_node.verify_sig(crate::acl::ACL_DOMAIN, f.ws().as_str()));
        assert!(
            !acl_node.verify_sig(AUTHZ_DOMAIN, f.ws().as_str()),
            "planes are mutually unusable"
        );
    }
}
