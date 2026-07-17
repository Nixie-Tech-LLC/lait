//! Membership & access control — the signed ACL op-graph (S§6), **actor-keyed**
//! since the `lait/actor/1` cutover.
//!
//! **What changed at the cutover.** Ops used to bind a raw device key
//! (`UserId`); a member *was* a key. Membership now binds an [`ActorId`] — a
//! self-certifying identity over a self-managed set of device keys
//! ([`crate::actor`]). Every op is still signed by exactly one device (the
//! [`SignedNode`] envelope is unchanged), but authority resolves through one
//! indirection: each op **declares the actor it speaks for** (`by`) and the
//! frontier of that actor's key-event log its author observed (`actor_asof`),
//! and replay verifies the signing device belonged to that actor *at that
//! frontier* before weighing the actor's standing. This keeps replay a pure
//! function of `(genesis, actor events, acl ops)` — never a current-state gate
//! — so replicas at different sync points converge (the [`crate::authz`]
//! doctrine, applied one layer down). Authors MUST land any actor events an
//! op's frontier references in the same commit as the op (see
//! `MembershipDoc::add_actor_event`), so no replica ever holds an op whose
//! frontier it cannot resolve.
//!
//! **Grants, not roles.** Standing is an extensible capability set
//! ([`Grant`]): `Admin` (membership authority) and `Write` (content
//! authority). A member with **no grants is view-only** — sealed the key,
//! zero write standing. Agents remain the structural case: sealed but
//! grant-less, sponsored, and their standing dies with the sponsor.
//!
//! **Names never enter this plane.** The only synced identity facts are keys,
//! actors, and signed ops; petnames live in each node's local alias store.
//!
//! Trust maximum unchanged: replay is deterministic (topo order, remove-wins,
//! sponsor cascade), undecodable ops are opaque DAG nodes (ancestry, no
//! state), and the E2EE epoch remains the recency fence (removal rotates the
//! workspace key so a removed actor's devices cannot read forward).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::actor::{self, ActorPlane, SignedEvent};
use crate::ids::{ActorId, UserId, WorkspaceId};
use crate::sigdag::{self, SignedNode};
use crate::store::Genesis;

pub const ACL_DOMAIN: &[u8] = b"lait/aclop/1";

/// A signed membership op — the shared envelope under this plane's domain.
pub type SignedOp = SignedNode;

/// A capability grant. Variants are **append-only** (postcard positional) —
/// this is the extensible carrier future capabilities ride (finer write
/// scopes, service grants) without another op-shape cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Grant {
    /// Membership authority: add/remove members, set grants, rotate the key.
    Admin,
    /// Content authority: author high-consequence content ops (authz plane).
    Write,
}

/// What a membership op does. Variants are **append-only**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclAction {
    AddMember {
        actor: ActorId,
        grants: Vec<Grant>,
    },
    RemoveMember {
        actor: ActorId,
    },
    SetGrants {
        actor: ActorId,
        grants: Vec<Grant>,
    },
    /// Sponsor an agent actor (contract §3.4). The sponsor is the op's `by`
    /// actor; the agent's membership is derived, and dies, with them.
    AddAgent {
        actor: ActorId,
    },
}

impl AclAction {
    pub fn actor(&self) -> &ActorId {
        match self {
            AclAction::AddMember { actor, .. }
            | AclAction::RemoveMember { actor }
            | AclAction::SetGrants { actor, .. }
            | AclAction::AddAgent { actor } => actor,
        }
    }
}

/// A membership op: the action, the actor its author claims to be, and the
/// frontier of that actor's key-event log the author observed — the
/// at-position anchor for device→actor resolution (module docs; cf.
/// [`crate::authz`]'s membership `asof`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclOp {
    pub action: AclAction,
    /// The actor the signing device speaks for.
    pub by: ActorId,
    /// Heads of `by`'s key-event log at signing (≤ [`actor::MAX_ACTOR_ASOF`]).
    pub actor_asof: Vec<String>,
    /// For an `AddMember` admitting via a single-use invite, the nonce it spent.
    /// Binding it into the signed op makes single-use convergent: [`replay`]
    /// admits exactly one actor per nonce (deterministic tie-break), so two
    /// admins concurrently redeeming the same invite for different actors can't
    /// both stick. `None` for every other op.
    #[serde(default)]
    pub nonce: Option<[u8; 16]>,
}

impl AclOp {
    fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode acl op")
    }
}

/// Sign an [`AclOp`] with the author's ed25519 device seed, given the current
/// heads as parents (S§6). Same envelope bindings as every plane.
pub fn sign_op(
    seed: &[u8; 32],
    op: &AclOp,
    parents: Vec<String>,
    workspace_id: &WorkspaceId,
) -> SignedOp {
    sigdag::sign_node(
        ACL_DOMAIN,
        seed,
        op.encode(),
        parents,
        workspace_id.as_str(),
    )
}

/// The materialized ACL state after replay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AclState {
    /// Every actor sealed into the workspace, humans and agents alike, with
    /// their grants. Agents carry no grants.
    members: BTreeMap<ActorId, BTreeSet<Grant>>,
    /// agent actor → sponsoring actor. Every key here is also in `members`;
    /// an agent's presence is derived from its sponsor's.
    agents: BTreeMap<ActorId, ActorId>,
}

impl AclState {
    /// Whether `a` is sealed into the workspace (humans and agents alike).
    pub fn is_member(&self, a: &ActorId) -> bool {
        self.members.contains_key(a)
    }
    pub fn is_admin(&self, a: &ActorId) -> bool {
        self.members
            .get(a)
            .is_some_and(|g| g.contains(&Grant::Admin))
    }
    /// Content-write authority: `Admin` or `Write`. An empty grant set is a
    /// view-only member.
    pub fn can_write(&self, a: &ActorId) -> bool {
        self.members
            .get(a)
            .is_some_and(|g| g.contains(&Grant::Admin) || g.contains(&Grant::Write))
    }
    /// Whether `a` is an agent principal (contract §3.4).
    pub fn is_agent(&self, a: &ActorId) -> bool {
        self.agents.contains_key(a)
    }
    /// The sponsoring actor of an agent.
    pub fn sponsor_of(&self, a: &ActorId) -> Option<&ActorId> {
        self.agents.get(a)
    }
    /// A human (non-agent) member — the standing membership authority and
    /// content-authority ops require.
    pub fn is_human_member(&self, a: &ActorId) -> bool {
        self.is_member(a) && !self.is_agent(a)
    }
    pub fn grants(&self, a: &ActorId) -> Vec<Grant> {
        self.members
            .get(a)
            .map(|g| g.iter().copied().collect())
            .unwrap_or_default()
    }
    /// `admin` | `member` | `viewer` | `agent` — the projection surface.
    pub fn standing(&self, a: &ActorId) -> Option<&'static str> {
        if self.is_agent(a) {
            return Some("agent");
        }
        let g = self.members.get(a)?;
        Some(if g.contains(&Grant::Admin) {
            "admin"
        } else if g.contains(&Grant::Write) {
            "member"
        } else {
            "viewer"
        })
    }
    /// All current members, sorted by actor (includes agents — the actor-level
    /// sealing set; fan out to devices via the actor plane).
    pub fn members(&self) -> Vec<(ActorId, Vec<Grant>)> {
        self.members
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
            .collect()
    }
    /// All current agents with their sponsors, sorted by actor.
    pub fn agents(&self) -> Vec<(ActorId, ActorId)> {
        self.agents
            .iter()
            .map(|(k, s)| (k.clone(), s.clone()))
            .collect()
    }
    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

/// One rendered row of the membership audit log (`lait members log`): the op
/// in deterministic causal order, with its replay verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub hash: String,
    /// The signing device key (verified — the signature covers the op).
    pub author: UserId,
    /// The actor the author claimed (its device→actor binding is part of the
    /// verdict).
    pub by: Option<ActorId>,
    /// `add_member` | `remove_member` | `set_grants` | `add_agent` | `unknown`.
    pub kind: &'static str,
    /// The subject actor (absent for undecodable ops).
    pub subject: Option<ActorId>,
    pub grants: Option<Vec<Grant>>,
    /// Whether replay honored the op (false = unauthorized or undecodable).
    pub authorized: bool,
}

/// Deterministically replay the signed op-graph from the genesis (S§6), given
/// the actor plane's event set. Founding actors seed the admin set; each op is
/// honored only if signature-valid, its author device belonged to its claimed
/// actor at the declared frontier, and the actor held the required standing as
/// of the op's causal history; membership resolves **remove-wins** over the
/// causal ancestor closure, then agents cascade with their sponsors.
pub fn replay(genesis: &Genesis, actor_events: &[SignedEvent], ops: &[SignedOp]) -> AclState {
    replay_with_audit(genesis, actor_events, ops).0
}

/// [`replay`] plus the per-op audit trail, in the same deterministic order.
pub fn replay_with_audit(
    genesis: &Genesis,
    actor_events: &[SignedEvent],
    ops: &[SignedOp],
) -> (AclState, Vec<AuditEntry>) {
    let ws = &genesis.workspace_id;

    // Index signature-valid ops by hash. Undecodable ops stay as opaque DAG
    // nodes (ancestry, no state) — the forward-compat rule in the module docs.
    let mut nodes: HashMap<String, &SignedOp> = HashMap::new();
    let mut decoded: HashMap<String, Option<AclOp>> = HashMap::new();
    for so in ops {
        if !so.verify_sig(ACL_DOMAIN, ws.as_str()) {
            continue;
        }
        let h = so.hash();
        decoded.insert(h.clone(), postcard::from_bytes(&so.op).ok());
        nodes.insert(h, so);
    }

    let ancestors = sigdag::compute_ancestors(&nodes);
    let order = sigdag::topo_order(&nodes);

    // Memoized at-frontier actor resolution: the same (device, actor, asof)
    // claim resolves identically everywhere, so cache by (actor, sorted asof).
    let mut planes: HashMap<Vec<String>, ActorPlane> = HashMap::new();
    let mut device_speaks_for = |device: &UserId, by: &ActorId, asof: &[String]| -> bool {
        let mut key: Vec<String> = asof.to_vec();
        key.sort();
        let plane = planes
            .entry(key)
            .or_insert_with(|| actor::replay_at(ws, actor_events, asof));
        plane.is_device_of(by, device)
    };

    // ---- pass 1 (topo): authorize ops, tracking standing as it evolves ----
    let mut admins: BTreeSet<ActorId> = genesis.founding_actors.iter().cloned().collect();
    let mut humans: BTreeSet<ActorId> = admins.clone();
    let mut agents_now: BTreeMap<ActorId, ActorId> = BTreeMap::new();

    let mut authorized: Vec<String> = Vec::new();
    let mut audit: Vec<AuditEntry> = Vec::new();
    for h in &order {
        let so = nodes[h];
        let op = &decoded[h];
        let mut entry = AuditEntry {
            hash: h.clone(),
            author: so.author.clone(),
            by: None,
            kind: "unknown",
            subject: None,
            grants: None,
            authorized: false,
        };
        let Some(op) = op else {
            audit.push(entry); // opaque node: ancestry only
            continue;
        };
        entry.by = Some(op.by.clone());
        entry.subject = Some(op.action.actor().clone());
        entry.kind = match &op.action {
            AclAction::AddMember { .. } => "add_member",
            AclAction::RemoveMember { .. } => "remove_member",
            AclAction::SetGrants { .. } => "set_grants",
            AclAction::AddAgent { .. } => "add_agent",
        };
        if let AclAction::AddMember { grants, .. } | AclAction::SetGrants { grants, .. } =
            &op.action
        {
            entry.grants = Some(grants.clone());
        }

        // The device→actor binding: the signing device must speak for the
        // claimed actor at the frontier the author declared. An unresolvable
        // frontier (events not yet synced / oversized) does not authorize —
        // and converges to authorized once the events arrive, because replay
        // is recomputed over whatever is held (see module docs).
        let by = &op.by;
        let bound = device_speaks_for(&so.author, by, &op.actor_asof);

        // Agents may author NO membership op (contract §3.4).
        let ok = bound
            && !agents_now.contains_key(by)
            && match &op.action {
                AclAction::AddMember { .. } | AclAction::SetGrants { .. } => admins.contains(by),
                // Admins remove anyone; a sponsor may retire their own agent.
                AclAction::RemoveMember { actor } => {
                    admins.contains(by) || agents_now.get(actor) == Some(by)
                }
                // Any human member may sponsor an agent for themselves; the
                // agent actor must be fresh (not already a principal).
                AclAction::AddAgent { actor } => {
                    humans.contains(by)
                        && actor != by
                        && !humans.contains(actor)
                        && !agents_now.contains_key(actor)
                }
            };
        entry.authorized = ok;
        audit.push(entry);
        if !ok {
            continue;
        }
        authorized.push(h.clone());
        match &op.action {
            AclAction::AddMember { actor, grants } | AclAction::SetGrants { actor, grants } => {
                humans.insert(actor.clone());
                agents_now.remove(actor);
                if grants.contains(&Grant::Admin) {
                    admins.insert(actor.clone());
                } else {
                    admins.remove(actor);
                }
            }
            AclAction::AddAgent { actor } => {
                agents_now.insert(actor.clone(), op.by.clone());
            }
            AclAction::RemoveMember { actor } => {
                humans.remove(actor);
                admins.remove(actor);
                agents_now.remove(actor);
                // in-pass sponsor cascade so an orphaned agent cannot author
                // (nothing to author anyway) nor be counted as standing.
                agents_now.retain(|_, sponsor| sponsor != actor);
            }
        }
    }

    // ---- pass 2: materialize membership from authorized ops in topo order ----
    let founding: BTreeSet<Grant> = [Grant::Admin, Grant::Write].into();
    let mut members: BTreeMap<ActorId, BTreeSet<Grant>> = genesis
        .founding_actors
        .iter()
        .map(|a| (a.clone(), founding.clone()))
        .collect();
    let mut agents: BTreeMap<ActorId, ActorId> = BTreeMap::new();

    for h in &authorized {
        let op = decoded[h].as_ref().expect("authorized ops decoded");
        match &op.action {
            AclAction::AddMember { actor, grants } | AclAction::SetGrants { actor, grants } => {
                members.insert(actor.clone(), grants.iter().copied().collect());
                agents.remove(actor);
            }
            AclAction::AddAgent { actor } => {
                members.insert(actor.clone(), BTreeSet::new());
                agents.insert(actor.clone(), op.by.clone());
            }
            AclAction::RemoveMember { actor } => {
                members.remove(actor);
                agents.remove(actor);
            }
        }
    }

    // ---- remove-wins override (S§6): an authorized remove not causally
    // succeeded by an authorized (re-)add removes the actor even if a
    // concurrent add appeared later in topo order. AddAgent counts as an add.
    let subjects: BTreeSet<ActorId> = authorized
        .iter()
        .filter_map(|h| decoded[h].as_ref().map(|op| op.action.actor().clone()))
        .collect();
    for subject in subjects {
        let adds: Vec<&String> = authorized
            .iter()
            .filter(|h| {
                decoded[*h].as_ref().is_some_and(|op| {
                    matches!(
                        &op.action,
                        AclAction::AddMember { actor, .. }
                        | AclAction::SetGrants { actor, .. }
                        | AclAction::AddAgent { actor } if actor == &subject
                    )
                })
            })
            .collect();
        let removes: Vec<&String> = authorized
            .iter()
            .filter(|h| {
                decoded[*h].as_ref().is_some_and(|op| {
                    matches!(&op.action, AclAction::RemoveMember { actor } if actor == &subject)
                })
            })
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
            members.remove(&subject);
            agents.remove(&subject);
        }
    }

    // ---- sponsor cascade: an agent stands only while its sponsor does.
    // Sponsors are never agents (AddAgent authorization), so one pass suffices.
    let orphaned: Vec<ActorId> = agents
        .iter()
        .filter(|(_, sponsor)| !members.contains_key(*sponsor))
        .map(|(k, _)| k.clone())
        .collect();
    for k in orphaned {
        agents.remove(&k);
        members.remove(&k);
    }

    // ---- single-use invite convergence: a nonce admits exactly one actor.
    // Two admins on un-merged replicas can each authorize an AddMember spending
    // the same nonce for a different actor; after merge both ops are valid, so
    // pick the winner deterministically (lowest op hash) and evict the rest.
    let mut by_nonce: BTreeMap<[u8; 16], Vec<(String, ActorId)>> = BTreeMap::new();
    for h in &authorized {
        if let Some(AclOp {
            action: AclAction::AddMember { actor, .. },
            nonce: Some(n),
            ..
        }) = decoded[h].as_ref()
        {
            by_nonce.entry(*n).or_default().push((h.clone(), actor.clone()));
        }
    }
    for (_n, mut group) in by_nonce {
        let distinct: BTreeSet<&ActorId> = group.iter().map(|(_, a)| a).collect();
        if distinct.len() <= 1 {
            continue; // idempotent re-admits of the same actor are fine
        }
        group.sort_by(|a, b| a.0.cmp(&b.0));
        let winner = group[0].1.clone();
        for (_, actor) in &group {
            if *actor != winner {
                members.remove(actor);
                agents.remove(actor);
            }
        }
    }

    (AclState { members, agents }, audit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::{consent_sign, sign_event, ActorOp, ConsentCtx};
    use crate::ids::SystemUlidSource;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// A one-device actor for seed `n` in workspace `w`.
    fn incept(n: u8, w: &WorkspaceId) -> (SignedEvent, ActorId) {
        actor::incept_single(&seed(n), w, [n; 16], [n.wrapping_add(70); 16], None)
    }

    /// A test fixture: genesis founded by actor(1), with inceptions for the
    /// given seeds available on the actor plane.
    struct Fx {
        genesis: Genesis,
        events: Vec<SignedEvent>,
        actors: BTreeMap<u8, ActorId>,
    }
    fn fx(founder: u8, others: &[u8]) -> Fx {
        let wsid = WorkspaceId::mint(&SystemUlidSource);
        let mut events = Vec::new();
        let mut actors = BTreeMap::new();
        for n in std::iter::once(founder).chain(others.iter().copied()) {
            let (ev, id) = incept(n, &wsid);
            events.push(ev);
            actors.insert(n, id);
        }
        Fx {
            genesis: Genesis {
                workspace_id: wsid,
                founding_actors: vec![actors[&founder].clone()],
            },
            events,
            actors,
        }
    }
    impl Fx {
        fn op(&self, author: u8, by: u8, action: AclAction, parents: Vec<String>) -> SignedOp {
            // asof = the author actor's inception (single-device logs here).
            let asof = vec![self.actors[&by].incept_hash().to_string()];
            sign_op(
                &seed(author),
                &AclOp {
                    action,
                    by: self.actors[&by].clone(),
                    actor_asof: asof,
                    nonce: None,
                },
                parents,
                &self.genesis.workspace_id,
            )
        }
        fn replay(&self, ops: &[SignedOp]) -> AclState {
            replay(&self.genesis, &self.events, ops)
        }
        fn a(&self, n: u8) -> &ActorId {
            &self.actors[&n]
        }
    }

    #[test]
    fn founder_is_admin_and_can_add_members() {
        let f = fx(1, &[2]);
        let add = f.op(
            1,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Write],
            },
            vec![],
        );
        let st = f.replay(&[add]);
        assert!(st.is_admin(f.a(1)));
        assert!(st.is_member(f.a(2)));
        assert!(st.can_write(f.a(2)));
        assert!(!st.is_admin(f.a(2)));
        assert_eq!(st.standing(f.a(2)), Some("member"));
        assert_eq!(st.len(), 2);
    }

    #[test]
    fn empty_grants_member_is_view_only() {
        let f = fx(1, &[2]);
        let add = f.op(
            1,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![],
            },
            vec![],
        );
        let st = f.replay(&[add]);
        assert!(st.is_member(f.a(2)), "sealed in");
        assert!(!st.can_write(f.a(2)), "but no write standing");
        assert_eq!(st.standing(f.a(2)), Some("viewer"));
    }

    #[test]
    fn non_admin_ops_are_rejected() {
        let f = fx(1, &[2, 3]);
        // Actor 2 (not a member) tries to add actor 3 — unauthorized, ignored.
        let forged = f.op(
            2,
            2,
            AclAction::AddMember {
                actor: f.a(3).clone(),
                grants: vec![Grant::Admin],
            },
            vec![],
        );
        let st = f.replay(&[forged]);
        assert!(!st.is_member(f.a(3)));
        assert!(!st.is_member(f.a(2)));
    }

    #[test]
    fn device_must_speak_for_the_claimed_actor() {
        let f = fx(1, &[2]);
        // Device 2 signs an op CLAIMING to be the founder actor: the claim
        // fails device→actor resolution and the op is void — even though the
        // claimed actor is an admin.
        let imposter = f.op(
            2,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Admin],
            },
            vec![],
        );
        let st = f.replay(&[imposter]);
        assert!(
            !st.is_member(f.a(2)),
            "a device that is not the claimed actor's must not authorize"
        );
    }

    #[test]
    fn second_device_authorizes_after_add_device() {
        let f = fx(1, &[2]);
        // Founder binds a second device (seed 9) to their actor...
        let binding = consent_sign(
            &seed(9),
            f.genesis.workspace_id.as_str(),
            [90u8; 16],
            &ConsentCtx::Member { actor: f.a(1) },
        );
        let add_dev = sign_event(
            &seed(1),
            &ActorOp::AddDevice {
                actor: f.a(1).clone(),
                binding,
            },
            vec![f.a(1).incept_hash().to_string()],
            &f.genesis.workspace_id,
        );
        let mut events = f.events.clone();
        events.push(add_dev.clone());
        // ...and the SECOND device signs a member-add, declaring the frontier
        // that includes its own binding.
        let op = sign_op(
            &seed(9),
            &AclOp {
                action: AclAction::AddMember {
                    actor: f.a(2).clone(),
                    grants: vec![Grant::Write],
                },
                by: f.a(1).clone(),
                actor_asof: vec![add_dev.hash()],
                nonce: None,
            },
            vec![],
            &f.genesis.workspace_id,
        );
        let st = replay(&f.genesis, &events, std::slice::from_ref(&op));
        assert!(
            st.is_member(f.a(2)),
            "an added device speaks for the actor at its declared frontier"
        );
        // The same op against a plane that lacks the AddDevice event does not
        // authorize (yet) — and this is the convergence story: once the event
        // syncs, replay flips it to authorized. Same input ⇒ same output.
        let st = replay(&f.genesis, &f.events, &[op]);
        assert!(!st.is_member(f.a(2)));
    }

    #[test]
    fn remove_wins_over_concurrent_add() {
        let f = fx(1, &[2, 3]);
        // Two admins: founder adds 2 as admin.
        let add2 = f.op(
            1,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Admin, Grant::Write],
            },
            vec![],
        );
        // Concurrently: admin 2 adds 3; founder removes 3 (not seeing the add).
        let add3 = f.op(
            2,
            2,
            AclAction::AddMember {
                actor: f.a(3).clone(),
                grants: vec![Grant::Write],
            },
            vec![add2.hash()],
        );
        let rm3 = f.op(
            1,
            1,
            AclAction::RemoveMember {
                actor: f.a(3).clone(),
            },
            vec![add2.hash()],
        );
        let st = f.replay(&[add2, add3, rm3]);
        assert!(
            !st.is_member(f.a(3)),
            "remove-wins: a concurrent add must not resurrect the actor"
        );
    }

    #[test]
    fn readd_causally_after_remove_restores() {
        let f = fx(1, &[2]);
        let add = f.op(
            1,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Write],
            },
            vec![],
        );
        let rm = f.op(
            1,
            1,
            AclAction::RemoveMember {
                actor: f.a(2).clone(),
            },
            vec![add.hash()],
        );
        let readd = f.op(
            1,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Write],
            },
            vec![rm.hash()],
        );
        let st = f.replay(&[add, rm, readd]);
        assert!(st.is_member(f.a(2)), "a causal re-add restores membership");
    }

    #[test]
    fn agents_are_sponsored_grantless_and_cascade_with_their_sponsor() {
        let f = fx(1, &[2, 7]);
        let add2 = f.op(
            1,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Write],
            },
            vec![],
        );
        // Member 2 sponsors agent-actor 7.
        let sponsor = f.op(
            2,
            2,
            AclAction::AddAgent {
                actor: f.a(7).clone(),
            },
            vec![add2.hash()],
        );
        let st = f.replay(&[add2.clone(), sponsor.clone()]);
        assert!(st.is_member(f.a(7)));
        assert!(st.is_agent(f.a(7)));
        assert!(!st.can_write(f.a(7)), "agents carry no grants");
        assert!(!st.is_human_member(f.a(7)));
        assert_eq!(st.sponsor_of(f.a(7)), Some(f.a(2)));

        // The agent may author NO membership op.
        let agent_op = f.op(
            7,
            7,
            AclAction::AddMember {
                actor: f.a(7).clone(),
                grants: vec![Grant::Admin],
            },
            vec![sponsor.hash()],
        );
        let st = f.replay(&[add2.clone(), sponsor.clone(), agent_op]);
        assert!(!st.is_admin(f.a(7)));

        // Removing the sponsor cascades the agent away.
        let rm2 = f.op(
            1,
            1,
            AclAction::RemoveMember {
                actor: f.a(2).clone(),
            },
            vec![sponsor.hash()],
        );
        let st = f.replay(&[add2, sponsor, rm2]);
        assert!(!st.is_member(f.a(2)));
        assert!(!st.is_member(f.a(7)), "agent dies with its sponsor");
    }

    #[test]
    fn forged_signature_is_rejected() {
        let f = fx(1, &[2]);
        let mut op = f.op(
            1,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Write],
            },
            vec![],
        );
        op.sig[0] ^= 0xff; // tamper
        let st = f.replay(&[op]);
        assert!(!st.is_member(f.a(2)), "a bad signature must be rejected");
    }

    #[test]
    fn removed_actor_devices_lose_standing_via_the_indirection() {
        let f = fx(1, &[2]);
        let add2 = f.op(
            1,
            1,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Admin, Grant::Write],
            },
            vec![],
        );
        let rm2 = f.op(
            1,
            1,
            AclAction::RemoveMember {
                actor: f.a(2).clone(),
            },
            vec![add2.hash()],
        );
        // Actor 2's device authors an op causally AFTER its removal.
        let late = f.op(
            2,
            2,
            AclAction::AddMember {
                actor: f.a(2).clone(),
                grants: vec![Grant::Admin],
            },
            vec![rm2.hash()],
        );
        let st = f.replay(&[add2, rm2, late]);
        assert!(
            !st.is_member(f.a(2)),
            "every device of a removed actor is powerless at once"
        );
    }
}
