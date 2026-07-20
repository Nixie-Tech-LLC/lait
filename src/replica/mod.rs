//! The daemon's issue-tracking core — the bridge from Layer B (the control
//! façade, [`crate::control`]) to Layer A (the Loro docs, [`crate::catalog`] +
//! [`crate::issue`]) over the git-backed [`crate::store`]. Fully testable
//! in-process (no socket, no iroh, injected clock), which is where the SCHEMA and
//! control-plane invariants are exercised.

use std::collections::{BTreeMap, HashMap, VecDeque};

use anyhow::{anyhow, Context, Result};

use crate::acl::{self, AclAction, AclOp, AclState, Grant, SignedOp};
use crate::actor::{self, ActorPlane};
use crate::authz;
use crate::catalog::{CatalogDoc, RowMeta};
use crate::control::{BoardPos, CatalogScope, Filter, Request, Response};
use crate::crypto::{self, SpaceKey};
use crate::dto::{
    ActivityEvent, BoardColumn, BoardView, FieldChange, GraphView, IssueView, LabelDto, LinkDto,
    Priority, ProjectDto, Row, StatusCategory, SCHEMA_VERSION,
};
use crate::fabric::history;
use crate::fabric::op::OpCtx;
use crate::genesis::Genesis;
use crate::ids::{ActorId, DeviceId, DocId, LabelId, ProjectId, SpaceId, UlidSource};
use crate::index::{self, AliasTable, RefResolution};
use crate::issue::{IssueDoc, NewIssue};
use crate::membership::MembershipDoc;
use crate::store::Store;

/// Issue-link kinds accepted by the control interface. `relates` is
/// symmetric and canonicalized (sorted endpoints) so one edge represents it.
pub const LINK_KINDS: [&str; 3] = ["blocks", "relates", "duplicates"];

mod devices;
mod dispatch;
mod keyring;
mod lifecycle;
mod membership;
mod mutate;
mod project;
mod recovery;
mod sync;
#[cfg(test)]
mod tests;

pub use lifecycle::{derive_project_key, found_space, join_space_store};
pub use recovery::{
    ArtifactRead, DegradedRecoveryHolder, LocalCustodyState, RecoveryArtifactFailure,
    RecoveryStatus,
};
// private re-imports so `use super::*` in children keeps unqualified helper names working:
use lifecycle::mint_recovery;
use mutate::WorkAction;
use recovery::{persist_recovery_key, persist_space_recovery};

/// The batched, project-keyed dirty set produced by a mutation. The
/// node layer stamps it with an epoch + session `seq` to form a `Doorbell`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirtySet {
    pub dirty_by_project: HashMap<String, Vec<String>>,
    pub dirty_catalog: Vec<CatalogScope>,
    pub activity_advanced: bool,
}

impl DirtySet {
    fn issue(project: &ProjectId, doc: &DocId) -> Self {
        let mut m = HashMap::new();
        m.insert(project.as_str().to_string(), vec![doc.as_str().to_string()]);
        DirtySet {
            dirty_by_project: m,
            dirty_catalog: Vec::new(),
            activity_advanced: true,
        }
    }
    fn with_scope(mut self, scope: CatalogScope) -> Self {
        self.dirty_catalog.push(scope);
        self
    }
    fn catalog(scope: CatalogScope) -> Self {
        DirtySet {
            dirty_by_project: HashMap::new(),
            dirty_catalog: vec![scope],
            activity_advanced: false,
        }
    }

    /// Coalesce another dirty-set into this one (daemon-side doorbell batching,
    /// a whole sync-import transaction becomes one frame.
    pub fn merge(&mut self, other: DirtySet) {
        for (proj, docs) in other.dirty_by_project {
            let e = self.dirty_by_project.entry(proj).or_default();
            for d in docs {
                if !e.contains(&d) {
                    e.push(d);
                }
            }
        }
        for s in other.dirty_catalog {
            if !self.dirty_catalog.contains(&s) {
                self.dirty_catalog.push(s);
            }
        }
        self.activity_advanced |= other.activity_advanced;
    }

    /// A dirty-set marking the catalog registries (projects/labels/workflow)
    /// dirty — used when a sync imported a catalog diff whose structure moved.
    pub fn catalog_structure() -> Self {
        DirtySet {
            dirty_by_project: HashMap::new(),
            dirty_catalog: vec![
                CatalogScope::Projects,
                CatalogScope::Labels,
                CatalogScope::Workflow,
            ],
            activity_advanced: false,
        }
    }

    /// Whether this dirty-set carries anything worth ringing a doorbell for.
    pub fn is_empty(&self) -> bool {
        self.dirty_by_project.is_empty() && self.dirty_catalog.is_empty() && !self.activity_advanced
    }
}

/// One issue document a puller must fetch during catalog-first sync: the
/// `doc_id` plus the puller's local version vector for it (empty ⇒ fetch all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocNeed {
    pub doc_id: String,
    pub vv: Vec<u8>,
}

/// The issue-tracking core.
pub struct Replica {
    store: Store,
    catalog: CatalogDoc,
    issues: HashMap<DocId, IssueDoc>,
    aliases: AliasTable,
    me: DeviceId,
    my_nick: String,
    space_id: SpaceId,
    activity: VecDeque<ActivityEvent>,
    activity_seq: u64,
    clock: Box<dyn UlidSource + Send + Sync>,
    // ---- space encryption ----
    /// The plaintext membership layer (signed ACL + sealed key envelopes).
    membership: MembershipDoc,
    /// The genesis trust root: space ID and founding administrator keys.
    genesis: Genesis,
    /// Our ed25519 secret seed — signs ACL ops and unseals key envelopes.
    seed: [u8; 32],
    /// Every key-epoch we can unseal (a keyring; older epochs stay decryptable —
    /// lazy revocation). Empty ⇒ we are not a member and see only ciphertext.
    keyring: BTreeMap<[u8; 16], SpaceKey>,
}

/// 16 random bytes (an actor inception / consent nonce). Non-deterministic by
/// design — an inception id must be unpredictable, so this never routes through
/// the injected [`UlidSource`] clock.
fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("getrandom");
    b
}

impl Replica {
    /// Load-time invariant: recompute every head and row from the real issue
    /// docs. Lazily caches each issue doc.
    fn recompute_all_rows(&mut self) -> Result<()> {
        let mut changed = false;
        for doc_id in self.store.issue_doc_ids() {
            if let Some(issue) = self.store.load_issue(&doc_id)? {
                self.catalog.upsert_row(&issue)?;
                self.issues.insert(doc_id, issue);
                changed = true;
            }
        }
        if changed {
            self.catalog.apply(&OpCtx::structure("row_heal", &self.me));
            self.store.save_catalog(&self.catalog)?;
        }
        Ok(())
    }

    fn rebuild_aliases(&mut self) {
        self.aliases = AliasTable::build(&self.catalog);
    }

    fn now_secs(&self) -> u64 {
        self.clock.now_ms() / 1000
    }

    // Test/inspection accessors.
    pub fn space_id(&self) -> &SpaceId {
        &self.space_id
    }
    /// The synced display name (empty on a joiner until the catalog arrives).
    pub fn space_name(&self) -> String {
        self.catalog.space_name()
    }
    /// Update the display nick (a `ConfigReload` applying `user.nick` live).
    /// Affects future activity attribution; nothing durable to rewrite.
    pub fn set_nick(&mut self, nick: String) {
        self.my_nick = nick;
    }
    /// Advisory project snapshot for the machine-level space registry.
    pub fn project_briefs(&self) -> Vec<crate::spaces::ProjectBrief> {
        self.catalog
            .projects_list()
            .into_iter()
            .map(|p| crate::spaces::ProjectBrief {
                key: p.key,
                name: p.name,
            })
            .collect()
    }
    pub fn issue_count(&self) -> usize {
        self.catalog
            .all_rows()
            .iter()
            .filter(|r| !r.tombstone)
            .count()
    }
    pub fn project_count(&self) -> usize {
        self.catalog.projects_list().len()
    }
    pub fn catalog(&self) -> &CatalogDoc {
        &self.catalog
    }

    /// Get a cached issue doc, loading it from the store on first access (lazy).
    fn issue(&mut self, doc_id: &DocId) -> Result<Option<&IssueDoc>> {
        if !self.issues.contains_key(doc_id) {
            if let Some(loaded) = self.store.load_issue(doc_id)? {
                self.issues.insert(doc_id.clone(), loaded);
            } else {
                return Ok(None);
            }
        }
        Ok(self.issues.get(doc_id))
    }
}
