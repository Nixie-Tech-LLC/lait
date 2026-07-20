//! Property-based tests for the invariant that all merge semantics live in
//! Loro. Each test drives a proptest-generated sequence of operations
//! across 2–3 independent replicas of one document, exchanges updates all-pairs
//! until quiescence, and asserts every replica reaches identical state
//! (deep-value equality via `state_json()`) plus the schema-level invariant
//! that the merge rule promises:
//!
//!   * `issue_lww_converges` — last-writer-wins registers
//!   * `assignees_labels_map_union_converges` — present-key set (map-union)
//!   * `board_movable_list_converges` — board ordering (movable list)
//!   * `catalog_docs_grow_set_converges` — the `docs` grow-only key set
//!
//! Post-contract note: these tests exercise the sealed fabric surface only
//! (`docs/DATA-CONTRACT.md`) — replicas fork via `from_snapshot`, mutate through
//! the typed writers, land ops with `apply(OpCtx)`, and exchange bytes through
//! `oplog_vv_bytes`/`export_from_bytes`/`import`. No raw kernel handle exists
//! out here, which is itself part of what is under test.
//!
//! Determinism rule (the plan's "inject clocks/seeds"): all randomness that
//! affects assertions flows through proptest inputs. `SystemUlidSource` is used
//! ONLY to mint ids (whose *values* never enter an assertion — only their
//! identity/uniqueness does), and `created_at` is a fixed constant. No
//! wall-clock or RNG is read inside an assertion path.

use proptest::prelude::*;

use lait::catalog::CatalogDoc;
use lait::dto::Priority;
use lait::fabric::op::OpCtx;
use lait::ids::{ActorId, DeviceId, DocId, LabelId, ProjectId, SpaceId, SystemUlidSource};
use lait::issue::{IssueDoc, NewIssue};

/// A fixed creation timestamp — never varied, so it can never be the reason two
/// replicas differ.
const CREATED_AT: u64 = 1_000;

fn tester() -> DeviceId {
    DeviceId::from_key_string("a".repeat(64))
}
fn ctx() -> OpCtx {
    OpCtx::content("test", &tester())
}

/// The fabric surface a convergence test needs from any replicated doc.
trait Replica {
    fn vv(&self) -> Vec<u8>;
    fn export_missing(&self, peer_vv: &[u8]) -> Vec<u8>;
    fn import_bytes(&self, bytes: &[u8]);
    fn state(&self) -> serde_json::Value;
}

impl Replica for IssueDoc {
    fn vv(&self) -> Vec<u8> {
        self.oplog_vv_bytes()
    }
    fn export_missing(&self, peer_vv: &[u8]) -> Vec<u8> {
        self.export_from_bytes(peer_vv).expect("export updates")
    }
    fn import_bytes(&self, bytes: &[u8]) {
        self.import(bytes).expect("import updates");
    }
    fn state(&self) -> serde_json::Value {
        self.state_json()
    }
}

impl Replica for CatalogDoc {
    fn vv(&self) -> Vec<u8> {
        self.oplog_vv_bytes()
    }
    fn export_missing(&self, peer_vv: &[u8]) -> Vec<u8> {
        self.export_from_bytes(peer_vv).expect("export updates")
    }
    fn import_bytes(&self, bytes: &[u8]) {
        self.import(bytes).expect("import updates");
    }
    fn state(&self) -> serde_json::Value {
        self.state_json()
    }
}

/// Exchanges version-vector deltas between every pair of replicas. For every
/// ordered pair (i, j), this ships i's ops that j is missing into
/// j. Running the full all-pairs loop three times drives the mesh to quiescence
/// even when an update produced in an earlier round only becomes relevant to a
/// third replica after a later import.
fn sync_all<R: Replica>(docs: &[&R]) {
    for _ in 0..3 {
        for i in 0..docs.len() {
            for j in 0..docs.len() {
                if i == j {
                    continue;
                }
                let update = docs[i].export_missing(&docs[j].vv());
                if !update.is_empty() {
                    docs[j].import_bytes(&update);
                }
            }
        }
    }
}

/// Assert every replica's materialized deep value equals replica 0's — the
/// definition of convergence (all replicas agree on the whole document state).
fn assert_deep_values_converged<R: Replica>(docs: &[&R]) {
    let base = docs[0].state();
    for (i, d) in docs.iter().enumerate().skip(1) {
        assert_eq!(
            d.state(),
            base,
            "replica {i} deep value diverged from replica 0",
        );
    }
}

/// Fork an issue replica off a shared base snapshot. Replicas MUST descend from
/// a common base doc: two docs created independently would share no history root
/// and their overlapping container layouts could not merge. `from_snapshot`
/// gives a replica the shared root while the kernel still assigns it a distinct
/// internal peer id.
fn issue_replica_from(snap: &[u8]) -> IssueDoc {
    IssueDoc::from_snapshot(snap, None).expect("import base issue snapshot")
}

/// Fork a catalog replica off a shared base snapshot (same rationale as above).
fn catalog_replica_from(snap: &[u8]) -> CatalogDoc {
    CatalogDoc::from_snapshot(snap, None).expect("import base catalog snapshot")
}

fn base_issue() -> IssueDoc {
    IssueDoc::create(NewIssue {
        doc_id: DocId::mint(&SystemUlidSource),
        space_id: SpaceId::mint(&SystemUlidSource),
        project_id: ProjectId::mint(&SystemUlidSource),
        title: "base title".into(),
        priority: Priority::None,
        created_by: ActorId::from_incept_hash(&"a".repeat(64)),
        committed_by: tester(),
        created_at: CREATED_AT,
        body: None,
        peer: None,
    })
    .expect("create base issue")
}

// ---------------------------------------------------------------------------
// LWW registers: title, status, and priority.
// ---------------------------------------------------------------------------

/// The four workflow statuses an issue LWW register may hold.
const STATUSES: [&str; 4] = ["backlog", "in_progress", "in_review", "done"];

#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)] // Set* reads clearly as "set this field"
enum LwwOp {
    SetTitle(String),
    SetStatus(usize),
    SetPriority(Priority),
}

fn priority_strategy() -> impl Strategy<Value = Priority> {
    prop_oneof![
        Just(Priority::None),
        Just(Priority::Low),
        Just(Priority::Medium),
        Just(Priority::High),
        Just(Priority::Urgent),
    ]
}

fn lww_op_strategy() -> impl Strategy<Value = LwwOp> {
    prop_oneof![
        "[a-z ]{0,12}".prop_map(LwwOp::SetTitle),
        (0usize..STATUSES.len()).prop_map(LwwOp::SetStatus),
        priority_strategy().prop_map(LwwOp::SetPriority),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Title, status, and priority are single-key LWW registers. Under any
    /// interleaving of concurrent writes across replicas, after sync every
    /// replica must not only converge byte-for-byte but expose ONE coherent
    /// winner per register — never a value spliced from two writers.
    #[test]
    fn issue_lww_converges(
        n_replicas in 2usize..=3,
        ops in prop::collection::vec((0u8..3, lww_op_strategy()), 0..40),
    ) {
        let snap = base_issue().snapshot().unwrap();
        let replicas: Vec<IssueDoc> = (0..n_replicas).map(|_| issue_replica_from(&snap)).collect();

        for (who, op) in &ops {
            let r = &replicas[(*who as usize) % n_replicas];
            match op {
                LwwOp::SetTitle(t) => r.set_title(t).unwrap(),
                LwwOp::SetStatus(i) => r.set_status(STATUSES[*i]).unwrap(),
                LwwOp::SetPriority(p) => r.set_priority(*p).unwrap(),
            }
            r.apply(&ctx()); // ops must land before they can be exported
        }

        let docs: Vec<&IssueDoc> = replicas.iter().collect();
        sync_all(&docs);

        assert_deep_values_converged(&docs);

        // The LWW invariant: identical winner strings across all replicas.
        let title = replicas[0].title();
        let status = replicas[0].status();
        let priority = replicas[0].priority();
        for (i, r) in replicas.iter().enumerate() {
            prop_assert_eq!(r.title(), title.clone(), "title diverged at replica {}", i);
            prop_assert_eq!(r.status(), status.clone(), "status diverged at replica {}", i);
            prop_assert_eq!(r.priority(), priority, "priority diverged at replica {}", i);
        }
    }
}

// ---------------------------------------------------------------------------
// Present-key sets: assignees and labels as map-union.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum SetOp {
    AddAssignee(usize),
    RemoveAssignee(usize),
    AddLabel(usize),
    RemoveLabel(usize),
}

fn set_op_strategy() -> impl Strategy<Value = SetOp> {
    prop_oneof![
        (0usize..4).prop_map(SetOp::AddAssignee),
        (0usize..4).prop_map(SetOp::RemoveAssignee),
        (0usize..4).prop_map(SetOp::AddLabel),
        (0usize..4).prop_map(SetOp::RemoveLabel),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Assignees and labels are `LoroMap<Id, true>` present-key sets. Adds of
    /// DIFFERENT keys on different replicas union; concurrent add-vs-remove of
    /// the SAME key resolves to a single per-key LWW winner (deterministic, no
    /// panic). After sync the resolved key SET must be identical everywhere.
    #[test]
    fn assignees_labels_map_union_converges(
        n_replicas in 2usize..=3,
        ops in prop::collection::vec((0u8..3, set_op_strategy()), 0..40),
    ) {
        // Fixed pools of 4 actors and 4 labels, minted once and shared by every
        // replica (so add/remove target the same keys across replicas).
        let actors: Vec<ActorId> =
            (0..4).map(|i| ActorId::from_incept_hash(&format!("{:064x}", i + 1))).collect();
        let labels: Vec<LabelId> = (0..4).map(|_| LabelId::mint(&SystemUlidSource)).collect();

        let snap = base_issue().snapshot().unwrap();
        let replicas: Vec<IssueDoc> = (0..n_replicas).map(|_| issue_replica_from(&snap)).collect();

        for (who, op) in &ops {
            let r = &replicas[(*who as usize) % n_replicas];
            match op {
                SetOp::AddAssignee(i) => r.add_assignee(&actors[*i]).unwrap(),
                SetOp::RemoveAssignee(i) => r.remove_assignee(&actors[*i]).unwrap(),
                SetOp::AddLabel(i) => r.add_label(&labels[*i]).unwrap(),
                SetOp::RemoveLabel(i) => r.remove_label(&labels[*i]).unwrap(),
            }
            r.apply(&ctx());
        }

        let docs: Vec<&IssueDoc> = replicas.iter().collect();
        sync_all(&docs);

        assert_deep_values_converged(&docs);

        // Present-key SETS (readers already return sorted vecs) agree.
        let assignees = replicas[0].assignees();
        let labels_present = replicas[0].labels();
        for (i, r) in replicas.iter().enumerate() {
            prop_assert_eq!(r.assignees(), assignees.clone(), "assignee set diverged at replica {}", i);
            prop_assert_eq!(r.labels(), labels_present.clone(), "label set diverged at replica {}", i);
        }
    }
}

// ---------------------------------------------------------------------------
// Board ordering: a movable list reorders without duplication.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum BoardOp {
    Move {
        doc: usize,
        anchor: usize,
        after: bool,
    },
    InsertTop(usize),
    InsertBottom(usize),
}

fn board_op_strategy() -> impl Strategy<Value = BoardOp> {
    prop_oneof![
        (0usize..6, 0usize..6, any::<bool>()).prop_map(|(doc, anchor, after)| BoardOp::Move {
            doc,
            anchor,
            after
        }),
        (0usize..6).prop_map(BoardOp::InsertTop),
        (0usize..6).prop_map(BoardOp::InsertBottom),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The board is a `LoroMovableList` used for ordering only. Starting
    /// from a shared board of K issues, concurrent reorders across replicas must
    /// converge to one identical raw order, whose deduplicated projection is a
    /// permutation of the same K docs. (The raw list may hold a duplicate after
    /// concurrent insert paths; dedup is a projection-time rule.)
    #[test]
    fn board_movable_list_converges(
        k in 3usize..=6,
        n_replicas in 2usize..=3,
        ops in prop::collection::vec((0u8..3, board_op_strategy()), 0..40),
    ) {
        // Shared base catalog: one project + K issues already on the board.
        let ws = SpaceId::mint(&SystemUlidSource);
        let base = CatalogDoc::create(&ws, "test", None, &tester()).unwrap();
        let project = ProjectId::mint(&SystemUlidSource);
        base.add_project(&project, "Engineering", "ENG", "blue").unwrap();

        let mut doc_ids: Vec<DocId> = Vec::with_capacity(k);
        for n in 0..k {
            let issue = IssueDoc::create(NewIssue {
                doc_id: DocId::mint(&SystemUlidSource),
                space_id: ws.clone(),
                project_id: project.clone(),
                title: format!("issue {n}"),
                priority: Priority::None,
                created_by: ActorId::from_incept_hash(&"a".repeat(64)),
                committed_by: tester(),
                created_at: CREATED_AT,
                body: None,
                peer: None,
            })
            .unwrap();
            let id = issue.doc_id().unwrap();
            base.upsert_row(&issue).unwrap();
            base.board_insert_bottom(&project, &id).unwrap();
            doc_ids.push(id);
        }
        base.apply(&ctx());
        let snap = base.snapshot().unwrap();

        let replicas: Vec<CatalogDoc> =
            (0..n_replicas).map(|_| catalog_replica_from(&snap)).collect();

        for (who, op) in &ops {
            let c = &replicas[(*who as usize) % n_replicas];
            match op {
                BoardOp::Move { doc, anchor, after } => {
                    c.board_move(&project, &doc_ids[doc % k], &doc_ids[anchor % k], *after).unwrap();
                }
                BoardOp::InsertTop(i) => c.board_insert_top(&project, &doc_ids[i % k]).unwrap(),
                BoardOp::InsertBottom(i) => c.board_insert_bottom(&project, &doc_ids[i % k]).unwrap(),
            }
            c.apply(&ctx());
        }

        let docs: Vec<&CatalogDoc> = replicas.iter().collect();
        sync_all(&docs);

        assert_deep_values_converged(&docs);

        let order0 = replicas[0].board_order(&project);

        // Convergence proper: every replica agrees on the EXACT raw movable-list
        // order — the CRDT guarantee. Reorders of an already-listed doc use the
        // native `mov` (no duplicate under concurrent same-doc moves); the
        // insert paths can still contribute a surviving insert each, and Loro
        // totally-orders those, so all replicas land on the identical raw list;
        // Deduplication is a projection-time render rule.
        for (i, c) in replicas.iter().enumerate() {
            prop_assert_eq!(c.board_order(&project), order0.clone(), "board order diverged at replica {}", i);
        }

        // The deduplicated projection is well-formed: exactly the K seeded docs,
        // no phantom ids, none dropped — a permutation of the doc set.
        let mut deduped = order0.clone();
        deduped.sort();
        deduped.dedup();
        let mut expected = doc_ids.clone();
        expected.sort();
        prop_assert_eq!(deduped, expected, "deduped board order is not the K-doc permutation");
    }
}

// ---------------------------------------------------------------------------
// The docs grow-only key set: concurrently registered docs form a union.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// `Catalog.docs` is a keyed set that only grows (registering an issue
    /// adds its `DocId` key). When replicas register DIFFERENT issues, after
    /// sync every replica's `doc_ids()` must equal the identical union set.
    #[test]
    fn catalog_docs_grow_set_converges(
        n_replicas in 2usize..=3,
        registrations in prop::collection::vec(0u8..3, 0..30),
    ) {
        let ws = SpaceId::mint(&SystemUlidSource);
        let base = CatalogDoc::create(&ws, "test", None, &tester()).unwrap();
        let project = ProjectId::mint(&SystemUlidSource);
        base.add_project(&project, "Engineering", "ENG", "blue").unwrap();
        base.apply(&ctx());
        let snap = base.snapshot().unwrap();

        let replicas: Vec<CatalogDoc> =
            (0..n_replicas).map(|_| catalog_replica_from(&snap)).collect();

        // Each registration mints a globally-unique issue on one replica, so the
        // expected converged set is simply the union of all minted DocIds.
        let mut expected: Vec<DocId> = Vec::new();
        for who in &registrations {
            let c = &replicas[(*who as usize) % n_replicas];
            let issue = IssueDoc::create(NewIssue {
                doc_id: DocId::mint(&SystemUlidSource),
                space_id: ws.clone(),
                project_id: project.clone(),
                title: "grow".into(),
                priority: Priority::None,
                created_by: ActorId::from_incept_hash(&"a".repeat(64)),
                committed_by: tester(),
                created_at: CREATED_AT,
                body: None,
                peer: None,
            })
            .unwrap();
            expected.push(issue.doc_id().unwrap());
            c.upsert_row(&issue).unwrap();
            c.apply(&ctx());
        }
        expected.sort();

        let docs: Vec<&CatalogDoc> = replicas.iter().collect();
        sync_all(&docs);

        assert_deep_values_converged(&docs);

        for (i, c) in replicas.iter().enumerate() {
            let mut ids = c.doc_ids();
            ids.sort();
            prop_assert_eq!(ids, expected.clone(), "docs set diverged at replica {}", i);
        }
    }
}

// ---------------------------------------------------------------------------
// Sub-issue hierarchy: the tree-move CRDT converges,
// concurrent cross-replica cycles never survive the merge.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Following the Kleppmann et al. TPDS 2022 tree model, arbitrary concurrent
    /// `set_parent` operations across replicas converge to ONE identical
    /// hierarchy that is always a valid forest — every doc has at most one
    /// parent and no doc is its own ancestor — even when replicas concurrently
    /// perform moves whose combination would be a cycle.
    #[test]
    fn sub_hierarchy_converges_and_never_cycles(
        k in 3usize..=6,
        n_replicas in 2usize..=3,
        moves in prop::collection::vec((0u8..3, 0usize..6, prop::option::of(0usize..6)), 0..30),
    ) {
        let ws = SpaceId::mint(&SystemUlidSource);
        let base = CatalogDoc::create(&ws, "test", None, &tester()).unwrap();
        let project = ProjectId::mint(&SystemUlidSource);
        base.add_project(&project, "Engineering", "ENG", "blue").unwrap();
        let doc_ids: Vec<DocId> = (0..k).map(|_| DocId::mint(&SystemUlidSource)).collect();
        // Materialize every node at root before forking, so replicas share
        // tree-node identities (same reason replicas share a base snapshot).
        for id in &doc_ids {
            base.set_parent(id, None).unwrap();
        }
        base.apply(&ctx());
        let snap = base.snapshot().unwrap();

        let replicas: Vec<CatalogDoc> =
            (0..n_replicas).map(|_| catalog_replica_from(&snap)).collect();

        for (who, child, parent) in &moves {
            let c = &replicas[(*who as usize) % n_replicas];
            let child_id = &doc_ids[child % k];
            let parent_id = parent.map(|p| doc_ids[p % k].clone());
            if parent_id.as_ref() == Some(child_id) {
                continue; // self-parent is rejected at Layer B; skip in the driver
            }
            // A locally-visible cycle errors (that's the local guard); ignore it
            // — the interesting cycles are the cross-replica concurrent ones.
            let _ = c.set_parent(child_id, parent_id.as_ref());
            c.apply(&ctx());
        }

        let docs: Vec<&CatalogDoc> = replicas.iter().collect();
        sync_all(&docs);

        assert_deep_values_converged(&docs);

        // Identical hierarchy everywhere…
        let parents0: Vec<Option<DocId>> =
            doc_ids.iter().map(|d| replicas[0].parent_of(d)).collect();
        for (i, c) in replicas.iter().enumerate().skip(1) {
            let parents: Vec<Option<DocId>> = doc_ids.iter().map(|d| c.parent_of(d)).collect();
            prop_assert_eq!(&parents, &parents0, "hierarchy diverged at replica {}", i);
        }
        // …and it is a valid forest: walking up from any node terminates
        // without revisiting (no cycles), in at most k steps.
        for d in &doc_ids {
            let mut seen = std::collections::HashSet::new();
            let mut cur = Some(d.clone());
            while let Some(c) = cur {
                prop_assert!(seen.insert(c.clone()), "cycle through {}", c);
                cur = replicas[0].parent_of(&c);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Issue links: the edge set is an add-wins union.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// `edges` is an add-wins set keyed by the whole edge triple.
    /// Concurrent adds union; concurrent add/remove of the same edge resolves
    /// deterministically; the converged edge set is identical everywhere.
    #[test]
    fn edge_set_converges(
        n_replicas in 2usize..=3,
        ops in prop::collection::vec((0u8..3, 0usize..4, 0usize..4, any::<bool>()), 0..40),
    ) {
        let ws = SpaceId::mint(&SystemUlidSource);
        let base = CatalogDoc::create(&ws, "test", None, &tester()).unwrap();
        let doc_ids: Vec<DocId> = (0..4).map(|_| DocId::mint(&SystemUlidSource)).collect();
        base.apply(&ctx());
        let snap = base.snapshot().unwrap();

        let replicas: Vec<CatalogDoc> =
            (0..n_replicas).map(|_| catalog_replica_from(&snap)).collect();

        for (who, from, to, add) in &ops {
            if from == to {
                continue;
            }
            let c = &replicas[(*who as usize) % n_replicas];
            if *add {
                c.edge_add(&doc_ids[*from], "blocks", &doc_ids[*to]).unwrap();
            } else {
                let _ = c.edge_remove(&doc_ids[*from], "blocks", &doc_ids[*to]).unwrap();
            }
            c.apply(&ctx());
        }

        let docs: Vec<&CatalogDoc> = replicas.iter().collect();
        sync_all(&docs);

        assert_deep_values_converged(&docs);

        let key = |e: &lait::catalog::Edge| format!("{}|{}|{}", e.from, e.kind, e.to);
        let mut edges0: Vec<String> = replicas[0].edges().iter().map(&key).collect();
        edges0.sort();
        for (i, c) in replicas.iter().enumerate().skip(1) {
            let mut edges: Vec<String> = c.edges().iter().map(&key).collect();
            edges.sort();
            prop_assert_eq!(&edges, &edges0, "edge set diverged at replica {}", i);
        }
    }
}
