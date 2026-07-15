//! Property-based CRDT convergence tests (SCHEMA §1: "all merge semantics live
//! in Loro"). Each test drives a proptest-generated sequence of operations
//! across 2–3 independent replicas of one document, exchanges Loro updates
//! all-pairs until quiescence, and asserts every replica reaches byte-identical
//! state (`LoroDoc::get_deep_value()` equality) plus the schema-level invariant
//! that the merge rule promises:
//!
//!   * `issue_lww_converges`               — S§5.1 last-writer-wins registers
//!   * `assignees_labels_map_union_converges` — S§5.2 present-key set (map-union)
//!   * `board_movable_list_converges`      — S§5.5 board ordering (movable list)
//!   * `catalog_docs_grow_set_converges`   — S§4  the `docs` grow-only key set
//!
//! Determinism rule (the plan's "inject clocks/seeds"): all randomness that
//! affects assertions flows through proptest inputs. `SystemUlidSource` is used
//! ONLY to mint ids (whose *values* never enter an assertion — only their
//! identity/uniqueness does), and `created_at` is a fixed constant. No
//! wall-clock or RNG is read inside an assertion path.

use loro::{ExportMode, LoroDoc};
use proptest::prelude::*;

use lait::catalog::CatalogDoc;
use lait::dto::Priority;
use lait::ids::{DocId, LabelId, ProjectId, SystemUlidSource, UserId, WorkspaceId};
use lait::issue::{IssueDoc, NewIssue};

/// A fixed creation timestamp — never varied, so it can never be the reason two
/// replicas differ.
const CREATED_AT: u64 = 1_000;

/// The core sync primitive (SCHEMA §8): all-pairs exchange of version-vector
/// deltas. For every ordered pair (i, j) we ship i's ops that j is missing
/// (`export(updates(j.oplog_vv()))`) into j. Running the full all-pairs loop
/// three times drives the mesh to quiescence even when an update produced in an
/// earlier round only becomes relevant to a third replica after a later import.
fn sync_all(docs: &[&LoroDoc]) {
    for _ in 0..3 {
        for i in 0..docs.len() {
            for j in 0..docs.len() {
                if i == j {
                    continue;
                }
                let missing = docs[j].oplog_vv();
                let update = docs[i]
                    .export(ExportMode::updates(&missing))
                    .expect("export updates");
                if !update.is_empty() {
                    docs[j].import(&update).expect("import updates");
                }
            }
        }
    }
}

/// Assert every replica's materialized deep value equals replica 0's — the
/// definition of convergence (all replicas agree on the whole document state).
fn assert_deep_values_converged(docs: &[&LoroDoc]) {
    let base = docs[0].get_deep_value();
    for (i, d) in docs.iter().enumerate().skip(1) {
        assert_eq!(
            d.get_deep_value(),
            base,
            "replica {i} deep value diverged from replica 0",
        );
    }
}

/// Fork an issue replica off a shared base snapshot. Replicas MUST descend from
/// a common base doc: two docs created independently would share no history root
/// and their overlapping container layouts could not merge. Importing the same
/// snapshot into a fresh `LoroDoc` gives a replica the shared root while Loro
/// still assigns it a distinct internal peer id.
fn issue_replica_from(snap: &[u8]) -> IssueDoc {
    let d = LoroDoc::new();
    d.import(snap).expect("import base issue snapshot");
    IssueDoc::from_doc(d)
}

/// Fork a catalog replica off a shared base snapshot (same rationale as above).
fn catalog_replica_from(snap: &[u8]) -> CatalogDoc {
    let d = LoroDoc::new();
    d.import(snap).expect("import base catalog snapshot");
    CatalogDoc::from_doc(d)
}

fn base_issue() -> IssueDoc {
    IssueDoc::create(NewIssue {
        doc_id: DocId::mint(&SystemUlidSource),
        workspace_id: WorkspaceId::mint(&SystemUlidSource),
        project_id: ProjectId::mint(&SystemUlidSource),
        title: "base title".into(),
        priority: Priority::None,
        created_by: UserId::from_key_string("a".repeat(64)),
        created_at: CREATED_AT,
        body: None,
    })
    .expect("create base issue")
}

// ---------------------------------------------------------------------------
// Test 1 — LWW registers (S§5.1): title / status / priority.
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

    /// S§5.1: title/status/priority are single-key LWW registers. Under any
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
            r.commit(); // a LoroDoc must commit before its ops can be exported
        }

        let docs: Vec<&LoroDoc> = replicas.iter().map(|r| r.doc()).collect();
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
// Test 2 — present-key sets (S§5.2): assignees & labels as map-union.
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

    /// S§5.2: assignees/labels are `LoroMap<Id, true>` present-key sets. Adds of
    /// DIFFERENT keys on different replicas union; concurrent add-vs-remove of
    /// the SAME key resolves to a single per-key LWW winner (deterministic, no
    /// panic). After sync the resolved key SET must be identical everywhere.
    #[test]
    fn assignees_labels_map_union_converges(
        n_replicas in 2usize..=3,
        ops in prop::collection::vec((0u8..3, set_op_strategy()), 0..40),
    ) {
        // Fixed pools of 4 users and 4 labels, minted once and shared by every
        // replica (so add/remove target the same keys across replicas).
        let users: Vec<UserId> =
            (0..4).map(|i| UserId::from_key_string(format!("{:064x}", i + 1))).collect();
        let labels: Vec<LabelId> = (0..4).map(|_| LabelId::mint(&SystemUlidSource)).collect();

        let snap = base_issue().snapshot().unwrap();
        let replicas: Vec<IssueDoc> = (0..n_replicas).map(|_| issue_replica_from(&snap)).collect();

        for (who, op) in &ops {
            let r = &replicas[(*who as usize) % n_replicas];
            match op {
                SetOp::AddAssignee(i) => r.add_assignee(&users[*i]).unwrap(),
                SetOp::RemoveAssignee(i) => r.remove_assignee(&users[*i]).unwrap(),
                SetOp::AddLabel(i) => r.add_label(&labels[*i]).unwrap(),
                SetOp::RemoveLabel(i) => r.remove_label(&labels[*i]).unwrap(),
            }
            r.commit();
        }

        let docs: Vec<&LoroDoc> = replicas.iter().map(|r| r.doc()).collect();
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
// Test 3 — board ordering (S§5.5): a movable list reorders without duplication.
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

    /// S§5.5: the board is a `LoroMovableList` used for ordering only. Starting
    /// from a shared board of K issues, concurrent reorders across replicas must
    /// converge to ONE identical raw order, whose S§5.5 projection (dedup) is a
    /// permutation of the same K docs. (The raw list may hold a duplicate after
    /// a concurrent move-of-the-same-doc, since `board_move` reinserts rather
    /// than `mov`s — see the assertion block; dedup is a projection-time rule.)
    #[test]
    fn board_movable_list_converges(
        k in 3usize..=6,
        n_replicas in 2usize..=3,
        ops in prop::collection::vec((0u8..3, board_op_strategy()), 0..40),
    ) {
        // Shared base catalog: one project + K issues already on the board.
        let ws = WorkspaceId::mint(&SystemUlidSource);
        let base = CatalogDoc::create(&ws, "test").unwrap();
        let project = ProjectId::mint(&SystemUlidSource);
        base.add_project(&project, "Engineering", "ENG", "blue").unwrap();

        let mut doc_ids: Vec<DocId> = Vec::with_capacity(k);
        for n in 0..k {
            let issue = IssueDoc::create(NewIssue {
                doc_id: DocId::mint(&SystemUlidSource),
                workspace_id: ws.clone(),
                project_id: project.clone(),
                title: format!("issue {n}"),
                priority: Priority::None,
                created_by: UserId::from_key_string("a".repeat(64)),
                created_at: CREATED_AT,
                body: None,
            })
            .unwrap();
            let id = issue.doc_id().unwrap();
            base.upsert_row(&issue).unwrap();
            base.board_insert_bottom(&project, &id).unwrap();
            doc_ids.push(id);
        }
        base.doc().commit();
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
            c.doc().commit();
        }

        let docs: Vec<&LoroDoc> = replicas.iter().map(|c| c.doc()).collect();
        sync_all(&docs);

        assert_deep_values_converged(&docs);

        let order0 = replicas[0].board_order(&project);

        // Convergence proper: every replica agrees on the EXACT raw movable-list
        // order — the CRDT guarantee. `board_move` is implemented as
        // delete-then-insert of the doc id (catalog.rs), not the movable list's
        // in-place `mov`, so two replicas concurrently moving the SAME doc each
        // contribute a surviving insert and the merged raw list can carry a
        // duplicate. That is expected: S§5.5 makes dedup a *projection-time*
        // render rule (`board_order` returns the raw list, per its own doc
        // comment), and Loro still totally-orders those concurrent inserts, so
        // all replicas land on the identical raw list.
        for (i, c) in replicas.iter().enumerate() {
            prop_assert_eq!(c.board_order(&project), order0.clone(), "board order diverged at replica {}", i);
        }

        // The S§5.5 projection (dedup) is well-formed: exactly the K seeded docs,
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
// Test 4 — the docs grow-only key set (S§4): concurrently registered docs union.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// S§4: `Catalog.docs` is a keyed set that only grows (registering an issue
    /// adds its `DocId` key). When replicas register DIFFERENT issues, after
    /// sync every replica's `doc_ids()` must equal the identical union set.
    #[test]
    fn catalog_docs_grow_set_converges(
        n_replicas in 2usize..=3,
        registrations in prop::collection::vec(0u8..3, 0..30),
    ) {
        let ws = WorkspaceId::mint(&SystemUlidSource);
        let base = CatalogDoc::create(&ws, "test").unwrap();
        let project = ProjectId::mint(&SystemUlidSource);
        base.add_project(&project, "Engineering", "ENG", "blue").unwrap();
        base.doc().commit();
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
                workspace_id: ws.clone(),
                project_id: project.clone(),
                title: "grow".into(),
                priority: Priority::None,
                created_by: UserId::from_key_string("a".repeat(64)),
                created_at: CREATED_AT,
                body: None,
            })
            .unwrap();
            expected.push(issue.doc_id().unwrap());
            c.upsert_row(&issue).unwrap();
            c.doc().commit();
        }
        expected.sort();

        let docs: Vec<&LoroDoc> = replicas.iter().map(|c| c.doc()).collect();
        sync_all(&docs);

        assert_deep_values_converged(&docs);

        for (i, c) in replicas.iter().enumerate() {
            let mut ids = c.doc_ids();
            ids.sort();
            prop_assert_eq!(ids, expected.clone(), "docs set diverged at replica {}", i);
        }
    }
}
