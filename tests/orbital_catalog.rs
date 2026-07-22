//! Deterministic Catalog formation gates (plan M4): the crash-resumable
//! `InitializeTracker` bootstrap record, exact signed-action replay at every
//! injected fault, deterministic Catalog identity, and typed
//! `WorldStateCorrupt` for missing/misplaced/duplicated Catalog state.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use lait::orbital::{read_bootstrap_record, BootstrapFault, BootstrapPhase, OrbitalMechanics};
use lait::world::contract;
use runtime::{World, WorldContext, WorldError, WorldQuery};

const FOUNDER_SEED: [u8; 32] = [71u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_home(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-cat-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Query the formed space's snapshot through a real docked Session.
fn snapshot_projects(home: &std::path::Path, mech: &OrbitalMechanics) -> usize {
    let rt = runtime::Runtime::open(
        lait::orbital::orbital_store_root(home),
        runtime::RuntimeBuilder::new()
            .register(
                lait::world::IssuesWorld::registration(),
                std::sync::Arc::new(lait::world::IssuesWorld::new()),
            )
            .build()
            .unwrap(),
        std::sync::Arc::new(mech.clone()),
        std::sync::Arc::new(mech.clone()),
    );
    let station = rt
        .orbit(&mech.space())
        .unwrap()
        .activate(runtime::ActivationOptions::offline())
        .unwrap();
    let identity = runtime::Runtime::identity_from_seed(&FOUNDER_SEED);
    let session = station.dock(&contract::world_id(), &identity).unwrap();
    let projection = session
        .query(runtime::WorldQuery {
            schema: contract::issue_schema(),
            schema_version: contract::ISSUE_SCHEMA_VERSION,
            payload: contract::IssueQuery::Snapshot.to_json(),
        })
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&projection.bytes).unwrap();
    let n = v["catalog"]["projects"].as_object().map(|m| m.len());
    let _ = station.go_dormant();
    n.unwrap_or(0)
}

#[test]
fn formation_resumes_the_exact_signed_action_across_every_fault() {
    for fault in [
        BootstrapFault::BeforeRecord,
        BootstrapFault::AfterRecord,
        BootstrapFault::BeforeSubmit,
        BootstrapFault::BeforeComplete,
    ] {
        let home = temp_home("fault");
        let err = match lait::orbital::form_space_with_fault(
            &home,
            &FOUNDER_SEED,
            "Fault Space",
            None,
            Some(fault),
        ) {
            Err(e) => e,
            Ok(_) => panic!("the injected fault must interrupt formation"),
        };
        assert!(err.to_string().contains("injected fault"), "{err}");

        let space = lait::orbital::discover_space_id(&home).expect("the Space store exists");
        let interrupted = read_bootstrap_record(&home, &space);
        match fault {
            BootstrapFault::BeforeRecord => {
                assert!(interrupted.is_none(), "no record before the record write")
            }
            _ => {
                let rec = interrupted.clone().expect("the record is durable");
                assert_eq!(rec.phase, BootstrapPhase::Recorded);
                assert_eq!(rec.space, space.as_str());
            }
        }

        // Resume: the EXACT persisted signed bytes replay; nothing is
        // reconstructed with a fresh timestamp/id/signature.
        let (mech, _coords) =
            lait::orbital::form_space(&home, &FOUNDER_SEED, "Fault Space").unwrap();
        let complete = read_bootstrap_record(&home, &space).expect("record complete");
        assert_eq!(complete.phase, BootstrapPhase::Complete);
        if let Some(rec) = interrupted {
            assert_eq!(
                rec.signed_action, complete.signed_action,
                "resume replays the identical signed action bytes ({fault:?})"
            );
            assert_eq!(rec.request_id, complete.request_id);
            assert_eq!(rec.canonical_intent_bytes, complete.canonical_intent_bytes);
        }
        // Exactly one initialization: one project, no duplicate Catalog state.
        assert_eq!(
            snapshot_projects(&home, &mech),
            1,
            "exactly one initial project after resume ({fault:?})"
        );
        // A THIRD run changes nothing (idempotent by the durable record).
        let (mech2, _c) = lait::orbital::form_space(&home, &FOUNDER_SEED, "Fault Space").unwrap();
        assert_eq!(snapshot_projects(&home, &mech2), 1);
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn the_catalog_identity_is_deterministic_per_space() {
    let home_a = temp_home("det-a");
    let home_b = temp_home("det-b");
    let (mech_a, _c) = lait::orbital::form_space(&home_a, &FOUNDER_SEED, "A").unwrap();
    let (mech_b, _c) = lait::orbital::form_space(&home_b, &[72u8; 32], "B").unwrap();
    let key_a = contract::catalog_key(&mech_a.space());
    // Recomputation is stable.
    assert_eq!(key_a, contract::catalog_key(&mech_a.space()));
    // A different Space derives a different Catalog identity.
    assert_ne!(key_a, contract::catalog_key(&mech_b.space()));
    let _ = std::fs::remove_dir_all(&home_a);
    let _ = std::fs::remove_dir_all(&home_b);
}

// ---- WorldStateCorrupt: missing / misplaced / duplicated Catalog ----------

/// A stub committed snapshot: collaborative views by key, plus the
/// catalog-schema binding set the World enumerates.
#[derive(Default)]
struct StubReader {
    views: BTreeMap<replica::ids::BodyKey, replica::CollaborativeView>,
    catalog_bodies: Vec<replica::ids::BodyKey>,
}

impl runtime::BodyReader for StubReader {
    fn read_body(&self, _key: &replica::ids::BodyKey) -> Option<Vec<u8>> {
        None
    }
    fn read_collaborative_body(
        &self,
        key: &replica::ids::BodyKey,
    ) -> Option<replica::CollaborativeView> {
        self.views.get(key).cloned()
    }
    fn bodies_with_schema(
        &self,
        _world: &replica::ids::WorldId,
        _schema: &replica::ids::SchemaId,
    ) -> Vec<replica::ids::BodyKey> {
        self.catalog_bodies.clone()
    }
}

fn principal(space: &mechanics::ids::SpaceId) -> runtime::PrincipalFacts {
    let device = mechanics::crypto::device_from_seed(&FOUNDER_SEED);
    runtime::PrincipalFacts {
        actor: mechanics::ids::ActorId::from_incept_hash(&"ab".repeat(32)),
        station: mechanics::ids::StationId::from_device(&device).unwrap(),
        device,
        space: space.clone(),
        standing: runtime::Standing::new(vec![]),
        authority_frontier: replica::frontier::AuthorityFrontier::from_canonical_bytes(vec![]),
    }
}

fn snapshot_query(
    world: &lait::world::IssuesWorld,
    ctx: &WorldContext<'_>,
) -> Result<(), WorldError> {
    world
        .query(
            ctx,
            WorldQuery {
                schema: contract::issue_schema(),
                schema_version: contract::ISSUE_SCHEMA_VERSION,
                payload: contract::IssueQuery::Snapshot.to_json(),
            },
        )
        .map(|_| ())
}

#[test]
fn misplaced_and_duplicate_catalogs_are_typed_corrupt_never_repaired() {
    let space = mechanics::ids::SpaceId::mint(&mechanics::ids::SystemUlidSource);
    let world = lait::world::IssuesWorld::new();
    let facts = principal(&space);
    let right = contract::catalog_key(&space);
    let wrong = replica::ids::BodyKey::new(
        contract::world_id(),
        replica::ids::BodyId::from_bytes([9u8; 16]),
    );

    // A catalog-schema Body at the WRONG key only: corrupt (never selected).
    let mut reader = StubReader::default();
    reader.catalog_bodies = vec![wrong.clone()];
    reader
        .views
        .insert(wrong.clone(), replica::CollaborativeView::default());
    let ctx = WorldContext::with_reads(&facts, &reader, [0u8; 32]);
    assert!(
        matches!(
            snapshot_query(&world, &ctx),
            Err(WorldError::WorldStateCorrupt)
        ),
        "a misplaced catalog is never chosen"
    );

    // The right key AND a second semantic catalog: corrupt (never merged).
    let mut reader = StubReader::default();
    reader.catalog_bodies = vec![right.clone(), wrong.clone()];
    reader
        .views
        .insert(right.clone(), replica::CollaborativeView::default());
    reader
        .views
        .insert(wrong, replica::CollaborativeView::default());
    let ctx = WorldContext::with_reads(&facts, &reader, [0u8; 32]);
    assert!(
        matches!(
            snapshot_query(&world, &ctx),
            Err(WorldError::WorldStateCorrupt)
        ),
        "a duplicate catalog is never merged"
    );

    // The right key bound as a catalog but unreadable under the collaborative
    // model (wrong model/encoding): corrupt, not "missing".
    let mut reader = StubReader::default();
    reader.catalog_bodies = vec![right.clone()];
    let ctx = WorldContext::with_reads(&facts, &reader, [0u8; 32]);
    assert!(
        matches!(
            snapshot_query(&world, &ctx),
            Err(WorldError::WorldStateCorrupt)
        ),
        "a wrong-model catalog is corrupt"
    );

    // No catalog at all: legitimate pre-adoption state, NOT corrupt (a joiner
    // adopts through Manifest synchronization).
    let reader = StubReader::default();
    let ctx = WorldContext::with_reads(&facts, &reader, [0u8; 32]);
    assert!(snapshot_query(&world, &ctx).is_ok());
}
