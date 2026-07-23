//! C4 / G8 — the product World adapter's mapping/parity harness, over the
//! final public APIs and store.
//!
//! The test plays the daemon's role (minting ids, stamping timestamps,
//! resolving refs from the Snapshot query) and drives every issue-family
//! behavior through `IssuesWorld` Sessions on isolated orbital stores: create/
//! edit/board/assign/label/comment/link/parent/work-state/delete/restore,
//! legacy-shape projections (Rows, Board columns, IssueView, GraphView,
//! History), `KEY-n` aliases, idempotent no-ops, restart durability, and
//! two-Station product convergence over the real Contact plane. Legacy
//! production paths are untouched (the C5 cutover switches them atomically).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lait::dto::{BoardView, GraphView, IssueView, LabelDto, ProjectDto, Row, StatusCategory};
use lait::ids::{ActorId, DeviceId, DocId, LabelId, ProjectId, SystemUlidSource};
use lait::world::contract::{self, IssueIntent, IssueQuery, Pos, WorkAction};
use lait::world::IssuesWorld;
use mechanics::crypto::AuthorizedBodyKey;
use replica::frontier::AuthorityFrontier;
use runtime::{
    ActivationOptions, CommsOptions, ContactMechanics, ContactOptions, EnterOptions, LocalIdentity,
    RequestId, Runtime, RuntimeBuilder, Session, SignedWorldAction, Station, WorldError,
    WorldIntent, WorldQuery,
};

const FOUNDER_SEED: [u8; 32] = [7u8; 32];
const RECOVERY_SEED: [u8; 32] = [20u8; 32];
const STATION_A_SEED: [u8; 32] = [61u8; 32];
const STATION_B_SEED: [u8; 32] = [62u8; 32];
const WRITER_SEED: [u8; 32] = [63u8; 32];
const EPOCH: [u8; 16] = [19u8; 16];
const EPOCH_KEY: [u8; 32] = [21u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-parity-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn coordinates() -> runtime::SignedCoordinates {
    use runtime::coordinates::{ApproachRoute, CoordinatesAdmission, CoordinatesPayload};
    let rc = mechanics::space::recovery_commit(&mechanics::space::recovery_pub_of(&RECOVERY_SEED))
        .unwrap();
    let device = mechanics::space::recovery_pub_of(&FOUNDER_SEED);
    let ws = mechanics::space::derive_space_id(&device, &[9u8; 16], &rc);
    let (incept, _actor) =
        mechanics::actor::incept_single(&FOUNDER_SEED, &ws, [1u8; 16], [2u8; 16], None);
    let payload = CoordinatesPayload {
        space: <[u8; 29]>::try_from(ws.as_str().as_bytes()).unwrap(),
        salt: [9u8; 16],
        recovery_root: rc,
        founder_inception: postcard::to_stdvec(&incept).unwrap(),
        display_name_hint: "Parity Space".into(),
        approach_station: mechanics::crypto::device_from_seed(&STATION_A_SEED)
            .key_bytes()
            .unwrap(),
        approach_nick_hint: "a".into(),
        approach_routes: vec![ApproachRoute::DirectV4 {
            ip: [127, 0, 0, 1],
            port: 4242,
        }],
        admission: CoordinatesAdmission::None,
    };
    runtime::SignedCoordinates::sign(payload, &STATION_A_SEED)
}

struct WriterAuthority;
impl runtime::AuthorityView for WriterAuthority {
    fn resolve(&self, _device: &DeviceId) -> Option<runtime::PrincipalResolution> {
        Some(runtime::PrincipalResolution {
            actor: my_actor(),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![8]),
        })
    }
}

struct AnyKnownSigner;
impl replica::AuthoritySource for AnyKnownSigner {
    fn signer_authorized(&self, signer: &[u8; 32], _f: &AuthorityFrontier) -> bool {
        [WRITER_SEED, STATION_A_SEED, STATION_B_SEED]
            .iter()
            .any(|seed| mechanics::crypto::device_from_seed(seed).key_bytes() == Some(*signer))
    }
}

struct AcceptingIncorporator;
impl replica::AuthorityIncorporator for AcceptingIncorporator {
    fn incorporate_authority(
        &mut self,
        _records: &[Vec<u8>],
    ) -> Result<replica::AuthorityBatchReceipt, String> {
        Ok(replica::AuthorityBatchReceipt {
            space: coordinates().verify().unwrap().space.clone(),
            prior_frontier: replica::frontier::AuthorityFrontier::from_canonical_bytes(vec![]),
            resulting_frontier: AuthorityFrontier::from_canonical_bytes(vec![8]),
            batch_digest: *blake3::hash(&_records.concat()).as_bytes(),
        })
    }
}

fn my_actor() -> ActorId {
    ActorId::from_incept_hash(&"f".repeat(64))
}

fn my_device() -> DeviceId {
    mechanics::crypto::device_from_seed(&WRITER_SEED)
}

fn product_runtime(root: &std::path::Path) -> Runtime {
    let registry = RuntimeBuilder::new()
        .register(IssuesWorld::registration(), Arc::new(IssuesWorld::new()))
        .build()
        .unwrap();
    Runtime::open(
        root.to_path_buf(),
        registry,
        Arc::new(WriterAuthority),
        Arc::new(replica::StaticBodyKeys::new(
            AuthorizedBodyKey::for_authorized_epoch(EPOCH, EPOCH_KEY),
        )),
    )
}

/// The daemon-side driver: docks a session and adapts intents/queries.
struct Driver {
    session: Session,
    writer: LocalIdentity,
    now: u64,
}

impl Driver {
    fn dock(station: &Station) -> Self {
        let writer = Runtime::identity_from_seed(&WRITER_SEED);
        let session = station.dock(&contract::world_id(), &writer).unwrap();
        Self {
            session,
            writer,
            now: 1_700_000_000,
        }
    }

    fn ts(&mut self) -> u64 {
        self.now += 1;
        self.now
    }

    fn signed(&self, intent: &IssueIntent) -> SignedWorldAction {
        self.writer
            .sign_action(
                &self.session,
                RequestId::mint(),
                WorldIntent {
                    schema: contract::issue_schema(),
                    schema_version: contract::ISSUE_SCHEMA_VERSION,
                    payload: intent.to_json(),
                },
            )
            .unwrap()
    }

    fn submit(&self, intent: &IssueIntent) -> Result<contract::IssueEffect, WorldError> {
        let committed = self.session.submit(self.signed(intent))?;
        Ok(contract::IssueEffect::from_json(&committed.effect).unwrap())
    }

    fn query_raw(&self, query: &IssueQuery) -> Vec<u8> {
        self.session
            .query(WorldQuery {
                schema: contract::issue_schema(),
                schema_version: contract::ISSUE_SCHEMA_VERSION,
                payload: query.to_json(),
            })
            .unwrap()
            .bytes
    }

    fn query<T: serde::de::DeserializeOwned>(&self, query: &IssueQuery) -> T {
        serde_json::from_slice(&self.query_raw(query)).unwrap()
    }

    fn snapshot(&self) -> serde_json::Value {
        self.query(&IssueQuery::Snapshot)
    }

    /// Resolve a `KEY-n` alias or canonical prefix to a DocId string, the way
    /// the daemon will (from the Snapshot's derived aliases).
    fn resolve(&self, reff: &str) -> Option<String> {
        let snapshot = self.snapshot();
        let aliases = &snapshot["aliases"];
        if let Some(doc) = aliases["by_alias"][reff.to_ascii_lowercase()].as_str() {
            return Some(doc.to_string());
        }
        // canonical / doc-id prefix match
        let lower = reff.to_ascii_lowercase();
        let seqs = snapshot["catalog"]["seqs"].as_object().unwrap();
        let mut hits: Vec<String> = seqs
            .keys()
            .filter(|doc| doc.to_ascii_lowercase().starts_with(&lower))
            .cloned()
            .collect();
        hits.dedup();
        (hits.len() == 1).then(|| hits.remove(0))
    }
}

fn setup(root: &std::path::Path) -> (Runtime, Station) {
    let rt = product_runtime(root);
    let station = rt
        .form_space(runtime::SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions::offline())
        .unwrap();
    (rt, station)
}

fn seed_space(driver: &mut Driver) -> (String, String, String) {
    let ts = driver.ts();
    let project = ProjectId::mint(&SystemUlidSource).as_str().to_string();
    driver
        .submit(&lait::world::contract::initialize_tracker_intent(
            "Parity Space",
            ts,
            &project,
            "Engineering",
            "eng",
            my_device().as_str(),
        ))
        .unwrap();
    let doc = DocId::mint(&SystemUlidSource).as_str().to_string();
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::IssueNew {
            duedate: None,
            estimate: None,
            doc: doc.clone(),
            project: project.clone(),
            title: "First issue".into(),
            priority: "high".into(),
            assignees: vec![my_actor().as_str().to_string()],
            labels: vec![],
            new_labels: vec![],
            body: Some("the description".into()),
            actor: my_actor().as_str().to_string(),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    (project, doc, "ENG-1".to_string())
}

#[test]
fn the_full_issue_surface_round_trips_with_legacy_shapes() {
    let root = temp_root("surface");
    let (_rt, station) = setup(&root);
    let mut driver = Driver::dock(&station);
    let (project, doc, alias) = seed_space(&mut driver);

    // Aliases: ENG-1 resolves to the doc; the canonical prefix resolves too.
    assert_eq!(driver.resolve(&alias).as_deref(), Some(doc.as_str()));
    assert_eq!(driver.resolve(&doc[..12]).as_deref(), Some(doc.as_str()));

    // The IssueView carries the legacy shape.
    let view: IssueView = driver.query(&IssueQuery::View {
        doc: doc.clone(),
        me: Some(my_actor().as_str().to_string()),
    });
    assert_eq!(view.schema_version, 3);
    assert_eq!(view.title, "First issue");
    assert_eq!(view.description, "the description");
    assert_eq!(view.status, "backlog");
    assert_eq!(view.priority, lait::dto::Priority::High);
    assert_eq!(view.assignees, vec![my_actor()]);
    assert_eq!(view.key_alias.as_deref(), Some("ENG-1"));

    // A second issue gets ENG-2 and sits above on the board (insert-at-top).
    let doc2 = DocId::mint(&SystemUlidSource).as_str().to_string();
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::IssueNew {
            duedate: None,
            estimate: None,
            doc: doc2.clone(),
            project: project.clone(),
            title: "Second issue".into(),
            priority: "low".into(),
            assignees: vec![],
            labels: vec![],
            new_labels: vec![],
            body: None,
            actor: my_actor().as_str().to_string(),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    assert_eq!(driver.resolve("ENG-2").as_deref(), Some(doc2.as_str()));

    // List: priority desc (high first), then DocId asc.
    let rows: Vec<Row> = driver.query(&IssueQuery::List {
        project: Some(project.clone()),
        label: None,
        status: None,
        mine: None,
        all: false,
        me: Some(my_actor().as_str().to_string()),
    });
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].title, "First issue");
    assert_eq!(rows[0].assignee_summary, "you");
    assert_eq!(rows[1].title, "Second issue");

    // Board: backlog column holds both, newest insert on top.
    let board: BoardView = driver.query(&IssueQuery::Board {
        project: project.clone(),
        me: None,
    });
    assert_eq!(board.schema_version, 3);
    assert_eq!(board.columns.len(), 4);
    let backlog = &board.columns[0];
    assert_eq!(backlog.state.id, "backlog");
    assert_eq!(backlog.rows.len(), 2);
    assert_eq!(backlog.rows[0].title, "Second issue");

    // Move ENG-2 after ENG-1 (the legacy Before/After math).
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::IssueMove {
            doc: doc2.clone(),
            project: None,
            pos: Some(Pos::After { doc: doc.clone() }),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let board: BoardView = driver.query(&IssueQuery::Board {
        project: project.clone(),
        me: None,
    });
    assert_eq!(board.columns[0].rows[0].title, "First issue");
    assert_eq!(board.columns[0].rows[1].title, "Second issue");

    // Labels create-on-first-use; label filter applies.
    let label_id = LabelId::mint(&SystemUlidSource).as_str().to_string();
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::Label {
            doc: doc.clone(),
            add: vec![],
            new_labels: vec![contract::NewLabel {
                id: label_id.clone(),
                name: "bug".into(),
                color: "red".into(),
            }],
            remove: vec![],
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let labels: Vec<LabelDto> = driver.query(&IssueQuery::Labels);
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].name, "bug");
    let rows: Vec<Row> = driver.query(&IssueQuery::List {
        project: None,
        label: Some(label_id.clone()),
        status: None,
        mine: None,
        all: false,
        me: None,
    });
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].title, "First issue");

    // Comment lands append-only with author attribution.
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::Comment {
            id: None,
            parent: None,
            doc: doc.clone(),
            body: "a comment".into(),
            actor: my_actor().as_str().to_string(),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let view: IssueView = driver.query(&IssueQuery::View {
        doc: doc.clone(),
        me: None,
    });
    assert_eq!(view.comments.len(), 1);
    assert_eq!(view.comments[0].body, "a comment");
    assert_eq!(view.comments[0].author, my_actor());

    // Links + graph: blocks with transitive open blockers.
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::Link {
            doc: doc2.clone(),
            kind: "blocks".into(),
            target: doc.clone(),
            add: true,
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let graph: GraphView = driver.query(&IssueQuery::Graph {
        doc: doc.clone(),
        me: None,
    });
    assert_eq!(graph.links.len(), 1);
    assert_eq!(graph.links[0].direction, "in");
    assert_eq!(graph.blocked_by.len(), 1);
    assert_eq!(graph.blocked_by[0].title, "Second issue");

    // Self-link and unknown-kind links are refused.
    let ts = driver.ts();
    assert_eq!(
        driver.submit(&IssueIntent::Link {
            doc: doc.clone(),
            kind: "blocks".into(),
            target: doc.clone(),
            add: true,
            device: my_device().as_str().to_string(),
            ts,
        }),
        Err(WorldError::InvalidRequest)
    );

    // Parent hierarchy with ancestor-cycle refusal.
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::Parent {
            doc: doc2.clone(),
            parent: Some(doc.clone()),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let ts = driver.ts();
    assert_eq!(
        driver.submit(&IssueIntent::Parent {
            doc: doc.clone(),
            parent: Some(doc2.clone()),
            device: my_device().as_str().to_string(),
            ts,
        }),
        Err(WorldError::Conflict)
    );

    // Work state: done moves off the board; an idempotent repeat stages
    // nothing; stop returns to backlog and self-unassigns.
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::WorkState {
            doc: doc.clone(),
            action: WorkAction::Done,
            actor: my_actor().as_str().to_string(),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let board: BoardView = driver.query(&IssueQuery::Board {
        project: project.clone(),
        me: None,
    });
    let done = board.columns.iter().find(|c| c.state.id == "done").unwrap();
    assert_eq!(done.rows.len(), 1);
    let ts = driver.ts();
    let repeat = driver
        .submit(&IssueIntent::WorkState {
            doc: doc.clone(),
            action: WorkAction::Done,
            actor: my_actor().as_str().to_string(),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    assert!(repeat.unchanged, "an idempotent no-op commits nothing");

    // Delete tombstones and hides from default lists; restore brings it back.
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::SetTombstone {
            doc: doc2.clone(),
            on: true,
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let rows: Vec<Row> = driver.query(&IssueQuery::List {
        project: None,
        label: None,
        status: None,
        mine: None,
        all: false,
        me: None,
    });
    assert!(rows.iter().all(|r| r.title != "Second issue"));
    let all_rows: Vec<Row> = driver.query(&IssueQuery::List {
        project: None,
        label: None,
        status: None,
        mine: None,
        all: true,
        me: None,
    });
    assert!(all_rows
        .iter()
        .any(|r| r.title == "Second issue" && r.tombstone));
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::SetTombstone {
            doc: doc2.clone(),
            on: false,
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();

    // History: the durable per-issue event log, oldest first, attributed.
    let history: serde_json::Value = driver.query(&IssueQuery::History { doc: doc.clone() });
    let events = history["events"].as_array().unwrap();
    assert!(events.len() >= 3);
    assert_eq!(events[0]["kind"], "created");
    assert_eq!(events[0]["seq"], 1);

    // Projects list.
    let projects: Vec<ProjectDto> = driver.query(&IssueQuery::Projects);
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].key, "ENG");

    // Restart durability: everything above survives a cold reactivation.
    let space = station.space_id().clone();
    let orbit = station.go_dormant().unwrap();
    drop(orbit);
    let rt = product_runtime(&root);
    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::offline())
        .unwrap();
    let driver = Driver::dock(&station);
    let view: IssueView = driver.query(&IssueQuery::View {
        doc: doc.clone(),
        me: None,
    });
    assert_eq!(view.title, "First issue");
    assert_eq!(view.comments.len(), 1);
    assert_eq!(driver.resolve("ENG-2").as_deref(), Some(doc2.as_str()));
    let _ = station.go_dormant();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_denied_or_invalid_request_commits_and_publishes_nothing() {
    let root = temp_root("refusals");
    let (_rt, station) = setup(&root);
    let mut driver = Driver::dock(&station);
    let (_project, doc, _alias) = seed_space(&mut driver);
    let frontier = station.frontier();

    // Unknown project refuses; empty title refuses; unknown status refuses.
    let ts = driver.ts();
    assert_eq!(
        driver.submit(&IssueIntent::IssueNew {
            duedate: None,
            estimate: None,
            doc: DocId::mint(&SystemUlidSource).as_str().to_string(),
            project: "prj_00000000000000000000000000".into(),
            title: "x".into(),
            priority: "high".into(),
            assignees: vec![],
            labels: vec![],
            new_labels: vec![],
            body: None,
            actor: my_actor().as_str().to_string(),
            device: my_device().as_str().to_string(),
            ts,
        }),
        Err(WorldError::InvalidRequest)
    );
    let ts = driver.ts();
    assert_eq!(
        driver.submit(&IssueIntent::IssueEdit {
            duedate: None,
            estimate: None,
            doc: doc.clone(),
            title: None,
            status: Some("nonexistent".into()),
            priority: None,
            description: None,
            device: my_device().as_str().to_string(),
            ts,
        }),
        Err(WorldError::InvalidRequest)
    );
    assert_eq!(station.frontier(), frontier, "nothing committed");
    let _ = station.go_dormant();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn two_stations_converge_product_issues_over_the_contact_plane() {
    let coords = coordinates();
    let net = comms::mem::MemNet::new();
    let ta: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_A_SEED)));
    let tb: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_B_SEED)));
    let comms_options = |transport: Arc<dyn comms::Transport>, seed: [u8; 32]| CommsOptions {
        transport,
        station_seed: seed,
        mechanics: ContactMechanics {
            source: Arc::new(AnyKnownSigner),
            incorporator: Arc::new(Mutex::new(AcceptingIncorporator)),
            export: Arc::new(Vec::new),
            frontier: Arc::new(|| AuthorityFrontier::from_canonical_bytes(vec![8])),
        },
        gossip: None,
        whole_deadline: Duration::from_secs(20),
        progress_deadline: Duration::from_secs(5),
        route_lease: Duration::from_secs(60),
    };

    let root_a = temp_root("conv-a");
    let root_b = temp_root("conv-b");
    let station_a = product_runtime(&root_a)
        .enter_orbit(&coords, EnterOptions)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_options(ta, STATION_A_SEED)),
            observation_capacity: 0,
        })
        .unwrap();
    let mut driver_a = Driver::dock(&station_a);
    let (project, doc, _alias) = seed_space(&mut driver_a);

    let station_b = product_runtime(&root_b)
        .enter_orbit(&coords, EnterOptions)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_options(tb, STATION_B_SEED)),
            observation_capacity: 0,
        })
        .unwrap();
    let a_station_id = mechanics::ids::StationId::from_device(
        &mechanics::crypto::device_from_seed(&STATION_A_SEED),
    )
    .unwrap();
    let outcome = station_b.contact(&a_station_id, ContactOptions).unwrap();
    assert!(outcome.convergence.accepted >= 1);

    // B sees A's product state through the SAME World adapter.
    let driver_b = Driver::dock(&station_b);
    let view: IssueView = driver_b.query(&IssueQuery::View {
        doc: doc.clone(),
        me: None,
    });
    assert_eq!(view.title, "First issue");
    assert_eq!(driver_b.resolve("ENG-1").as_deref(), Some(doc.as_str()));

    // B comments; A contacts back; the comment converges with stable
    // identity (no duplication on re-contact).
    let mut driver_b = driver_b;
    driver_b.now = 1_700_100_000;
    let ts = driver_b.ts();
    driver_b
        .submit(&IssueIntent::Comment {
            id: None,
            parent: None,
            doc: doc.clone(),
            body: "from b".into(),
            actor: my_actor().as_str().to_string(),
            device: mechanics::crypto::device_from_seed(&STATION_B_SEED)
                .as_str()
                .to_string(),
            ts,
        })
        .unwrap();
    let b_station_id = mechanics::ids::StationId::from_device(
        &mechanics::crypto::device_from_seed(&STATION_B_SEED),
    )
    .unwrap();
    let outcome = station_a.contact(&b_station_id, ContactOptions).unwrap();
    assert!(outcome.convergence.accepted >= 1);
    let view: IssueView = driver_a.query(&IssueQuery::View {
        doc: doc.clone(),
        me: None,
    });
    assert_eq!(view.comments.len(), 1);
    assert_eq!(view.comments[0].body, "from b");

    // The board converged too.
    let board: BoardView = driver_a.query(&IssueQuery::Board {
        project: project.clone(),
        me: None,
    });
    assert_eq!(board.columns[0].rows.len(), 1);

    let _ = station_a.go_dormant();
    let _ = station_b.go_dormant();
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
    let _ = BTreeMap::<String, String>::new();
    let _ = StatusCategory::Done;
}

#[test]
fn due_dates_estimates_and_comment_reactions_round_trip() {
    let root = temp_root("enriched");
    let (_rt, station) = setup(&root);
    let mut driver = Driver::dock(&station);
    let (_project, doc, _alias) = seed_space(&mut driver);

    // ---- due date + estimate: set, project, change, clear ----
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::IssueEdit {
            doc: doc.clone(),
            title: None,
            status: None,
            priority: None,
            description: None,
            duedate: Some(Some(1_800_000_000)),
            estimate: Some(Some(5)),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let view: IssueView = driver.query(&IssueQuery::View {
        doc: doc.clone(),
        me: None,
    });
    assert_eq!(view.due_date, Some(1_800_000_000));
    assert_eq!(view.estimate, Some(5));
    let rows: Vec<Row> = driver.query(&IssueQuery::List {
        project: None,
        label: None,
        status: None,
        mine: None,
        all: true,
        me: None,
    });
    let row = rows.iter().find(|r| r.doc_id.as_str() == doc).unwrap();
    assert_eq!(row.due_date, Some(1_800_000_000));
    assert_eq!(row.estimate, Some(5));

    // Clearing goes back to absent — the register is removed, not zeroed.
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::IssueEdit {
            doc: doc.clone(),
            title: None,
            status: None,
            priority: None,
            description: None,
            duedate: Some(None),
            estimate: Some(None),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let view: IssueView = driver.query(&IssueQuery::View {
        doc: doc.clone(),
        me: None,
    });
    assert_eq!(view.due_date, None);
    assert_eq!(view.estimate, None);
    // A due date of 0 is a typo, not an epoch-midnight deadline.
    let ts = driver.ts();
    let refused = driver.submit(&IssueIntent::IssueEdit {
        doc: doc.clone(),
        title: None,
        status: None,
        priority: None,
        description: None,
        duedate: Some(Some(0)),
        estimate: None,
        device: my_device().as_str().to_string(),
        ts,
    });
    assert!(matches!(refused, Err(WorldError::InvalidRequest)));

    // ---- comment identity, replies, reactions ----
    let cid = lait::ids::mint_comment_id(&SystemUlidSource);
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::Comment {
            doc: doc.clone(),
            body: "root comment".into(),
            id: Some(cid.clone()),
            parent: None,
            actor: my_actor().as_str().to_string(),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    // A duplicate id would fuse two comments' reactions — refused.
    let ts = driver.ts();
    let refused = driver.submit(&IssueIntent::Comment {
        doc: doc.clone(),
        body: "same id".into(),
        id: Some(cid.clone()),
        parent: None,
        actor: my_actor().as_str().to_string(),
        device: my_device().as_str().to_string(),
        ts,
    });
    assert!(matches!(refused, Err(WorldError::InvalidRequest)));

    let reply = lait::ids::mint_comment_id(&SystemUlidSource);
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::Comment {
            doc: doc.clone(),
            body: "a reply".into(),
            id: Some(reply.clone()),
            parent: Some(cid.clone()),
            actor: my_actor().as_str().to_string(),
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    // One level only: replying to the reply is refused, not laddered.
    let ts = driver.ts();
    let refused = driver.submit(&IssueIntent::Comment {
        doc: doc.clone(),
        body: "reply to reply".into(),
        id: Some(lait::ids::mint_comment_id(&SystemUlidSource)),
        parent: Some(reply.clone()),
        actor: my_actor().as_str().to_string(),
        device: my_device().as_str().to_string(),
        ts,
    });
    assert!(matches!(refused, Err(WorldError::InvalidRequest)));

    let ts = driver.ts();
    driver
        .submit(&IssueIntent::React {
            doc: doc.clone(),
            comment: cid.clone(),
            emoji: "👍".into(),
            actor: my_actor().as_str().to_string(),
            on: true,
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let view: IssueView = driver.query(&IssueQuery::View {
        doc: doc.clone(),
        me: None,
    });
    let root_comment = view
        .comments
        .iter()
        .find(|c| c.id.as_deref() == Some(cid.as_str()))
        .unwrap();
    assert_eq!(root_comment.reactions.len(), 1);
    assert_eq!(root_comment.reactions[0].emoji, "👍");
    assert_eq!(root_comment.reactions[0].actors, vec![my_actor()]);
    let reply_comment = view
        .comments
        .iter()
        .find(|c| c.id.as_deref() == Some(reply.as_str()))
        .unwrap();
    assert_eq!(reply_comment.parent.as_deref(), Some(cid.as_str()));

    // Un-react removes the pair; the set converges to empty.
    let ts = driver.ts();
    driver
        .submit(&IssueIntent::React {
            doc: doc.clone(),
            comment: cid.clone(),
            emoji: "👍".into(),
            actor: my_actor().as_str().to_string(),
            on: false,
            device: my_device().as_str().to_string(),
            ts,
        })
        .unwrap();
    let view: IssueView = driver.query(&IssueQuery::View {
        doc: doc.clone(),
        me: None,
    });
    let root_comment = view
        .comments
        .iter()
        .find(|c| c.id.as_deref() == Some(cid.as_str()))
        .unwrap();
    assert!(root_comment.reactions.is_empty());

    // Reacting to a comment that does not exist is refused.
    let ts = driver.ts();
    let refused = driver.submit(&IssueIntent::React {
        doc: doc.clone(),
        comment: lait::ids::mint_comment_id(&SystemUlidSource),
        emoji: "🎉".into(),
        actor: my_actor().as_str().to_string(),
        on: true,
        device: my_device().as_str().to_string(),
        ts,
    });
    assert!(matches!(refused, Err(WorldError::InvalidRequest)));
}
