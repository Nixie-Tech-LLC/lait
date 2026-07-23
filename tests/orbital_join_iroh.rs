//! `orbital_join_iroh` — the real-transport, Coordinates-only two-endpoint
//! bootstrap (M1). Two independently created production `DefaultTransport`
//! endpoints in isolated iroh networking, with **no** MemNet and **no**
//! cross-`learn` of addresses read out of band: every route the joiner uses
//! to reach the founder comes from the **signed Coordinates**, and the routes
//! the founder uses to reach the joiner arrive over gossip Beacons that the
//! joiner bootstraps from the founder's Coordinates-derived peer id.
//!
//! Flow: form → invite (founder signs its advertised routes into Coordinates)
//! → join (the joiner teaches its transport the founder's signed routes) →
//! admit (Contact redeems the admission) → create issue → converge → restart
//! both → recontact → query.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lait::dto::IssueView;
use lait::orbital::OrbitalMechanics;
use lait::world::contract::{self, IssueIntent, IssueQuery};
use lait::world::IssuesWorld;
use replica::AuthorityIncorporator;
use runtime::{
    ActivationOptions, CommsOptions, ContactMechanics, ContactOptions, EnterOptions, GossipOptions,
    RequestId, Runtime, RuntimeBuilder, Session, Station, WorldIntent, WorldQuery,
};

const FOUNDER_SEED: [u8; 32] = [91u8; 32];
const JOINER_SEED: [u8; 32] = [92u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-joiniroh-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn registry() -> runtime::WorldRegistry {
    RuntimeBuilder::new()
        .register(IssuesWorld::registration(), Arc::new(IssuesWorld::new()))
        .build()
        .unwrap()
}

fn comms_for(
    transport: Arc<dyn comms::Transport>,
    seed: [u8; 32],
    mech: &OrbitalMechanics,
    bootstrap: Vec<comms::PeerId>,
) -> CommsOptions {
    let export_mech = mech.clone();
    let frontier_mech = mech.clone();
    CommsOptions {
        transport,
        station_seed: seed,
        mechanics: ContactMechanics {
            source: Arc::new(mech.clone()),
            incorporator: Arc::new(Mutex::new(mech.clone()))
                as Arc<Mutex<dyn AuthorityIncorporator + Send>>,
            export: Arc::new(move || export_mech.export_records()),
            frontier: Arc::new(move || frontier_mech.current_frontier()),
        },
        // Gossip carries signed Beacons whose route hints teach each transport
        // the other's direct addresses — the founder learns the joiner's routes
        // here (the joiner learned the founder's from Coordinates).
        gossip: Some(GossipOptions {
            bootstrap,
            advertise: vec![],
            beacon_interval: Duration::from_millis(500),
        }),
        whole_deadline: Duration::from_secs(20),
        progress_deadline: Duration::from_secs(5),
        route_lease: Duration::from_secs(120),
    }
}

fn activate(
    root: &std::path::Path,
    seed: [u8; 32],
    mech: &OrbitalMechanics,
    coords: &runtime::SignedCoordinates,
    transport: Arc<dyn comms::Transport>,
    bootstrap: Vec<comms::PeerId>,
) -> (Runtime, Station) {
    let rt = Runtime::open(
        root.to_path_buf(),
        registry(),
        Arc::new(mech.clone()),
        Arc::new(mech.clone()),
    );
    let station = rt
        .enter_orbit(coords, EnterOptions)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_for(transport, seed, mech, bootstrap)),
            observation_capacity: 0,
        })
        .unwrap();
    (rt, station)
}

fn dock(station: &Station, seed: &[u8; 32]) -> Session {
    let identity = Runtime::identity_from_seed(seed);
    station.dock(&contract::world_id(), &identity).unwrap()
}

fn submit(
    session: &Session,
    seed: &[u8; 32],
    intent: &IssueIntent,
) -> Result<(), runtime::WorldError> {
    let identity = Runtime::identity_from_seed(seed);
    let action = identity.sign_action(
        session,
        RequestId::mint(),
        WorldIntent {
            schema: contract::issue_schema(),
            schema_version: contract::ISSUE_SCHEMA_VERSION,
            payload: intent.to_json(),
        },
    )?;
    session.submit(action).map(|_| ())
}

fn query<T: serde::de::DeserializeOwned>(session: &Session, q: &IssueQuery) -> T {
    let bytes = session
        .query(WorldQuery {
            schema: contract::issue_schema(),
            schema_version: contract::ISSUE_SCHEMA_VERSION,
            payload: q.to_json(),
        })
        .unwrap()
        .bytes;
    serde_json::from_slice(&bytes).unwrap()
}

fn station_id(seed: &[u8; 32]) -> mechanics::ids::StationId {
    mechanics::ids::StationId::from_device(&mechanics::crypto::device_from_seed(seed)).unwrap()
}

/// Retry a Contact until it converges (over real iroh, path establishment and
/// gossip route learning are asynchronous). Bounded; panics on exhaustion.
fn contact_until<F: Fn() -> bool>(station: &Station, peer: &mechanics::ids::StationId, done: F) {
    for _ in 0..40 {
        let _ = station.contact(peer, ContactOptions);
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("contact did not converge within the deadline");
}

#[test]
fn coordinates_only_two_endpoint_bootstrap_over_real_iroh() {
    let alpns: &[comms::Alpn] = &[runtime::contact::CONTACT_ALPN, runtime::PRESENCE_ALPN];
    let net = comms::policy::Network::Isolated;
    // A long-lived multi-thread runtime hosts both endpoints' background tasks.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (t_founder, founder_routes) = rt.block_on(async {
        let t = comms::DefaultTransport::new(&FOUNDER_SEED, &net, alpns)
            .await
            .unwrap();
        use comms::Transport;
        let routes = t.advertised_routes(Duration::from_secs(3)).await.unwrap();
        (t, routes)
    });
    let t_joiner = rt.block_on(async {
        comms::DefaultTransport::new(&JOINER_SEED, &net, alpns)
            .await
            .unwrap()
    });
    let t_founder: Arc<dyn comms::Transport> = Arc::new(t_founder);
    let t_joiner: Arc<dyn comms::Transport> = Arc::new(t_joiner);
    let founder_routes = runtime::canonical_routes(&founder_routes);
    assert!(
        !founder_routes.is_empty(),
        "an isolated iroh endpoint advertises at least one direct route"
    );

    // 1. Founder forms and seeds product policy.
    let root_f = temp_root("founder");
    let (mech_f, _coords) =
        OrbitalMechanics::form(root_f.as_path(), &FOUNDER_SEED, "Iroh Space", vec![]).unwrap();
    lait::orbital::seed_founder_policy(&mech_f).unwrap();
    let coords_f = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Iroh Space", vec![], None)
        .unwrap();
    let (_rt_f, station_f) = activate(
        root_f.as_path(),
        FOUNDER_SEED,
        &mech_f,
        &coords_f,
        t_founder.clone(),
        // The founder bootstraps gossip from the joiner once it knows it; here
        // it starts solo and the joiner joins its room.
        vec![],
    );
    let session_f = dock(&station_f, &FOUNDER_SEED);
    // One InitializeTracker seeds the catalog AND the initial project.
    submit(
        &session_f,
        &FOUNDER_SEED,
        &lait::world::contract::initialize_tracker_intent(
            "Iroh Space",
            1,
            lait::ids::ProjectId::mint(&lait::ids::SystemUlidSource).as_str(),
            "Main",
            "MAIN",
            mechanics::crypto::device_from_seed(&FOUNDER_SEED).as_str(),
        ),
    )
    .unwrap();

    // 2. The founder mints an admission-bearing invite carrying ITS OWN signed
    //    advertised routes — the only way the joiner learns how to reach it.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let admission = mech_f
        .mint_admission(&FOUNDER_SEED, 3600, true, now, "contributor", [0u8; 32])
        .unwrap();
    let invite = mech_f
        .mint_coordinates(
            &FOUNDER_SEED,
            "Iroh Space",
            founder_routes.clone(),
            Some(admission),
        )
        .unwrap();

    // 3. The joiner enters with the invite and teaches its transport the
    //    founder's SIGNED routes (verified from the Coordinates) — no manual
    //    cross-learn, no shared registry.
    let root_j = temp_root("joiner");
    let mech_j = OrbitalMechanics::enter(root_j.as_path(), &JOINER_SEED, &invite).unwrap();
    let verified = invite.verify().unwrap();
    t_joiner.learn(verified.approach_station.clone(), &verified.approach_routes);
    let (_rt_j, station_j) = activate(
        root_j.as_path(),
        JOINER_SEED,
        &mech_j,
        &invite,
        t_joiner.clone(),
        // The joiner bootstraps gossip from the founder's peer id (from the
        // Coordinates), so its Beacons reach the founder and the founder learns
        // the joiner's routes.
        vec![verified.approach_station.clone()],
    );

    // 4. The joiner's first Contact reaches the founder over real iroh (routes
    //    from Coordinates) and pulls the founder's material opaquely.
    contact_until(&station_j, &station_id(&FOUNDER_SEED), || true);

    // 5. The founder pulls the joiner (its Beacon taught the founder the
    //    joiner's routes) and redeems the admission (AddMember + sealing).
    contact_until(&station_f, &station_id(&JOINER_SEED), || {
        mech_f.am_i_admin() && {
            use runtime::AuthorityView;
            mech_f
                .resolve(&mechanics::crypto::device_from_seed(&JOINER_SEED))
                .is_some()
        }
    });

    // 6. The joiner's next Contacts import membership + keys, then dock.
    contact_until(&station_j, &station_id(&FOUNDER_SEED), || {
        mech_j.am_i_member()
    });
    assert!(
        mech_j.am_i_member(),
        "the joiner was admitted over real iroh"
    );
    let session_j = dock(&station_j, &JOINER_SEED);

    // 7. The joiner creates an issue and it converges back to the founder.
    let doc = lait::ids::DocId::mint(&lait::ids::SystemUlidSource)
        .as_str()
        .to_string();
    // The founder created the default project via SpaceInit; the joiner reads it.
    let snapshot: serde_json::Value = {
        let bytes = session_j
            .query(WorldQuery {
                schema: contract::issue_schema(),
                schema_version: contract::ISSUE_SCHEMA_VERSION,
                payload: IssueQuery::Snapshot.to_json(),
            })
            .unwrap()
            .bytes;
        serde_json::from_slice(&bytes).unwrap()
    };
    let project_id = snapshot
        .get("catalog")
        .and_then(|c| c.get("projects"))
        .and_then(|p| p.as_object())
        .and_then(|m| m.keys().next().cloned())
        .expect("the joiner sees the founder's project");
    submit(
        &session_j,
        &JOINER_SEED,
        &IssueIntent::IssueNew {
            doc: doc.clone(),
            project: project_id,
            title: "From the joiner".into(),
            priority: "high".into(),
            assignees: vec![],
            labels: vec![],
            new_labels: vec![],
            body: Some("over real iroh".into()),
            duedate: None,
            estimate: None,
            actor: {
                use runtime::AuthorityView;
                mech_j
                    .resolve(&mechanics::crypto::device_from_seed(&JOINER_SEED))
                    .unwrap()
                    .actor
                    .as_str()
                    .to_string()
            },
            device: mechanics::crypto::device_from_seed(&JOINER_SEED)
                .as_str()
                .to_string(),
            ts: 3,
        },
    )
    .unwrap();

    // 8. Converge back to the founder and read the joiner's issue there.
    contact_until(&station_f, &station_id(&JOINER_SEED), || {
        let s = dock(&station_f, &FOUNDER_SEED);
        let view: Option<IssueView> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                query::<IssueView>(
                    &s,
                    &IssueQuery::View {
                        doc: doc.clone(),
                        me: None,
                    },
                )
            }))
            .ok();
        view.is_some_and(|v| v.title == "From the joiner")
    });

    // 9. Restart both endpoints/stores; recontact; the issue is still readable.
    drop(session_f);
    drop(session_j);
    let _ = station_j.go_dormant();
    let _ = station_f.go_dormant();

    let mech_f2 = OrbitalMechanics::open(root_f.as_path(), &mech_f.space(), &FOUNDER_SEED).unwrap();
    let (_rt_f2, station_f2) = activate(
        root_f.as_path(),
        FOUNDER_SEED,
        &mech_f2,
        &coords_f,
        t_founder.clone(),
        vec![],
    );
    let session_f2 = dock(&station_f2, &FOUNDER_SEED);
    let view: IssueView = query(&session_f2, &IssueQuery::View { doc, me: None });
    assert_eq!(view.title, "From the joiner", "the issue survives restart");
    let _ = station_f2.go_dormant();
    rt.block_on(async {
        t_founder.shutdown().await;
        t_joiner.shutdown().await;
    });
}
