//! C5 — real mechanics formation, invitation, entry, admission redemption,
//! and E2EE convergence over the orbital plane. No fixture authorities: every
//! seam is `OrbitalMechanics` over real signed membership material.
//!
//! The flow proven here is the product's guided-join heir:
//! 1. the founder FORMS a Space (genesis, founding inception, epoch-0 sealed
//!    to itself) and commits product issues under real keys;
//! 2. an uninvited entrant converges the founder's material but holds no
//!    epoch key: every Body stays opaque — E2EE is the access control;
//! 3. the founder mints admission-bearing Coordinates; the joiner enters,
//!    self-incepts, and serves its admission redemption over Contact;
//! 4. the founder's Contact pull auto-approves (AddMember + epoch sealing);
//! 5. the joiner's next Contact imports membership + sealed keys FIRST (the
//!    authority-first durable phase), then the SAME pass upgrades previously
//!    opaque Bodies to interpreted product state;
//! 6. the admitted joiner docks, writes, and converges back.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lait::dto::IssueView;
use lait::orbital::OrbitalMechanics;
use lait::world::contract::{self, IssueIntent, IssueQuery};
use lait::world::IssuesWorld;
use replica::AuthorityIncorporator;
use runtime::{
    ActivationOptions, CommsOptions, ContactMechanics, ContactOptions, EnterOptions, RequestId,
    Runtime, RuntimeBuilder, Session, Station, WorldIntent, WorldQuery,
};

const FOUNDER_SEED: [u8; 32] = [81u8; 32];
const JOINER_SEED: [u8; 32] = [82u8; 32];
const STRANGER_SEED: [u8; 32] = [83u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-join-{tag}-{}-{n}", std::process::id()));
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
        gossip: None,
        whole_deadline: Duration::from_secs(20),
        progress_deadline: Duration::from_secs(5),
        route_lease: Duration::from_secs(60),
    }
}

fn activate(
    root: &std::path::Path,
    seed: [u8; 32],
    mech: &OrbitalMechanics,
    coords: &runtime::SignedCoordinatesV1,
    transport: Arc<dyn comms::Transport>,
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
            comms: Some(comms_for(transport, seed, mech)),
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

#[test]
fn form_invite_join_autoapprove_and_e2ee_convergence() {
    let net = comms::mem::MemNet::new();
    let t_founder: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&FOUNDER_SEED)));
    let t_joiner: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&JOINER_SEED)));
    let t_stranger: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STRANGER_SEED)));

    // 1. Formation: real genesis + founding inception + epoch-0.
    let root_f = temp_root("founder");
    let (mech_f, coords) =
        OrbitalMechanics::form(&root_f, &FOUNDER_SEED, "Joined Space", vec![]).unwrap();
    assert!(mech_f.am_i_member(), "the founder holds standing at birth");
    let (_rt_f, station_f) = activate(&root_f, FOUNDER_SEED, &mech_f, &coords, t_founder);
    let session_f = dock(&station_f, &FOUNDER_SEED);
    // Seed product state under real keys.
    submit(
        &session_f,
        &FOUNDER_SEED,
        &IssueIntent::SpaceInit {
            name: "Joined Space".into(),
            ts: 1,
        },
    )
    .unwrap();
    let project = lait::ids::ProjectId::mint(&lait::ids::SystemUlidSource)
        .as_str()
        .to_string();
    submit(
        &session_f,
        &FOUNDER_SEED,
        &IssueIntent::ProjectNew {
            id: project.clone(),
            name: "Core".into(),
            key: "core".into(),
            device: mechanics::crypto::device_from_seed(&FOUNDER_SEED)
                .as_str()
                .to_string(),
            ts: 2,
        },
    )
    .unwrap();
    let doc = lait::ids::DocId::mint(&lait::ids::SystemUlidSource)
        .as_str()
        .to_string();
    let founder_actor = {
        // The founder's actor id, from its own resolution.
        use runtime::AuthorityView;
        mech_f
            .resolve(&mechanics::crypto::device_from_seed(&FOUNDER_SEED))
            .unwrap()
            .actor
    };
    submit(
        &session_f,
        &FOUNDER_SEED,
        &IssueIntent::IssueNew {
            doc: doc.clone(),
            project: project.clone(),
            title: "Secret plan".into(),
            priority: "high".into(),
            assignees: vec![],
            labels: vec![],
            new_labels: vec![],
            body: Some("the sealed body".into()),
            actor: founder_actor.as_str().to_string(),
            device: mechanics::crypto::device_from_seed(&FOUNDER_SEED)
                .as_str()
                .to_string(),
            ts: 3,
        },
    )
    .unwrap();

    // 2. An UNINVITED entrant converges the founder's material but can read
    //    nothing: no admission, no epoch key — every Body stays opaque.
    let root_s = temp_root("stranger");
    let mech_s = OrbitalMechanics::enter(&root_s, &STRANGER_SEED, &coords).unwrap();
    assert!(!mech_s.am_i_member());
    let (_rt_s, station_s) = activate(&root_s, STRANGER_SEED, &mech_s, &coords, t_stranger);
    let outcome = station_s
        .contact(&station_id(&FOUNDER_SEED), ContactOptions)
        .unwrap();
    assert!(
        outcome.convergence.unsupported_retained >= 1,
        "material is retained opaquely, not read"
    );
    assert_eq!(outcome.convergence.accepted, 0, "nothing interpretable");
    // The stranger cannot even dock: no standing resolves.
    let stranger_identity = Runtime::identity_from_seed(&STRANGER_SEED);
    assert!(station_s
        .dock(&contract::world_id(), &stranger_identity)
        .is_err());

    // 3. The founder mints single-use admission-bearing Coordinates.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let admission = mech_f
        .mint_admission(&FOUNDER_SEED, 3600, true, now)
        .unwrap();
    let invite = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Joined Space", vec![], Some(admission))
        .unwrap();

    // 4. The joiner enters with the invite; its FIRST pull (before admission)
    //    retains the founder's Bodies opaquely.
    let root_j = temp_root("joiner");
    let mech_j = OrbitalMechanics::enter(&root_j, &JOINER_SEED, &invite).unwrap();
    assert!(!mech_j.am_i_member());
    let (_rt_j, station_j) = activate(&root_j, JOINER_SEED, &mech_j, &invite, t_joiner);
    let before = station_j
        .contact(&station_id(&FOUNDER_SEED), ContactOptions)
        .unwrap();
    assert!(before.convergence.unsupported_retained >= 1);

    // 5. The founder pulls the joiner: the admission redemption rides the
    //    authority records and auto-approves (AddMember + epoch sealing).
    let outcome = station_f
        .contact(&station_id(&JOINER_SEED), ContactOptions)
        .unwrap();
    let _ = outcome;
    // The founder's replay now admits the joiner's actor.
    {
        use runtime::AuthorityView;
        assert!(
            mech_f
                .resolve(&mechanics::crypto::device_from_seed(&JOINER_SEED))
                .is_some(),
            "the joiner is admitted on the founder's replay"
        );
    }

    // 6. The joiner pulls again: membership + sealed keys arrive FIRST (the
    //    authority-first phase), and the SAME pass upgrades the previously
    //    opaque Bodies into interpreted product state.
    let after = station_j
        .contact(&station_id(&FOUNDER_SEED), ContactOptions)
        .unwrap();
    assert!(
        after.convergence.accepted >= 1,
        "opaque material upgraded to interpreted once the keys arrived"
    );
    assert!(mech_j.am_i_member(), "the joiner holds standing");
    let session_j = dock(&station_j, &JOINER_SEED);
    let view: IssueView = query(
        &session_j,
        &IssueQuery::View {
            doc: doc.clone(),
            me: None,
        },
    );
    assert_eq!(view.title, "Secret plan");
    assert_eq!(view.description, "the sealed body");

    // 7. The admitted joiner writes; the founder converges it back.
    let joiner_actor = {
        use runtime::AuthorityView;
        mech_j
            .resolve(&mechanics::crypto::device_from_seed(&JOINER_SEED))
            .unwrap()
            .actor
    };
    submit(
        &session_j,
        &JOINER_SEED,
        &IssueIntent::Comment {
            doc: doc.clone(),
            body: "joined and commenting".into(),
            actor: joiner_actor.as_str().to_string(),
            device: mechanics::crypto::device_from_seed(&JOINER_SEED)
                .as_str()
                .to_string(),
            ts: 9,
        },
    )
    .unwrap();
    station_f
        .contact(&station_id(&JOINER_SEED), ContactOptions)
        .unwrap();
    let view: IssueView = query(
        &session_f,
        &IssueQuery::View {
            doc: doc.clone(),
            me: None,
        },
    );
    assert_eq!(view.comments.len(), 1);
    assert_eq!(view.comments[0].body, "joined and commenting");

    let _ = station_f.go_dormant();
    let _ = station_j.go_dormant();
    let _ = station_s.go_dormant();
    let _ = std::fs::remove_dir_all(&root_f);
    let _ = std::fs::remove_dir_all(&root_j);
    let _ = std::fs::remove_dir_all(&root_s);
}
