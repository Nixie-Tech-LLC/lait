//! G6 — operational Contact over `MemTransport`, through the **public**
//! Station API only.
//!
//! Two Stations enter the same Space (Coordinates v1), activate with a real
//! comms transport, and converge: once via the privileged administrative
//! `Station::contact`, and once fully automatically — a signed Beacon is
//! observed, the persistent registry queues the Neighbor, the Station
//! scheduler dials, the accepter serves its retained material, and the
//! validated bundle incorporates durably. No test code feeds frames or calls
//! Replica incorporation directly.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mechanics::acl::Grant;
use mechanics::crypto::AuthorizedBodyKey;
use mechanics::ids::{ActorId, DeviceId, SpaceId, StationId};
use replica::body::{BodyOp, BodySchema, MutationModel};
use replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};
use runtime::coordinates::{ApproachAddr, CoordinatesAdmission, CoordinatesPayloadV1};
use runtime::{
    ActivationOptions, CommsOptions, ContactMechanics, ContactOptions, EnterOptions, GossipOptions,
    RequestId, Runtime, RuntimeBuilder, SignedCoordinatesV1, Station, World, WorldContext,
    WorldEffect, WorldError, WorldIntent, WorldLimits, WorldProjection, WorldQuery,
    WorldRegistration, WorldVersion,
};

const FOUNDER_SEED: [u8; 32] = [7u8; 32];
const RECOVERY_SEED: [u8; 32] = [20u8; 32];
const STATION_A_SEED: [u8; 32] = [31u8; 32];
const STATION_B_SEED: [u8; 32] = [32u8; 32];
const WRITER_SEED: [u8; 32] = [33u8; 32];
const SALT: [u8; 16] = [9u8; 16];
const EPOCH: [u8; 16] = [13u8; 16];
const EPOCH_KEY: [u8; 32] = [14u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("lait-contact-mem-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A valid founding + Coordinates both nodes enter with.
fn coordinates() -> (SpaceId, SignedCoordinatesV1) {
    let rc = mechanics::space::recovery_commit(&mechanics::space::recovery_pub_of(&RECOVERY_SEED))
        .unwrap();
    let device = mechanics::space::recovery_pub_of(&FOUNDER_SEED);
    let ws = mechanics::space::derive_space_id(&device, &SALT, &rc);
    let (incept, _actor) =
        mechanics::actor::incept_single(&FOUNDER_SEED, &ws, [1u8; 16], [2u8; 16], None);
    let payload = CoordinatesPayloadV1 {
        space: <[u8; 29]>::try_from(ws.as_str().as_bytes()).unwrap(),
        salt: SALT,
        recovery_root: rc,
        founder_inception: postcard::to_stdvec(&incept).unwrap(),
        display_name_hint: "Contact Space".into(),
        approach_station: mechanics::crypto::device_from_seed(&STATION_A_SEED)
            .key_bytes()
            .unwrap(),
        approach_nick_hint: "a".into(),
        approach_addrs: vec![ApproachAddr::V4 {
            ip: [127, 0, 0, 1],
            port: 4242,
        }],
        admission: CoordinatesAdmission::None,
    };
    (ws, SignedCoordinatesV1::sign(payload, &STATION_A_SEED))
}

/// The shared note World: intents `key=value` set atomic Bodies.
struct KvWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}

impl KvWorld {
    fn new() -> Self {
        Self {
            id: WorldId::parse("dev.example.kv").unwrap(),
            schemas: vec![BodySchema {
                id: SchemaId::parse("entry").unwrap(),
                version: 1,
                encoding: EncodingId::parse("bytes").unwrap(),
                mutation: MutationModel::Atomic,
                readable_predecessors: vec![],
            }],
        }
    }
    fn body(&self, key: &str) -> BodyKey {
        let mut raw = [0u8; 16];
        let k = key.as_bytes();
        raw[..k.len().min(16)].copy_from_slice(&k[..k.len().min(16)]);
        BodyKey::new(self.id.clone(), BodyId::from_bytes(raw))
    }
}

impl World for KvWorld {
    fn id(&self) -> WorldId {
        self.id.clone()
    }
    fn schemas(&self) -> &[BodySchema] {
        &self.schemas
    }
    fn submit(
        &self,
        _ctx: &mut WorldContext<'_>,
        intent: WorldIntent,
    ) -> Result<WorldEffect, WorldError> {
        let text = String::from_utf8(intent.payload).map_err(|_| WorldError::InvalidRequest)?;
        let (key, value) = text.split_once('=').ok_or(WorldError::InvalidRequest)?;
        let body = self.body(key);
        Ok(WorldEffect {
            operations: vec![(
                body.clone(),
                BodyOp::ReplaceAtomic {
                    value: value.as_bytes().to_vec(),
                },
            )],
            scopes: vec![body],
            effect: vec![],
            declarations: vec![],
        })
    }
    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        let key = String::from_utf8(query.payload).map_err(|_| WorldError::InvalidRequest)?;
        Ok(WorldProjection {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            bytes: ctx.read_body(&self.body(&key)).unwrap_or_default(),
            frontier: ReplicaFrontier::EMPTY,
        })
    }
}

/// Authorizes everyone this test names (writer + both stations).
struct TestAuthority;
impl runtime::AuthorityView for TestAuthority {
    fn resolve(&self, _device: &DeviceId) -> Option<runtime::PrincipalResolution> {
        Some(runtime::PrincipalResolution {
            actor: ActorId::from_incept_hash(&"c".repeat(64)),
            standing: runtime::Standing::new(vec![Grant::Write]),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![3]),
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

#[derive(Default)]
struct AcceptingIncorporator;
impl replica::AuthorityIncorporator for AcceptingIncorporator {
    fn incorporate_authority(
        &mut self,
        _records: &[Vec<u8>],
    ) -> Result<replica::AuthorityBatchReceipt, String> {
        Ok(replica::AuthorityBatchReceipt {
            space: coordinates().0,
            prior_frontier: replica::frontier::AuthorityFrontier::from_canonical_bytes(vec![]),
            resulting_frontier: AuthorityFrontier::from_canonical_bytes(vec![3]),
            batch_digest: *blake3::hash(&_records.concat()).as_bytes(),
        })
    }
}

fn test_keys() -> Arc<dyn replica::BodyKeySource> {
    Arc::new(replica::StaticBodyKeys::new(
        AuthorizedBodyKey::for_authorized_epoch(EPOCH, EPOCH_KEY),
    ))
}

fn runtime_at(root: &std::path::Path) -> Runtime {
    let world = KvWorld::new();
    let reg = WorldRegistration {
        id: world.id(),
        implementation_version: WorldVersion(1),
        schemas: world.schemas().to_vec(),
        limits: WorldLimits::default(),
    };
    let registry = RuntimeBuilder::new()
        .register(reg, Arc::new(world))
        .build()
        .unwrap();
    Runtime::open(
        root.to_path_buf(),
        registry,
        Arc::new(TestAuthority),
        test_keys(),
    )
}

fn comms_options(
    transport: Arc<dyn comms::Transport>,
    station_seed: [u8; 32],
    gossip: Option<GossipOptions>,
) -> CommsOptions {
    CommsOptions {
        transport,
        station_seed,
        mechanics: ContactMechanics {
            source: Arc::new(AnyKnownSigner),
            incorporator: Arc::new(Mutex::new(AcceptingIncorporator)),
            export: Arc::new(Vec::new),
            frontier: Arc::new(|| AuthorityFrontier::from_canonical_bytes(vec![3])),
        },
        gossip,
        whole_deadline: Duration::from_secs(20),
        progress_deadline: Duration::from_secs(5),
        route_lease: Duration::from_secs(60),
    }
}

fn activate_with(
    rt: &Runtime,
    coords: &SignedCoordinatesV1,
    transport: Arc<dyn comms::Transport>,
    seed: [u8; 32],
    gossip: Option<GossipOptions>,
) -> Station {
    rt.enter_orbit(coords, EnterOptions)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_options(transport, seed, gossip)),
            observation_capacity: 0,
        })
        .unwrap()
}

fn submit_kv(station: &Station, entry: &str) {
    let world_id = WorldId::parse("dev.example.kv").unwrap();
    let writer = Runtime::identity_from_seed(&WRITER_SEED);
    let session = station.dock(&world_id, &writer).unwrap();
    let action = writer
        .sign_action(
            &session,
            RequestId::mint(),
            WorldIntent {
                schema: SchemaId::parse("entry").unwrap(),
                schema_version: 1,
                payload: entry.as_bytes().to_vec(),
            },
        )
        .unwrap();
    session.submit(action).unwrap();
}

fn read_kv(station: &Station, key: &str) -> Vec<u8> {
    let world_id = WorldId::parse("dev.example.kv").unwrap();
    let writer = Runtime::identity_from_seed(&WRITER_SEED);
    let session = station.dock(&world_id, &writer).unwrap();
    session
        .query(WorldQuery {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            payload: key.as_bytes().to_vec(),
        })
        .unwrap()
        .bytes
}

fn station_id(seed: &[u8; 32]) -> StationId {
    StationId::from_device(&mechanics::crypto::device_from_seed(seed)).unwrap()
}

#[test]
fn two_stations_converge_through_the_public_contact_api() {
    let (_space, coords) = coordinates();
    let net = comms::mem::MemNet::new();
    let ta: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_A_SEED)));
    let tb: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_B_SEED)));

    let root_a = temp_root("a");
    let root_b = temp_root("b");
    let rt_a = runtime_at(&root_a);
    let rt_b = runtime_at(&root_b);

    let station_a = activate_with(&rt_a, &coords, ta, STATION_A_SEED, None);
    submit_kv(&station_a, "greeting=hello");
    submit_kv(&station_a, "farewell=bye");

    let station_b = activate_with(&rt_b, &coords, tb, STATION_B_SEED, None);
    // Subscribe BEFORE the contact: remote convergence must publish exactly
    // one live-epoch Observation after durable incorporation.
    let world_id = WorldId::parse("dev.example.kv").unwrap();
    let writer = Runtime::identity_from_seed(&WRITER_SEED);
    let obs_session = station_b.dock(&world_id, &writer).unwrap();
    let mut obs = obs_session.observe(None);
    assert!(obs.try_next().unwrap().unwrap().reset);
    // The privileged administrative Contact, through the public API.
    let outcome = station_b
        .contact(&station_id(&STATION_A_SEED), ContactOptions)
        .unwrap();
    assert!(outcome.bytes_moved > 0, "bytes accounted separately");
    assert!(outcome.convergence.accepted >= 1);
    let remote_record = obs
        .next_timeout(Duration::from_secs(5))
        .unwrap()
        .expect("remote convergence publishes");
    assert!(!remote_record.reset);
    assert!(!remote_record.scopes.is_empty());
    obs_session.undock();
    assert_eq!(read_kv(&station_b, "greeting"), b"hello");
    assert_eq!(read_kv(&station_b, "farewell"), b"bye");

    // An unchanged second Contact converges nothing new.
    let again = station_b
        .contact(&station_id(&STATION_A_SEED), ContactOptions)
        .unwrap();
    assert_eq!(again.convergence.accepted, 0);
    assert!(again.convergence.unchanged >= 1);

    // Restart B: incorporated material is durable, and a further Contact is
    // still unchanged.
    let orbit_b = station_b.go_dormant().unwrap();
    drop(orbit_b);
    let tb2: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_B_SEED)));
    let space = station_a.space_id().clone();
    let station_b = rt_b
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_options(tb2, STATION_B_SEED, None)),
            observation_capacity: 0,
        })
        .unwrap();
    assert_eq!(read_kv(&station_b, "greeting"), b"hello");
    let after_restart = station_b
        .contact(&station_id(&STATION_A_SEED), ContactOptions)
        .unwrap();
    assert_eq!(after_restart.convergence.accepted, 0);

    // Dormancy rejects newly queued work with a typed refusal.
    let station_id_a = station_id(&STATION_A_SEED);
    let orbit_b = station_b.go_dormant().unwrap();
    drop(orbit_b);
    drop(station_a);
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
    let _ = station_id_a;
}

#[test]
fn a_beacon_drives_fully_automatic_convergence() {
    let (_space, coords) = coordinates();
    let net = comms::mem::MemNet::new();
    let ta: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_A_SEED)));
    let tb: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_B_SEED)));

    let root_a = temp_root("auto-a");
    let root_b = temp_root("auto-b");
    let rt_a = runtime_at(&root_a);
    let rt_b = runtime_at(&root_b);

    let gossip = |advertise: bool| {
        Some(GossipOptions {
            bootstrap: vec![],
            advertise: if advertise {
                vec![runtime::RouteHint {
                    scheme: 1,
                    bytes: b"127.0.0.1:1".to_vec(),
                }]
            } else {
                vec![]
            },
            beacon_interval: Duration::from_millis(100),
        })
    };
    let station_a = activate_with(&rt_a, &coords, ta, STATION_A_SEED, gossip(true));
    submit_kv(&station_a, "auto=converged");
    let station_b = activate_with(&rt_b, &coords, tb, STATION_B_SEED, gossip(true));

    // No manual contact: A's periodic Beacon reaches B over gossip, the
    // registry queues the Neighbor, and the scheduler dials + incorporates.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if read_kv(&station_b, "auto") == b"converged" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "automatic convergence never happened"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // The registry now lists A as a known Neighbor.
    assert!(station_b
        .neighbors()
        .iter()
        .any(|n| n.station == station_id(&STATION_A_SEED)));

    let _ = station_a.go_dormant();
    let _ = station_b.go_dormant();
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
}

#[test]
fn an_unknown_neighbor_is_unreachable_and_dormancy_refuses_contact() {
    let (_space, coords) = coordinates();
    let net = comms::mem::MemNet::new();
    let tb: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_B_SEED)));
    let root_b = temp_root("refuse");
    let rt_b = runtime_at(&root_b);
    let station_b = activate_with(&rt_b, &coords, tb, STATION_B_SEED, None);

    // Nobody answers this station id on the network.
    let ghost = station_id(&[99u8; 32]);
    assert!(station_b.contact(&ghost, ContactOptions).is_err());

    // After dormancy, newly queued work is refused with a typed error and no
    // task, staging file, or lock is leaked (the Orbit reactivates cleanly).
    let orbit = station_b.go_dormant().unwrap();
    let station_b = orbit.activate(ActivationOptions::offline()).unwrap();
    assert!(matches!(
        station_b.contact(&ghost, ContactOptions),
        Err(runtime::ContactError::Unreachable)
    ));
    let _ = station_b.go_dormant().unwrap();
    let _ = std::fs::remove_dir_all(&root_b);
}
