//! S7 / G10 — independent adoption conformance.
//!
//! This exercises the orbital lifecycle end to end through the **public**
//! `runtime` API only — the same surface an Issues-free consumer would use. It
//! registers a small test World and drives Space formation, activation, docking,
//! durable submit, committed-snapshot query, Observation, restart durability,
//! the double-lock, per-request authorization, and destructive deorbit. Nothing
//! here touches crate internals or product types.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use lait_kernel::acl::Grant;
use lait_kernel::ids::{ActorId, DeviceId, StationId};
use replica::body::{BodyOp, BodySchema, MutationModel};
use replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};
use runtime::{
    ActivationOptions, DeorbitConfirmation, LifecycleError, PrincipalFacts, Runtime,
    RuntimeBuilder, SpaceFormationOptions, Standing, World, WorldContext, WorldEffect, WorldError,
    WorldIntent, WorldLimits, WorldProjection, WorldQuery, WorldRegistration, WorldVersion,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-adoption-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A tiny key-value World: an intent `key=value` sets a Body; a query for `key`
/// returns its committed value. Deterministic and product-free.
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

    /// A stable Body id derived from the entry key.
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
        ctx: &mut WorldContext<'_>,
        intent: WorldIntent,
    ) -> Result<WorldEffect, WorldError> {
        if !ctx.principal().standing.has(&Grant::Write) {
            return Err(WorldError::Denied);
        }
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
            effect: value.as_bytes().to_vec(),
        })
    }
    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        let key = String::from_utf8(query.payload).map_err(|_| WorldError::InvalidRequest)?;
        let value = ctx.read_body(&self.body(&key)).unwrap_or_default();
        Ok(WorldProjection {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            bytes: value,
            frontier: ReplicaFrontier::EMPTY,
        })
    }
}

fn kv_runtime(root: &PathBuf) -> Runtime {
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
    Runtime::open(root.clone(), registry)
}

fn principal(grants: Vec<Grant>) -> PrincipalFacts {
    PrincipalFacts {
        actor: ActorId::from_incept_hash(&"a".repeat(64)),
        device: DeviceId::from_key_bytes(&[2u8; 32]),
        station: StationId::from_key_bytes([2u8; 32]),
        standing: Standing::new(grants),
        authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![1]),
    }
}

fn world_id() -> WorldId {
    WorldId::parse("dev.example.kv").unwrap()
}

#[test]
fn a_consumer_drives_the_whole_lifecycle_through_the_public_api() {
    let root = temp_root();
    let rt = kv_runtime(&root);

    // Form a Space and activate its Orbit.
    let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
    let space = orbit.space_id().clone();
    let station = orbit.activate(ActivationOptions::default()).unwrap();

    // Observation is advisory and reports the Space present + locked.
    let obs = rt.observe_orbit(&space).unwrap();
    assert!(obs.locked);
    assert_eq!(rt.observe_orbits().len(), 1);

    // Dock and durably submit two entries.
    let session = station
        .dock(&world_id(), principal(vec![Grant::Write]))
        .unwrap();
    let c1 = session
        .submit(WorldIntent {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            payload: b"greeting=hello".to_vec(),
        })
        .unwrap();
    assert_eq!(c1.observation.sequence, 1);
    assert_ne!(c1.frontier, ReplicaFrontier::EMPTY);
    let c2 = session
        .submit(WorldIntent {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            payload: b"farewell=bye".to_vec(),
        })
        .unwrap();
    assert_eq!(c2.observation.sequence, 2);
    assert_ne!(c1.frontier, c2.frontier);
    assert_eq!(station.frontier(), c2.frontier);

    // Query reads the committed snapshot.
    let read = |s: &runtime::Session, key: &str| {
        s.query(WorldQuery {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            payload: key.as_bytes().to_vec(),
        })
        .unwrap()
        .bytes
    };
    assert_eq!(read(&session, "greeting"), b"hello");
    assert_eq!(read(&session, "farewell"), b"bye");

    // Go dormant (checkpoints), then reactivate: committed entries survive.
    let orbit = station.go_dormant().unwrap();
    drop(orbit);
    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let session = station
        .dock(&world_id(), principal(vec![Grant::Write]))
        .unwrap();
    assert_eq!(read(&session, "greeting"), b"hello");
    assert_eq!(read(&session, "farewell"), b"bye");

    // A double acquisition while the Station is live is refused.
    assert!(matches!(
        rt.orbit(&space),
        Err(LifecycleError::ReplicaLocked(_))
    ));

    // Per-request authorization: a read-only principal cannot write.
    let readonly = station.dock(&world_id(), principal(vec![])).unwrap();
    assert_eq!(
        readonly.submit(WorldIntent {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            payload: b"x=y".to_vec(),
        }),
        Err(WorldError::Denied)
    );

    // Deorbit destroys the Space.
    let orbit = station.go_dormant().unwrap();
    orbit
        .deorbit(DeorbitConfirmation::for_space(space.clone()))
        .unwrap();
    assert!(matches!(
        rt.orbit(&space),
        Err(LifecycleError::OrbitNotFound(_))
    ));
}

#[test]
fn an_unregistered_world_cannot_be_docked() {
    let root = temp_root();
    let rt = kv_runtime(&root);
    let station = rt
        .form_space(SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let unknown = WorldId::parse("dev.example.other").unwrap();
    assert!(station
        .dock(&unknown, principal(vec![Grant::Write]))
        .is_err());
}
