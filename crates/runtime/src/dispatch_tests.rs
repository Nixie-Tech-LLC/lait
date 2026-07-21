//! S1 dispatch proof: a test-only World submits and queries through the generic
//! Session dispatch — no product types anywhere. This exercises the
//! envelope → dock → World → Effect/Projection seam the product adopts in S5.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use lait_kernel::acl::Grant;
use lait_kernel::ids::{ActorId, DeviceId, StationId};

use crate::error::WorldError;
use crate::lifecycle::{ActivationOptions, Runtime, SpaceFormationOptions};
use crate::registry::RuntimeBuilder;
use crate::session::ObservationCursor;
use crate::world::{
    PrincipalFacts, Standing, World, WorldContext, WorldEffect, WorldIntent, WorldLimits,
    WorldProjection, WorldQuery, WorldRegistration, WorldVersion,
};
use replica::body::{BodyOp, BodySchema, MutationModel};
use replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};

/// A minimal note World: intents carry UTF-8 text; `submit` stages an atomic
/// replacement and reports the touched scope; `query` echoes a deterministic
/// projection derived only from its inputs.
struct NoteWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}

impl NoteWorld {
    fn new() -> Self {
        Self {
            id: WorldId::parse("com.example.notes").unwrap(),
            schemas: vec![BodySchema {
                id: SchemaId::parse("note").unwrap(),
                version: 1,
                encoding: EncodingId::parse("text.utf8").unwrap(),
                mutation: MutationModel::Atomic,
                readable_predecessors: vec![],
            }],
        }
    }
}

impl World for NoteWorld {
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
        // Authorization is per request: the note World needs Write standing.
        if !ctx.principal().standing.has(&Grant::Write) {
            return Err(WorldError::Denied);
        }
        if intent.schema.as_str() != "note" {
            return Err(WorldError::UnsupportedSchema);
        }
        // Deterministic body key: same World, a fixed body for this test.
        let key = BodyKey::new(self.id.clone(), BodyId::from_bytes([0u8; 16]));
        Ok(WorldEffect {
            operations: vec![(
                key.clone(),
                BodyOp::ReplaceAtomic {
                    value: intent.payload.clone(),
                },
            )],
            scopes: vec![key],
            effect: intent.payload,
        })
    }
    fn query(
        &self,
        _ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        if query.schema.as_str() != "note" {
            return Err(WorldError::UnsupportedSchema);
        }
        // Deterministic projection: uppercase the query payload as UTF-8.
        let text = String::from_utf8(query.payload).map_err(|_| WorldError::InvalidRequest)?;
        Ok(WorldProjection {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            bytes: text.to_uppercase().into_bytes(),
            frontier: ReplicaFrontier::EMPTY,
        })
    }
}

fn principal(grants: Vec<Grant>) -> PrincipalFacts {
    PrincipalFacts {
        actor: ActorId::from_incept_hash(&"a".repeat(64)),
        device: DeviceId::from_key_bytes(&[1u8; 32]),
        station: StationId::from_key_bytes([1u8; 32]),
        standing: Standing::new(grants),
        authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![1]),
    }
}

fn note_registration() -> (WorldRegistration, Arc<dyn World>) {
    let world = NoteWorld::new();
    let reg = WorldRegistration {
        id: world.id(),
        implementation_version: WorldVersion(1),
        schemas: world.schemas().to_vec(),
        limits: WorldLimits::default(),
    };
    (reg, Arc::new(world))
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-dispatch-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn station_with(reg: WorldRegistration, world: Arc<dyn World>) -> crate::lifecycle::Station {
    let registry = RuntimeBuilder::new().register(reg, world).build().unwrap();
    let rt = Runtime::open(temp_root(), registry);
    rt.form_space(SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap()
}

fn station() -> crate::lifecycle::Station {
    let (reg, world) = note_registration();
    station_with(reg, world)
}

#[test]
fn test_world_submits_and_queries_through_dispatch() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();

    // Submit an intent and observe the staged operation + scope.
    let effect = session
        .submit(WorldIntent {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"hello".to_vec(),
        })
        .unwrap();
    assert_eq!(effect.operations.len(), 1);
    assert_eq!(effect.scopes.len(), 1);
    assert_eq!(effect.effect, b"hello");
    assert!(matches!(
        &effect.operations[0].1,
        BodyOp::ReplaceAtomic { value } if value == b"hello"
    ));

    // Query is deterministic for identical inputs.
    let proj = session
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"hello".to_vec(),
        })
        .unwrap();
    assert_eq!(proj.bytes, b"HELLO");
}

#[test]
fn authorization_is_checked_per_request() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    // A principal with no Write standing is denied at submit, not at dock.
    let session = station.dock(&world_id, principal(vec![])).unwrap();
    let denied = session.submit(WorldIntent {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        payload: b"x".to_vec(),
    });
    assert_eq!(denied, Err(WorldError::Denied));
}

#[test]
fn many_sessions_dock_independently_without_owning_the_station() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let s1 = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();
    let s2 = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();
    assert_eq!(s1.epoch(), s2.epoch());
    // Undocking one Session leaves the Station and the other Session intact.
    s1.undock();
    assert!(s2
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"ok".to_vec(),
        })
        .is_ok());
    // The Station survives its Sessions and can still go dormant.
    assert!(station.go_dormant().is_ok());
}

#[test]
fn dormancy_terminates_sessions() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();
    // Going dormant terminates the Session: further requests fail closed.
    let _orbit = station.go_dormant().unwrap();
    assert_eq!(
        session.query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"x".to_vec(),
        }),
        Err(WorldError::StationDormant)
    );
}

#[test]
fn a_session_cannot_stop_the_station() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    // Dock a Session and drop it (undock) — the Station is unaffected and can
    // still serve new Sessions.
    let s = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();
    s.undock();
    let s2 = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();
    assert!(s2
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"ok".to_vec(),
        })
        .is_ok());
    // A tracked task panicking does not stop the Station's ability to go dormant.
    station.spawn_tracked(|_c| panic!("boom")).unwrap();
    let exit = station.wait();
    assert!(matches!(
        exit.reason,
        Some(crate::error::StationExitReason::TaskFailed(_))
    ));
}

/// A World whose `submit` panics — to prove Runtime contains it.
struct PanicWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}
impl World for PanicWorld {
    fn id(&self) -> WorldId {
        self.id.clone()
    }
    fn schemas(&self) -> &[BodySchema] {
        &self.schemas
    }
    fn submit(
        &self,
        _ctx: &mut WorldContext<'_>,
        _intent: WorldIntent,
    ) -> Result<WorldEffect, WorldError> {
        panic!("world callback panics")
    }
    fn query(
        &self,
        _ctx: &WorldContext<'_>,
        _query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        Err(WorldError::InvalidRequest)
    }
}

#[test]
fn a_world_panic_is_contained_and_does_not_end_the_station() {
    let id = WorldId::parse("com.example.panic").unwrap();
    let schemas = vec![BodySchema {
        id: SchemaId::parse("note").unwrap(),
        version: 1,
        encoding: EncodingId::parse("text.utf8").unwrap(),
        mutation: MutationModel::Atomic,
        readable_predecessors: vec![],
    }];
    let reg = WorldRegistration {
        id: id.clone(),
        implementation_version: WorldVersion(1),
        schemas: schemas.clone(),
        limits: WorldLimits::default(),
    };
    let world: Arc<dyn World> = Arc::new(PanicWorld {
        id: id.clone(),
        schemas,
    });
    let station = station_with(reg, world);
    let session = station.dock(&id, principal(vec![Grant::Write])).unwrap();
    let r = session.submit(WorldIntent {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        payload: b"x".to_vec(),
    });
    assert_eq!(r, Err(WorldError::WorldImplementationFailed));
    // The Station survives the panic and can still go dormant cleanly.
    assert!(station.go_dormant().is_ok());
}

#[test]
fn payload_over_the_declared_limit_is_rejected_before_the_callback() {
    let (mut reg, world) = note_registration();
    reg.limits = WorldLimits {
        max_payload_bytes: 4,
    };
    let station = station_with(reg, world);
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();
    let r = session.submit(WorldIntent {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        payload: b"toolong".to_vec(),
    });
    assert_eq!(r, Err(WorldError::LimitExceeded));
}

#[test]
fn unregistered_schema_and_version_are_rejected() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();
    // Unknown schema.
    assert_eq!(
        session.submit(WorldIntent {
            schema: SchemaId::parse("other").unwrap(),
            schema_version: 1,
            payload: b"x".to_vec(),
        }),
        Err(WorldError::UnsupportedSchema)
    );
    // Known schema, unknown version.
    assert_eq!(
        session.submit(WorldIntent {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 9,
            payload: b"x".to_vec(),
        }),
        Err(WorldError::UnsupportedSchemaVersion)
    );
}

#[test]
fn observation_cursor_starts_at_a_reset_boundary() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station
        .dock(&world_id, principal(vec![Grant::Write]))
        .unwrap();
    let cursor = ObservationCursor::start(session.epoch());
    assert_eq!(cursor.sequence, 0);
    assert_eq!(session.observe(cursor), cursor);
}
