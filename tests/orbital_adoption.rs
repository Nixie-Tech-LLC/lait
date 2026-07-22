//! The product composes the orbital lifecycle through its mechanics-only
//! adoption seam (`lait::orbital`): store-root convention + caller-supplied
//! registry + caller-supplied mechanics authority view. The World used here is
//! an **independent example World** (a tiny counter journal) — deliberately not
//! product semantics: per O13/O23 the product ships no first-party World, and
//! the Issues adapter arrives with the daemon integration as an adapter over
//! the existing product behavior.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use lait::orbital::{open_orbital_runtime, orbital_store_root};
use mechanics::ids::{ActorId, DeviceId};
use runtime::{
    ActivationOptions, AuthorityView, PrincipalResolution, Runtime, RuntimeBuilder,
    SpaceFormationOptions, World, WorldContext, WorldEffect, WorldError, WorldIntent, WorldLimits,
    WorldProjection, WorldQuery, WorldRegistration, WorldVersion,
};

use ::replica::body::{BodyOp, BodySchema, MutationModel};
use ::replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use ::replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};

#[allow(dead_code)]
fn any_demand() -> Vec<u8> {
    mechanics::demand::AuthorizationDemand::require(
        mechanics::demand::PolicyCapability::new("w", "c"),
        mechanics::demand::PolicyResource::space("w"),
    )
    .encode_canonical()
    .expect("canonical demand")
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_home() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-orbital-adopt-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const WRITER_SEED: [u8; 32] = [61u8; 32];

/// The example deployment's mechanics view: the writer device gets Write.
struct ExampleAuthority;

impl AuthorityView for ExampleAuthority {
    fn resolve(&self, device: &DeviceId) -> Option<PrincipalResolution> {
        let writer = mechanics::crypto::device_from_seed(&WRITER_SEED);
        (device == &writer).then(|| PrincipalResolution {
            actor: ActorId::from_incept_hash(&"c".repeat(64)),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![3]),
        })
    }
}

/// An independent example World: a single tally Body; an intent increments it
/// by the payload's byte length, a query returns the tally as decimal ASCII.
struct TallyWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}

impl TallyWorld {
    fn new() -> Self {
        Self {
            id: WorldId::parse("dev.example.tally").unwrap(),
            schemas: vec![BodySchema {
                id: SchemaId::parse("tally").unwrap(),
                version: 1,
                encoding: EncodingId::parse("ascii.decimal").unwrap(),
                mutation: MutationModel::Atomic,
                readable_predecessors: vec![],
            }],
        }
    }
    fn body(&self) -> BodyKey {
        BodyKey::new(self.id.clone(), BodyId::from_bytes([9u8; 16]))
    }
    fn current(&self, ctx: &WorldContext<'_>) -> u64 {
        ctx.read_body(&self.body())
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}

impl World for TallyWorld {
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
        let next = self.current(ctx) + intent.payload.len() as u64;
        let key = self.body();
        Ok(WorldEffect {
            demand: any_demand(),
            operations: vec![(
                key.clone(),
                BodyOp::ReplaceAtomic {
                    value: next.to_string().into_bytes(),
                },
            )],
            scopes: vec![key],
            effect: next.to_string().into_bytes(),
            declarations: vec![],
        })
    }
    fn query(
        &self,
        ctx: &WorldContext<'_>,
        _query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        Ok(WorldProjection {
            demand: any_demand(),
            schema: SchemaId::parse("tally").unwrap(),
            schema_version: 1,
            bytes: self.current(ctx).to_string().into_bytes(),
            frontier: ReplicaFrontier::EMPTY, // overwritten by Runtime
        })
    }
}

/// Sign and submit an intent through the frozen public action API.
fn submit_as(
    session: &runtime::Session,
    identity: &runtime::LocalIdentity,
    intent: WorldIntent,
) -> Result<runtime::CommittedEffect, WorldError> {
    session.submit(identity.sign_action(session, runtime::RequestId::mint(), intent)?)
}

#[test]
fn the_product_composes_the_orbital_runtime_for_an_independent_world() {
    let home = temp_home();
    let world = TallyWorld::new();
    let world_id = world.id();
    let reg = WorldRegistration {
        id: world_id.clone(),
        implementation_version: WorldVersion(1),
        schemas: world.schemas().to_vec(),
        limits: WorldLimits::default(),
    };
    let registry = RuntimeBuilder::new()
        .register(reg, Arc::new(world))
        .build()
        .unwrap();

    // The product's composition seam: store-root convention + supplied parts.
    let keys = Arc::new(replica::StaticBodyKeys::new(
        mechanics::crypto::AuthorizedBodyKey::for_authorized_epoch([1u8; 16], [2u8; 32]),
    ));
    let rt = open_orbital_runtime(&home, registry, Arc::new(ExampleAuthority), keys).unwrap();
    assert!(orbital_store_root(&home).ends_with("orbital"));

    let writer = Runtime::identity_from_seed(&WRITER_SEED);
    let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
    let space = orbit.space_id().clone();
    let station = orbit.activate(ActivationOptions::default()).unwrap();
    let session = station.dock(&world_id, &writer).unwrap();

    // Two increments: 5 then 3 bytes.
    submit_as(
        &session,
        &writer,
        WorldIntent {
            schema: SchemaId::parse("tally").unwrap(),
            schema_version: 1,
            payload: b"hello".to_vec(),
        },
    )
    .unwrap();
    let second = submit_as(
        &session,
        &writer,
        WorldIntent {
            schema: SchemaId::parse("tally").unwrap(),
            schema_version: 1,
            payload: b"add".to_vec(),
        },
    )
    .unwrap();
    assert_eq!(second.effect, b"8");
    assert_eq!(second.scopes.len(), 1);

    // The store lives under the product's orbital root.
    assert!(orbital_store_root(&home).join(space.as_str()).is_dir());

    // Restart durability through the product seam.
    let orbit = station.go_dormant().unwrap();
    drop(orbit);
    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let session = station.dock(&world_id, &writer).unwrap();
    let proj = session
        .query(WorldQuery {
            schema: SchemaId::parse("tally").unwrap(),
            schema_version: 1,
            payload: vec![],
        })
        .unwrap();
    assert_eq!(proj.bytes, b"8");
    // Runtime stamped the real committed frontier onto the projection.
    assert_eq!(proj.frontier, second.frontier);
}

#[test]
fn a_legacy_home_is_refused_with_recreation_guidance_and_never_overwritten() {
    let home = temp_home();
    // A pre-orbital store signature.
    std::fs::create_dir_all(home.join("repo")).unwrap();
    std::fs::write(home.join("repo").join("genesis.json"), b"{}").unwrap();
    let registry = RuntimeBuilder::new().build().unwrap();
    let keys = Arc::new(replica::StaticBodyKeys::new(
        mechanics::crypto::AuthorizedBodyKey::for_authorized_epoch([1u8; 16], [2u8; 32]),
    ));
    let err = match open_orbital_runtime(&home, registry, Arc::new(ExampleAuthority), keys) {
        Err(err) => err,
        Ok(_) => panic!("a legacy home must be refused"),
    };
    assert!(err.guidance.contains("clean break"));
    assert!(err.to_string().contains("unsupported store version"));
    // Nothing orbital was created beside the legacy home.
    assert!(
        !orbital_store_root(&home).exists(),
        "no fresh Orbit beside a detected old home"
    );
}
