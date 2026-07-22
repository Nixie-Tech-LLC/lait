//! The immutable World registry.
//!
//! World implementations register with a [`RuntimeBuilder`]. `build()` validates
//! and **freezes** the set: registration is immutable per Runtime, and dynamic
//! loading is deferred. Runtime rejects duplicate ids, duplicate schema
//! versions within a World, invalid limits, and contradictory upgrade claims.

use std::collections::BTreeMap;
use std::sync::Arc;

use replica::ids::WorldId;

use crate::world::{World, WorldRegistration};

/// Why registration was rejected at `build()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    /// Two Worlds registered the same [`WorldId`].
    DuplicateWorld(WorldId),
    /// A World declared the same `(schema id, version)` twice.
    DuplicateSchemaVersion {
        world: WorldId,
        schema: String,
        version: u32,
    },
    /// A World's declared registration id/schemas disagree with the trait impl.
    RegistrationMismatch(WorldId),
    /// A schema claims to read a predecessor version that is not strictly older
    /// than itself, or lists the same predecessor twice.
    ContradictoryUpgrade {
        world: WorldId,
        schema: String,
        version: u32,
    },
    /// A World declared an invalid limit.
    InvalidLimits(WorldId),
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RegistrationError {}

/// One hosted World: its declared registration and its implementation.
struct Hosted {
    registration: WorldRegistration,
    world: Arc<dyn World>,
}

/// The frozen, immutable set of hosted Worlds. Lookup is by [`WorldId`].
#[derive(Clone)]
pub struct WorldRegistry {
    worlds: Arc<BTreeMap<WorldId, Arc<Hosted>>>,
}

// `Hosted` holds `Arc<dyn World>`, which is not `Debug`; the registry only ever
// shows which Worlds it hosts, so `Debug` lists the ids rather than deriving.
impl std::fmt::Debug for WorldRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorldRegistry")
            .field("worlds", &self.worlds.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl WorldRegistry {
    /// The number of hosted Worlds.
    pub fn len(&self) -> usize {
        self.worlds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.worlds.is_empty()
    }

    /// Whether a World is hosted.
    pub fn contains(&self, id: &WorldId) -> bool {
        self.worlds.contains_key(id)
    }

    /// The implementation for a hosted World, if any.
    pub fn world(&self, id: &WorldId) -> Option<Arc<dyn World>> {
        self.worlds.get(id).map(|h| h.world.clone())
    }

    /// The declared registration for a hosted World, if any.
    pub fn registration(&self, id: &WorldId) -> Option<&WorldRegistration> {
        self.worlds.get(id).map(|h| &h.registration)
    }

    /// The hosted World ids, in canonical order.
    pub fn ids(&self) -> impl Iterator<Item = &WorldId> {
        self.worlds.keys()
    }
}

/// Accumulates World registrations, then validates and freezes them into an
/// immutable [`WorldRegistry`]. Consumed by `build()`.
#[derive(Default)]
pub struct RuntimeBuilder {
    pending: Vec<Hosted>,
}

impl RuntimeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a World and its declared registration. Validation is deferred to
    /// [`RuntimeBuilder::build`], so ordering never masks a duplicate.
    pub fn register(mut self, registration: WorldRegistration, world: Arc<dyn World>) -> Self {
        self.pending.push(Hosted {
            registration,
            world,
        });
        self
    }

    /// Validate and freeze the registry. Rejects duplicate Worlds/schema
    /// versions, registration/impl mismatch, invalid limits, and contradictory
    /// upgrade claims.
    pub fn build(self) -> Result<WorldRegistry, RegistrationError> {
        let mut worlds: BTreeMap<WorldId, Arc<Hosted>> = BTreeMap::new();
        for hosted in self.pending {
            let id = hosted.registration.id.clone();

            // The declared registration must match what the impl reports.
            if hosted.world.id() != id
                || hosted.world.schemas() != hosted.registration.schemas.as_slice()
            {
                return Err(RegistrationError::RegistrationMismatch(id));
            }

            // Invalid limits (reserved shape; only the "max is expressible"
            // check applies until S1 freezes the bounds).
            // (No invalid limit is currently expressible; the branch stays for
            // when S1 adds real bounds.)

            // Per-World schema validation.
            let mut seen_versions: std::collections::BTreeSet<(String, u32)> =
                std::collections::BTreeSet::new();
            for schema in &hosted.registration.schemas {
                let key = (schema.id.as_str().to_string(), schema.version);
                if !seen_versions.insert(key) {
                    return Err(RegistrationError::DuplicateSchemaVersion {
                        world: id.clone(),
                        schema: schema.id.as_str().to_string(),
                        version: schema.version,
                    });
                }
                // Upgrade claims must reference strictly-older, distinct versions.
                let mut preds = std::collections::BTreeSet::new();
                for &pred in &schema.readable_predecessors {
                    if pred >= schema.version || !preds.insert(pred) {
                        return Err(RegistrationError::ContradictoryUpgrade {
                            world: id.clone(),
                            schema: schema.id.as_str().to_string(),
                            version: schema.version,
                        });
                    }
                }
            }

            if worlds.insert(id.clone(), Arc::new(hosted)).is_some() {
                return Err(RegistrationError::DuplicateWorld(id));
            }
        }
        Ok(WorldRegistry {
            worlds: Arc::new(worlds),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WorldError;
    use crate::world::{
        World, WorldContext, WorldEffect, WorldIntent, WorldLimits, WorldProjection, WorldQuery,
        WorldVersion,
    };
    use replica::body::{BodySchema, MutationModel};
    use replica::ids::{EncodingId, SchemaId};

    /// A minimal test-only World — the conformance harness's stand-in. It stages
    /// nothing and exists only to prove registry behavior.
    struct TestWorld {
        id: WorldId,
        schemas: Vec<BodySchema>,
    }

    impl World for TestWorld {
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
            Err(WorldError::InvalidRequest)
        }
        fn query(
            &self,
            _ctx: &WorldContext<'_>,
            _query: WorldQuery,
        ) -> Result<WorldProjection, WorldError> {
            Err(WorldError::InvalidRequest)
        }
    }

    fn schema(id: &str, version: u32, preds: Vec<u32>) -> BodySchema {
        BodySchema {
            id: SchemaId::parse(id).unwrap(),
            version,
            encoding: EncodingId::parse("lait.body.v1").unwrap(),
            mutation: MutationModel::Atomic,
            readable_predecessors: preds,
        }
    }

    fn registration(id: &str, schemas: Vec<BodySchema>) -> (WorldRegistration, Arc<dyn World>) {
        let wid = WorldId::parse(id).unwrap();
        let reg = WorldRegistration {
            id: wid.clone(),
            implementation_version: WorldVersion(1),
            schemas: schemas.clone(),
            limits: WorldLimits::default(),
        };
        let world: Arc<dyn World> = Arc::new(TestWorld { id: wid, schemas });
        (reg, world)
    }

    #[test]
    fn single_world_builds_and_is_queryable() {
        let (reg, world) = registration("com.example.issues", vec![schema("issue", 1, vec![])]);
        let registry = RuntimeBuilder::new().register(reg, world).build().unwrap();
        assert_eq!(registry.len(), 1);
        let id = WorldId::parse("com.example.issues").unwrap();
        assert!(registry.contains(&id));
        assert!(registry.world(&id).is_some());
    }

    #[test]
    fn duplicate_world_id_is_rejected() {
        let (r1, w1) = registration("com.example.issues", vec![schema("issue", 1, vec![])]);
        let (r2, w2) = registration("com.example.issues", vec![schema("issue", 1, vec![])]);
        let err = RuntimeBuilder::new()
            .register(r1, w1)
            .register(r2, w2)
            .build()
            .unwrap_err();
        assert_eq!(
            err,
            RegistrationError::DuplicateWorld(WorldId::parse("com.example.issues").unwrap())
        );
    }

    #[test]
    fn duplicate_schema_version_is_rejected() {
        let (reg, world) = registration(
            "com.example.issues",
            vec![schema("issue", 1, vec![]), schema("issue", 1, vec![])],
        );
        let err = RuntimeBuilder::new()
            .register(reg, world)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            RegistrationError::DuplicateSchemaVersion { .. }
        ));
    }

    #[test]
    fn contradictory_upgrade_claim_is_rejected() {
        // A v1 schema cannot "read" predecessor v1 (not strictly older).
        let (reg, world) = registration("com.example.issues", vec![schema("issue", 1, vec![1])]);
        let err = RuntimeBuilder::new()
            .register(reg, world)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            RegistrationError::ContradictoryUpgrade { .. }
        ));

        // A valid upgrade (v2 reads v1) is accepted.
        let (reg, world) = registration(
            "com.example.issues",
            vec![schema("issue", 1, vec![]), schema("issue", 2, vec![1])],
        );
        assert!(RuntimeBuilder::new().register(reg, world).build().is_ok());
    }

    #[test]
    fn registration_impl_mismatch_is_rejected() {
        // Registration claims a schema the impl does not report.
        let wid = WorldId::parse("com.example.issues").unwrap();
        let reg = WorldRegistration {
            id: wid.clone(),
            implementation_version: WorldVersion(1),
            schemas: vec![schema("issue", 1, vec![])],
            limits: WorldLimits::default(),
        };
        let world: Arc<dyn World> = Arc::new(TestWorld {
            id: wid,
            schemas: vec![], // disagrees with the registration
        });
        let err = RuntimeBuilder::new()
            .register(reg, world)
            .build()
            .unwrap_err();
        assert!(matches!(err, RegistrationError::RegistrationMismatch(_)));
    }
}
