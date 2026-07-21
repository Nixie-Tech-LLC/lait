//! The World implementation contract.
//!
//! A World is an independently supplied semantic implementation under Space
//! authority. It defines Body schemas, decodes Intents/Queries, authorizes
//! within supplied Space standing, stages LAIT-owned Body operations, and
//! returns Effects/Projections. It **cannot** redefine membership, custody, key
//! legitimacy, storage, Contact, or Convergence, and receives no Loro, raw
//! keys/ciphertext, files, network handles, or mutable Replica.
//!
//! World callbacks are trusted, cooperative, in-process Rust code — not a
//! sandbox. The API supplies no clock, RNG, environment, thread, file, or
//! network handle; implementations promise deterministic synchronous bounded CPU
//! work. Runtime contains an unwind-safe panic as `WorldImplementationFailed`
//! without ending the Station.

use lait_kernel::acl::Grant;
use lait_kernel::ids::{ActorId, DeviceId, StationId};
use replica::body::BodyOp;
use replica::frontier::AuthorityFrontier;
use replica::ids::{BodyKey, WorldId};
use replica::BodySchema;
use serde::{Deserialize, Serialize};

/// The mechanics-derived standing of a principal within a Space — the grants the
/// authority plane has replayed for the actor. A World reads it to authorize but
/// cannot alter it. Frozen against the S1a principal packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Standing {
    pub grants: Vec<Grant>,
}

impl Standing {
    pub fn new(grants: Vec<Grant>) -> Self {
        Self { grants }
    }
    pub fn has(&self, grant: &Grant) -> bool {
        self.grants.contains(grant)
    }
}

/// The facts Runtime derives for a docked principal. A World cannot assert or
/// replace them; authorization and commit compare-and-swap the same
/// `authority_frontier`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalFacts {
    pub actor: ActorId,
    pub device: DeviceId,
    pub station: StationId,
    pub standing: Standing,
    pub authority_frontier: AuthorityFrontier,
}

/// A World's declared implementation version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorldVersion(pub u32);

/// Bounded resource requirements a World declares. Concrete bounds are frozen in
/// S1; S0 reserves the shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WorldLimits {
    /// Maximum decoded Intent/Query payload size in bytes (`0` = Runtime default).
    pub max_payload_bytes: u32,
}

/// What a World supplies at registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldRegistration {
    pub id: WorldId,
    pub implementation_version: WorldVersion,
    pub schemas: Vec<BodySchema>,
    pub limits: WorldLimits,
}

/// A decoded, authorized-by-Runtime application intent handed to a World. The
/// payload is the World's own bytes; Runtime does not interpret it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldIntent {
    pub schema: replica::ids::SchemaId,
    pub schema_version: u32,
    pub payload: Vec<u8>,
}

/// A decoded application query handed to a World.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldQuery {
    pub schema: replica::ids::SchemaId,
    pub schema_version: u32,
    pub payload: Vec<u8>,
}

/// The result a World returns from `submit`: the staged Body operations, the
/// Observation scopes they touch, and an opaque application effect payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldEffect {
    /// Body operations staged this transaction, each keyed to the Body it
    /// mutates.
    pub operations: Vec<(BodyKey, BodyOp)>,
    /// The Observation scopes affected, so Runtime can publish invalidations.
    pub scopes: Vec<BodyKey>,
    /// An opaque application-defined effect payload returned to the caller.
    pub effect: Vec<u8>,
}

/// A canonical, versioned Projection a World returns from `query`, plus the
/// committed frontier it was derived at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldProjection {
    pub schema: replica::ids::SchemaId,
    pub schema_version: u32,
    pub bytes: Vec<u8>,
    pub frontier: replica::frontier::ReplicaFrontier,
}

/// The bounded capability handed to World callbacks. It exposes authorized reads
/// of the stable committed snapshot and staged LAIT-owned Body operations, and
/// **nothing** below the boundary: no Loro, no mutable storage, no keys, no
/// network. The concrete read/stage surface is implemented in S5; S0 fixes the
/// principal-facts accessor and the borrow shape (`WorldContext<'_>`).
pub struct WorldContext<'a> {
    principal: &'a PrincipalFacts,
}

impl<'a> WorldContext<'a> {
    /// Construct a context over a principal's facts. Runtime owns construction;
    /// World code only reads.
    pub fn new(principal: &'a PrincipalFacts) -> Self {
        Self { principal }
    }

    /// The derived facts for the docked principal. A World authorizes against
    /// these; it cannot replace them.
    pub fn principal(&self) -> &PrincipalFacts {
        self.principal
    }
}

/// An independently supplied World implementation.
///
/// Implementations promise deterministic synchronous bounded CPU work: identical
/// snapshot, facts, and request must produce identical staged operations and
/// Projection bytes. They must not persist, publish Observations, access
/// network/custody/configuration, decide Space legitimacy, or retain the
/// context.
pub trait World: Send + Sync + 'static {
    /// This World's stable namespaced identity.
    fn id(&self) -> WorldId;

    /// The Body schemas this World supports.
    fn schemas(&self) -> &[BodySchema];

    /// Decode, authorize, and stage Body operations for an application intent.
    fn submit(
        &self,
        ctx: &mut WorldContext<'_>,
        intent: WorldIntent,
    ) -> Result<WorldEffect, crate::error::WorldError>;

    /// Decode a query and derive a Projection from the stable snapshot.
    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, crate::error::WorldError>;
}
