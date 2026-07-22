//! **Runtime** — LAIT's orbital lifecycle.
//!
//! ```text
//! Space
//!   +-- Orbit: one device's durable relationship to the Space
//!         +-- Replica: durable local materialization
//!         +-- Station: that Orbit activated for exclusive local operation
//!               +-- hosted World implementation
//!                     +-- docked Session
//! ```
//!
//! Runtime owns the domain lifecycle: forming/entering/observing/acquiring
//! Orbits, activating them into Stations, hosting Worlds, docking Sessions,
//! Contact policy, and Observation publication. It exposes **no** Loro, iroh,
//! stream, file, key, ciphertext, mutex, or product request types — those live
//! below the boundary in [`fabric`], [`comms`], and [`mechanics`].
//!
//! Orbit and Station are the same durable relationship in mutually exclusive
//! states: [`Orbit::activate`] consumes the Orbit and returns a [`Station`];
//! [`Station::go_dormant`] consumes the Station and returns the Orbit.
//!
//! S0 establishes the sealed lifecycle contract surface and a **real, tested**
//! immutable World registry (duplicate registration is rejected). The lifecycle
//! transitions are wired in later stages (Orbit in S2, Station in S3,
//! World/Session/Contact in S5); their signatures here fix ownership and
//! consumption semantics.

pub mod action;
pub mod beacon;
pub mod contact;
pub mod contact_driver;
pub mod coordinates;
#[cfg(test)]
mod dispatch_tests;
pub mod dto;
pub mod error;
pub mod implementation;
pub mod lifecycle;
pub mod neighbor_presence;
pub mod neighbors;
pub mod registry;
pub mod session;
pub mod store;
pub(crate) mod wire;
pub mod world;

pub use action::{ActionError, IdempotencyKey, RequestId, SignedWorldActionV1, WorldActionHeader};
pub use beacon::{BeaconError, RouteHint, SignedBeaconV1, VerifiedBeacon};
pub use contact::{
    AccepterEvent, AccepterValidator, ContactFrame, ContactHelloAckV1, ContactHelloV1, ContactId,
    ContactWireError, InitiatorReceiver, InitiatorState, Progress, ReceivedMaterial,
};
pub use contact_driver::{CommsOptions, ContactMechanics, GossipOptions, MAX_CONTACTS_IN_FLIGHT};
pub use coordinates::{
    AdmissionCapabilityV1, ApproachAddr, CoordinatesAdmission, CoordinatesError,
    CoordinatesPayloadV1, SignedCoordinatesV1, VerifiedCoordinates,
};
pub use error::{ContactError, DormancyError, LifecycleError, StationExit, WorldError};
pub use lifecycle::{
    ActivationOptions, CancelToken, ContactOptions, ContactOutcome, DeorbitConfirmation,
    EnterOptions, Neighbor, Orbit, OrbitObservation, Reachability, Runtime, SpaceFormationOptions,
    Station,
};
pub use neighbor_presence::{AckV1, PresenceError, ProbeV1, PRESENCE_ALPN_V1};
pub use neighbors::{NeighborRecordV1, NeighborRegistry, RegistryError, StoredRoute};
pub use registry::{RuntimeBuilder, WorldRegistry};
pub use session::{
    CommittedEffect, Observation, ObservationCursor, ObservationStream, ObservationStreamError,
    Session, DEFAULT_OBSERVATION_CAPACITY, MAX_OBSERVATION_CAPACITY,
};
pub use world::{
    AuthorityView, BodyDeclaration, BodyReader, LocalIdentity, PrincipalFacts, PrincipalResolution,
    Standing, World, WorldContext, WorldEffect, WorldIntent, WorldLimits, WorldProjection,
    WorldQuery, WorldRegistration, WorldVersion,
};
