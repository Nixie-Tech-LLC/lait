//! The orbital lifecycle handles: [`Runtime`], [`Orbit`], and [`Station`].
//!
//! Orbit and Station are the same durable relationship in mutually exclusive
//! states. [`Orbit::activate`] consumes the Orbit and returns a [`Station`];
//! [`Station::go_dormant`] consumes the Station and returns the Orbit. Runtime is
//! cloneable and owns configuration + registrations; it owns no active Space
//! state. Orbit and Station are **not** cloneable.
//!
//! S0 wires the ownership/consumption transitions at the handle level (so the
//! shapes are real and the consumption is enforced by the type system) and
//! leaves the subsystem-backed operations — durable formation, custody, real
//! Contact — as typed [`LifecycleError::NotYetWired`] until their owning stage
//! (Orbit S2, Station S3, Contact/World S5).

use lait_kernel::ids::{SpaceId, StationEpoch, StationId};

use crate::error::{ContactError, DormancyError, LifecycleError, StationExit};
use crate::registry::{RuntimeBuilder, WorldRegistry};
use crate::session::Session;
use crate::world::PrincipalFacts;
use replica::ids::WorldId;
use replica::ConvergenceOutcome;

/// Verifiable material sufficient to identify and approach a Space. This is the
/// S0 placeholder shape; S2 replaces it with canonical `SignedCoordinatesV1`.
#[derive(Debug, Clone)]
pub struct Coordinates(pub Vec<u8>);

/// Options for forming a new Space. Reserved shape; fields land in S2.
#[derive(Debug, Clone, Default)]
pub struct SpaceFormationOptions {
    /// A display-name hint committed into the Space's Coordinates.
    pub display_name_hint: Option<String>,
}

/// Options for entering (materializing) an Orbit. Reserved shape; S2.
#[derive(Debug, Clone, Default)]
pub struct EnterOptions;

/// Options for activating an Orbit into a Station. Reserved shape; S3/S4.
#[derive(Debug, Clone, Default)]
pub struct ActivationOptions;

/// Options for an administrative/test Contact. Reserved shape; S5.
#[derive(Debug, Clone, Default)]
pub struct ContactOptions;

/// An explicit, non-defaultable confirmation that a destructive deorbit is
/// intended. Constructing it names the exact Space being removed, so a stray
/// call cannot destroy the wrong Orbit.
#[derive(Debug, Clone)]
pub struct DeorbitConfirmation {
    space: SpaceId,
}

impl DeorbitConfirmation {
    /// Confirm destructive removal of a specific Space's local Orbit.
    pub fn for_space(space: SpaceId) -> Self {
        Self { space }
    }
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
}

/// The cloneable entry point. Owns configuration and the immutable World
/// registry; owns no active Space state. Local Orbit discovery is Runtime's, but
/// acquisition/activation live on the returned [`Orbit`]/[`Station`].
#[derive(Clone)]
pub struct Runtime {
    registry: WorldRegistry,
}

impl Runtime {
    /// Begin building a Runtime by registering Worlds.
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder::new()
    }

    /// Wrap a frozen registry into a Runtime.
    pub fn from_registry(registry: WorldRegistry) -> Self {
        Self { registry }
    }

    /// The immutable World registry this Runtime hosts.
    pub fn registry(&self) -> &WorldRegistry {
        &self.registry
    }

    /// Form a new Space and its founding Orbit. Durable formation is wired in S2.
    pub fn form_space(&self, _options: SpaceFormationOptions) -> Result<Orbit, LifecycleError> {
        Err(LifecycleError::NotYetWired("form_space (S2)"))
    }

    /// Materialize this device's Orbit from Coordinates. Wired in S2.
    pub fn enter_orbit(
        &self,
        _coordinates: Coordinates,
        _options: EnterOptions,
    ) -> Result<Orbit, LifecycleError> {
        Err(LifecycleError::NotYetWired("enter_orbit (S2)"))
    }

    /// Acquire an existing local Orbit for operational ownership (revalidates
    /// integrity, protocol version, custody, and the store lock). Wired in S2.
    pub fn orbit(&self, space: &SpaceId) -> Result<Orbit, LifecycleError> {
        Err(LifecycleError::OrbitNotFound(space.clone()))
    }

    /// Advisory, read-only observation of a local Orbit. Never grants control.
    /// Wired in S2; until then no Orbit is discoverable.
    pub fn observe_orbit(&self, space: &SpaceId) -> Result<OrbitObservation, LifecycleError> {
        Err(LifecycleError::OrbitNotFound(space.clone()))
    }

    /// Advisory observation of every discoverable local Orbit. Empty until S2.
    pub fn observe_orbits(&self) -> Vec<OrbitObservation> {
        Vec::new()
    }
}

/// One device's durable relationship to a Space, acquired for operational
/// ownership. **Not** cloneable: [`Orbit::activate`] consumes it.
pub struct Orbit {
    space: SpaceId,
    registry: WorldRegistry,
    epoch: StationEpoch,
}

// The registry holds `Arc<dyn World>`, which is not `Debug`; a handle only ever
// wants to show its Space + epoch, so `Debug` is hand-rolled rather than derived.
impl std::fmt::Debug for Orbit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Orbit")
            .field("space", &self.space)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Orbit {
    /// Internal constructor — Runtime acquisition (S2) is the only public route
    /// to an Orbit; this seam lets the crate model the transitions now.
    pub(crate) fn new(space: SpaceId, registry: WorldRegistry, epoch: StationEpoch) -> Self {
        Self {
            space,
            registry,
            epoch,
        }
    }

    /// The Space this Orbit relates to.
    pub fn space_id(&self) -> &SpaceId {
        &self.space
    }

    /// Activate this Orbit into a [`Station`], consuming it. Activation is valid
    /// offline and grants no new Space authority. The durable epoch increment
    /// and task graph land in S3/S4; here the handle-level transition and epoch
    /// bump are real (and fail closed on counter overflow).
    pub fn activate(self, _options: ActivationOptions) -> Result<Station, LifecycleError> {
        let epoch = self
            .epoch
            .next()
            .ok_or(LifecycleError::NotYetWired("station epoch overflow"))?;
        Ok(Station {
            space: self.space,
            registry: self.registry,
            epoch,
        })
    }

    /// Destructively remove this local Orbit, consuming it. Wired in S2.
    pub fn deorbit(self, confirmation: DeorbitConfirmation) -> Result<(), LifecycleError> {
        let _ = confirmation;
        Err(LifecycleError::NotYetWired("deorbit (S2)"))
    }
}

/// An advisory, read-only snapshot of a local Orbit. Cannot activate or deorbit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrbitObservation {
    pub space: SpaceId,
    /// Whether the Orbit's store is currently locked by a live Station.
    pub locked: bool,
}

/// An activated Orbit: the exclusive Replica writer, live task graph, hosted
/// Worlds, docks, and shutdown. **Not** cloneable; [`Station::go_dormant`] and
/// [`Station::wait`] consume it.
pub struct Station {
    space: SpaceId,
    registry: WorldRegistry,
    epoch: StationEpoch,
}

impl std::fmt::Debug for Station {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Station")
            .field("space", &self.space)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Station {
    /// This activation's epoch.
    pub fn epoch(&self) -> StationEpoch {
        self.epoch
    }

    /// The Space this Station serves.
    pub fn space_id(&self) -> &SpaceId {
        &self.space
    }

    /// Attach a local caller to a hosted World and return a [`Session`] bound to
    /// this activation epoch. Many Sessions may dock; none can stop the Station.
    /// Authorization is checked per request, not only here.
    pub fn dock(
        &self,
        world_id: &WorldId,
        principal: PrincipalFacts,
    ) -> Result<Session, LifecycleError> {
        let world = self
            .registry
            .world(world_id)
            .ok_or(LifecycleError::NotYetWired("unknown world at dock"))?;
        Ok(Session::new(world_id.clone(), world, principal, self.epoch))
    }

    /// Known/discoverable Neighbors. Reachability is advisory. Populated in S4.
    pub fn neighbors(&self) -> Vec<Neighbor> {
        Vec::new()
    }

    /// An explicitly privileged administrative/test Contact. Not exposed on
    /// ordinary Session handles. Wired in S5.
    pub fn contact(
        &self,
        _neighbor: &StationId,
        _options: ContactOptions,
    ) -> Result<ContactOutcome, ContactError> {
        Err(ContactError::Unreachable)
    }

    /// Go dormant, consuming the Station and returning the Orbit. The full drain
    /// order (reject docks, end Sessions, stop scheduling, cancel Contacts,
    /// checkpoint, close transport, drain tasks, release lock) is wired in S3;
    /// the handle-level consumption and Orbit return are real here.
    pub fn go_dormant(self) -> Result<Orbit, DormancyError> {
        Ok(Orbit::new(self.space, self.registry, self.epoch))
    }

    /// Park until the Station exits, consuming it and returning a recoverable
    /// [`StationExit`]. Task supervision lands in S3; here the unwired Station
    /// exits immediately with the recovered Orbit and no failure reason.
    pub fn wait(self) -> StationExit {
        StationExit {
            orbit: Orbit::new(self.space, self.registry, self.epoch),
            reason: None,
        }
    }
}

/// Another known or discoverable Station. Neighbor state is keyed by verified
/// [`StationId`]; reachability is advisory and never standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    pub station: StationId,
    pub reachability: Reachability,
}

/// Advisory reachability of a Neighbor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    Unknown,
    Reachable,
    Unreachable,
}

/// The outcome of a Contact: bytes moved reported **separately** from the
/// Convergence classification of the material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactOutcome {
    pub bytes_moved: u64,
    pub convergence: ConvergenceOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world::{WorldLimits, WorldRegistration, WorldVersion};

    fn empty_runtime() -> Runtime {
        Runtime::from_registry(RuntimeBuilder::new().build().unwrap())
    }

    #[test]
    fn runtime_is_cloneable_and_owns_no_active_space_state() {
        let rt = empty_runtime();
        let _clone = rt.clone();
        assert!(rt.observe_orbits().is_empty());
    }

    #[test]
    fn activation_consumes_orbit_and_dormancy_returns_it() {
        // Model the mutually-exclusive Orbit<->Station transition. An Orbit is
        // acquired internally (S2 gives the public route); here we prove the
        // ownership contract: activate consumes, go_dormant restores.
        let space = SpaceId::from_digest([3u8; 16]);
        let registry = RuntimeBuilder::new().build().unwrap();
        let orbit = Orbit::new(space.clone(), registry, StationEpoch::ZERO);

        let station = orbit.activate(ActivationOptions).unwrap();
        // `orbit` is moved into `activate`; it cannot be used again — the type
        // system enforces the mutual exclusion.
        assert_eq!(station.epoch(), StationEpoch::from_u64(1));

        let orbit = station.go_dormant().unwrap();
        assert_eq!(orbit.space_id(), &space);
    }

    #[test]
    fn form_space_is_not_yet_wired() {
        let rt = empty_runtime();
        assert!(matches!(
            rt.form_space(SpaceFormationOptions::default()),
            Err(LifecycleError::NotYetWired(_))
        ));
    }

    #[test]
    fn observe_orbit_cannot_operate_on_a_missing_orbit() {
        let rt = empty_runtime();
        let space = SpaceId::from_digest([1u8; 16]);
        assert!(matches!(
            rt.observe_orbit(&space),
            Err(LifecycleError::OrbitNotFound(_))
        ));
    }

    #[test]
    fn wait_returns_a_recoverable_orbit() {
        let space = SpaceId::from_digest([5u8; 16]);
        let registry = RuntimeBuilder::new().build().unwrap();
        let station = Orbit::new(space.clone(), registry, StationEpoch::ZERO)
            .activate(ActivationOptions)
            .unwrap();
        let exit = station.wait();
        assert_eq!(exit.orbit.space_id(), &space);
        assert!(exit.reason.is_none());
    }

    // Silence unused-import warnings for reserved registration types until S1
    // exercises them here.
    #[allow(dead_code)]
    fn _reserved(_: WorldRegistration, _: WorldVersion, _: WorldLimits) {}
}
