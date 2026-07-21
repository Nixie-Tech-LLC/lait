//! C0.1 — the public lifecycle API freeze.
//!
//! Every target lifecycle method from `docs/plans/01-orbital-architecture.md`
//! is pinned here **by signature**: each binding below only compiles if the
//! method exists on the public surface with exactly the stated parameter and
//! result/error types. A signature drift is a compile error, not a silent
//! contract change.
//!
//! Two surfaces are documented incomplete until their completion packages land
//! (C2: `Station::neighbors`/`Station::contact` operational behavior; C3:
//! `Session::observe` streaming); their *signatures* are still frozen here so
//! the completion work implements the pinned shape rather than inventing one.

use runtime::{
    ActivationOptions, CommittedEffect, ContactError, ContactOptions, ContactOutcome,
    DeorbitConfirmation, DormancyError, EnterOptions, LifecycleError, LocalIdentity, Neighbor,
    ObservationCursor, Orbit, OrbitObservation, RequestId, Runtime, Session, SignedWorldActionV1,
    SpaceFormationOptions, Station, StationExit, WorldError, WorldIntent, WorldProjection,
    WorldQuery,
};

use mechanics::ids::{SpaceId, StationId};
use replica::ids::WorldId;

/// The frozen lifecycle surface. Each `let _: fn(..) -> ..` binding is a
/// compile-time assertion of the method's exact public signature.
#[test]
fn the_target_lifecycle_methods_have_their_frozen_signatures() {
    // Runtime
    let _: fn(&Runtime, SpaceFormationOptions) -> Result<Orbit, LifecycleError> =
        Runtime::form_space;
    let _: fn(
        &Runtime,
        &runtime::SignedCoordinatesV1,
        EnterOptions,
    ) -> Result<Orbit, LifecycleError> = Runtime::enter_orbit;
    let _: fn(&Runtime, &SpaceId) -> Result<Orbit, LifecycleError> = Runtime::orbit;
    let _: fn(&Runtime, &SpaceId) -> Result<OrbitObservation, LifecycleError> =
        Runtime::observe_orbit;
    let _: fn(&Runtime) -> Vec<OrbitObservation> = Runtime::observe_orbits;
    let _: fn(&[u8; 32]) -> LocalIdentity = Runtime::identity_from_seed;

    // Orbit
    let _: fn(Orbit, ActivationOptions) -> Result<Station, LifecycleError> = Orbit::activate;
    let _: fn(Orbit, DeorbitConfirmation) -> Result<(), LifecycleError> = Orbit::deorbit;

    // Station
    let _: fn(&Station, &WorldId, &LocalIdentity) -> Result<Session, LifecycleError> =
        Station::dock;
    let _: fn(&Station) -> Vec<Neighbor> = Station::neighbors;
    let _: fn(&Station, &StationId, ContactOptions) -> Result<ContactOutcome, ContactError> =
        Station::contact;
    let _: fn(Station) -> Result<Orbit, DormancyError> = Station::go_dormant;
    let _: fn(Station) -> StationExit = Station::wait;

    // Action signing + Session
    let _: fn() -> RequestId = RequestId::mint;
    let _: fn(
        &LocalIdentity,
        &Session,
        RequestId,
        WorldIntent,
    ) -> Result<SignedWorldActionV1, WorldError> = LocalIdentity::sign_action;
    let _: fn(&Session, SignedWorldActionV1) -> Result<CommittedEffect, WorldError> =
        Session::submit;
    let _: fn(&Session, WorldQuery) -> Result<WorldProjection, WorldError> = Session::query;
    let _: fn(&Session, ObservationCursor) -> ObservationCursor = Session::observe;
    let _: fn(Session) = Session::undock;
}

/// The stable error taxonomies backing those results are public, cloneable,
/// comparable types (so callers can match on them and tests can assert them).
#[test]
fn the_error_taxonomies_are_stable_typed_categories() {
    fn assert_error<E: std::error::Error + Clone + PartialEq + Send + Sync + 'static>() {}
    assert_error::<LifecycleError>();
    assert_error::<DormancyError>();
    assert_error::<ContactError>();
    assert_error::<WorldError>();

    // The unknown-World dock failure is a stable typed category (C0.1), not a
    // stage-progress placeholder.
    let world = WorldId::parse("dev.example.none").unwrap();
    let err = LifecycleError::UnknownWorld(world.clone());
    assert_eq!(err, LifecycleError::UnknownWorld(world));
}
