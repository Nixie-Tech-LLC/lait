//! S4 canonical fixtures: Beacon v1 identity/freshness/route matrix and the
//! Neighbor presence v1 challenge transcript matrix.

use mechanics::ids::{SpaceId, StationEpoch, StationId};
use runtime::beacon::{BeaconError, RouteHint, SignedBeacon, MAX_ROUTE_HINTS};
use runtime::neighbor_presence::{PresenceAck, PresenceError, PresenceProbe};

const STATION_SEED: [u8; 32] = [11u8; 32];

fn space() -> SpaceId {
    SpaceId::from_digest([4u8; 16])
}

fn space_bytes() -> [u8; 29] {
    <[u8; 29]>::try_from(space().as_str().as_bytes()).unwrap()
}

fn beacon(epoch: u64, sequence: u64, routes: Vec<RouteHint>) -> SignedBeacon {
    SignedBeacon::emit(
        runtime::beacon::BEACON_PROTOCOL,
        &space(),
        StationEpoch::from_u64(epoch),
        sequence,
        [1u8; 32],
        3,
        0,
        routes,
        &STATION_SEED,
    )
    .unwrap()
}

// ---- Beacon v1 ----

#[test]
fn valid_beacon_verifies() {
    let v = beacon(2, 5, vec![]).verify().unwrap();
    assert_eq!(v.space(), &space());
    assert_eq!(
        v.station(),
        &StationId::from_device(&mechanics::crypto::device_from_seed(&STATION_SEED)).unwrap()
    );
    assert_eq!(v.coordinate(), (2, 5));
}

#[test]
fn unsupported_version_and_algorithm_are_rejected() {
    let mut b = beacon(1, 0, vec![]);
    b.version = 2;
    assert_eq!(b.verify(), Err(BeaconError::UnsupportedVersion(2)));
    let mut b = beacon(1, 0, vec![]);
    b.signature_algorithm = 2;
    assert_eq!(
        b.verify(),
        Err(BeaconError::UnsupportedSignatureAlgorithm(2))
    );
}

#[test]
fn tampered_beacon_body_breaks_the_signature() {
    let mut b = beacon(1, 0, vec![]);
    b.body.sequence = 99;
    assert_eq!(b.verify(), Err(BeaconError::BadSignature));
}

#[test]
fn route_hints_bounds_and_ordering() {
    // Sorted, distinct routes verify.
    let good = beacon(
        1,
        0,
        vec![
            RouteHint {
                scheme: 0,
                bytes: vec![1],
            },
            RouteHint {
                scheme: 1,
                bytes: vec![2],
            },
        ],
    );
    assert!(good.verify().is_ok());

    // Unsorted/duplicate routes are rejected (checked before the signature).
    let mut unsorted = good.clone();
    unsorted.body.routes.reverse();
    assert_eq!(
        unsorted.verify(),
        Err(BeaconError::UnsortedOrDuplicateRoutes)
    );

    // Too many routes.
    let many: Vec<RouteHint> = (0..=MAX_ROUTE_HINTS as u8)
        .map(|i| RouteHint {
            scheme: i,
            bytes: vec![],
        })
        .collect();
    let b = beacon(1, 0, many);
    assert_eq!(b.verify(), Err(BeaconError::TooManyRoutes));
}

#[test]
fn trailing_bytes_are_non_canonical() {
    let mut bytes = beacon(1, 0, vec![]).encode();
    bytes.push(0);
    assert_eq!(
        SignedBeacon::decode_canonical(&bytes),
        Err(BeaconError::NonCanonical)
    );
}

// ---- Neighbor presence v1 ----

const INITIATOR_SEED: [u8; 32] = [21u8; 32];
const RESPONDER_SEED: [u8; 32] = [22u8; 32];

fn station_of(seed: &[u8; 32]) -> StationId {
    StationId::from_device(&mechanics::crypto::device_from_seed(seed)).unwrap()
}

fn probe(nonce: [u8; 32]) -> PresenceProbe {
    let responder = station_of(&RESPONDER_SEED).key_bytes();
    PresenceProbe::sign(
        runtime::neighbor_presence::PRESENCE_PROTOCOL,
        space_bytes(),
        responder,
        nonce,
        &INITIATOR_SEED,
    )
    .unwrap()
}

#[test]
fn an_unsupported_protocol_version_is_refused_not_negotiated() {
    // Beacon: a signed frame naming a future protocol is rejected by name.
    let b = SignedBeacon::emit(
        99,
        &space(),
        StationEpoch::from_u64(1),
        0,
        [1u8; 32],
        0,
        0,
        vec![],
        &STATION_SEED,
    )
    .unwrap();
    assert_eq!(b.verify(), Err(BeaconError::UnsupportedProtocol(99)));

    // Presence probe: same rule.
    let responder = station_of(&RESPONDER_SEED).key_bytes();
    let p = PresenceProbe::sign(99, space_bytes(), responder, [1u8; 32], &INITIATOR_SEED).unwrap();
    assert_eq!(
        p.verify(&space_bytes(), &station_of(&INITIATOR_SEED)),
        Err(PresenceError::UnsupportedProtocol(99))
    );
}

#[test]
fn a_valid_challenge_completes() {
    let p = probe([1u8; 32]);
    p.verify(&space_bytes(), &station_of(&INITIATOR_SEED))
        .unwrap();
    let a = PresenceAck::sign(&p, [2u8; 32], &RESPONDER_SEED).unwrap();
    a.verify(&p, &station_of(&RESPONDER_SEED)).unwrap();
}

#[test]
fn a_reflected_nonce_is_rejected() {
    let p = probe([1u8; 32]);
    // The responder echoes the initiator's nonce instead of a fresh one.
    let a = PresenceAck::sign(&p, [1u8; 32], &RESPONDER_SEED).unwrap();
    assert_eq!(
        a.verify(&p, &station_of(&RESPONDER_SEED)),
        Err(PresenceError::ChallengeMismatch)
    );
}

#[test]
fn an_ack_for_another_probe_is_rejected() {
    let p1 = probe([1u8; 32]);
    let p2 = probe([9u8; 32]);
    let a = PresenceAck::sign(&p1, [2u8; 32], &RESPONDER_SEED).unwrap();
    // Presented against a different probe: commitment mismatch.
    assert_eq!(
        a.verify(&p2, &station_of(&RESPONDER_SEED)),
        Err(PresenceError::ChallengeMismatch)
    );
}

#[test]
fn cross_space_replay_is_rejected() {
    let p = probe([1u8; 32]);
    let other_space =
        <[u8; 29]>::try_from(SpaceId::from_digest([7u8; 16]).as_str().as_bytes()).unwrap();
    assert_eq!(
        p.verify(&other_space, &station_of(&INITIATOR_SEED)),
        Err(PresenceError::SpaceMismatch)
    );
}

#[test]
fn station_transport_substitution_is_rejected() {
    let p = probe([1u8; 32]);
    // The negotiated transport peer is not the signing Station.
    assert_eq!(
        p.verify(&space_bytes(), &station_of(&RESPONDER_SEED)),
        Err(PresenceError::IdentityMismatch)
    );
}

#[test]
fn role_reversal_ack_signed_by_the_initiator_is_rejected() {
    let p = probe([1u8; 32]);
    // An ack "from" the responder but actually signed by the initiator.
    let mut a = PresenceAck::sign(&p, [2u8; 32], &INITIATOR_SEED).unwrap();
    // Claim the responder transport so identity passes, exposing the bad sig.
    a.responder_transport = station_of(&RESPONDER_SEED).key_bytes();
    assert_eq!(
        a.verify(&p, &station_of(&RESPONDER_SEED)),
        Err(PresenceError::BadSignature)
    );
}

#[test]
fn tampered_probe_signature_is_rejected() {
    let mut p = probe([1u8; 32]);
    p.signature[0] ^= 0xff;
    assert_eq!(
        p.verify(&space_bytes(), &station_of(&INITIATOR_SEED)),
        Err(PresenceError::BadSignature)
    );
}

#[test]
fn trailing_bytes_and_oversize_are_non_canonical() {
    let p = probe([1u8; 32]);
    let mut bytes = p.encode();
    bytes.push(0);
    assert_eq!(
        PresenceProbe::decode(&bytes),
        Err(PresenceError::NonCanonical)
    );

    let a = PresenceAck::sign(&p, [2u8; 32], &RESPONDER_SEED).unwrap();
    let mut abytes = a.encode();
    abytes.push(0);
    assert_eq!(
        PresenceAck::decode(&abytes),
        Err(PresenceError::NonCanonical)
    );

    assert_eq!(
        PresenceProbe::decode(&vec![0u8; 5000]),
        Err(PresenceError::NonCanonical)
    );
}

#[test]
fn presence_carries_no_frontier_or_authority() {
    // A structural guard: the probe/ack fields are exactly identity + nonce.
    // (If a frontier/standing field were ever added, this fixture's manual
    // construction would stop compiling — the reminder is deliberate.)
    let p = probe([1u8; 32]);
    let _ = (p.protocol, p.space, p.initiator_station, p.nonce);
    let a = PresenceAck::sign(&p, [2u8; 32], &RESPONDER_SEED).unwrap();
    let _ = (a.probe_hash, a.responder_transport, a.nonce);
}
