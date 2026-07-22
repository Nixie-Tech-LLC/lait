//! S2 Coordinates v1 packet: golden positive verification plus the exhaustive
//! malformed/substitution rejection matrix required before any routing change.

use mechanics::ids::SpaceId;
use runtime::coordinates::{
    AdmissionCapabilityV1, ApproachRoute, CoordinatesAdmission, CoordinatesError,
    CoordinatesPayloadV1, SignedCoordinatesV1, MAX_INCEPTION, MAX_NAME,
};

const FOUNDER_SEED: [u8; 32] = [7u8; 32];
const RECOVERY_SEED: [u8; 32] = [20u8; 32];
const STATION_SEED: [u8; 32] = [30u8; 32];
const SALT: [u8; 16] = [9u8; 16];

/// A valid founding: (space, recovery_root, canonical inception bytes).
fn founding(founder_seed: [u8; 32], salt: [u8; 16]) -> (SpaceId, [u8; 32], Vec<u8>) {
    let rc = mechanics::space::recovery_commit(&mechanics::space::recovery_pub_of(&RECOVERY_SEED))
        .unwrap();
    let device = mechanics::space::recovery_pub_of(&founder_seed);
    let ws = mechanics::space::derive_space_id(&device, &salt, &rc);
    let (incept, _actor) =
        mechanics::actor::incept_single(&founder_seed, &ws, [1u8; 16], [2u8; 16], None);
    (ws, rc, postcard::to_stdvec(&incept).unwrap())
}

fn station_pubkey() -> [u8; 32] {
    mechanics::crypto::device_from_seed(&STATION_SEED)
        .key_bytes()
        .unwrap()
}

fn space_bytes(ws: &SpaceId) -> [u8; 29] {
    <[u8; 29]>::try_from(ws.as_str().as_bytes()).unwrap()
}

fn valid_payload() -> (SpaceId, CoordinatesPayloadV1) {
    let (ws, rc, incept) = founding(FOUNDER_SEED, SALT);
    let payload = CoordinatesPayloadV1 {
        space: space_bytes(&ws),
        salt: SALT,
        recovery_root: rc,
        founder_inception: incept,
        display_name_hint: "My Space".into(),
        approach_station: station_pubkey(),
        approach_nick_hint: "host".into(),
        approach_routes: vec![ApproachRoute::DirectV4 {
            ip: [10, 0, 0, 1],
            port: 4242,
        }],
        admission: CoordinatesAdmission::None,
    };
    (ws, payload)
}

fn valid_coordinates() -> SignedCoordinatesV1 {
    let (_ws, payload) = valid_payload();
    SignedCoordinatesV1::sign(payload, &STATION_SEED)
}

#[test]
fn valid_coordinates_verify() {
    let (ws, _) = valid_payload();
    let coords = valid_coordinates();
    let verified = coords.verify().expect("valid coordinates verify");
    assert_eq!(verified.space, ws);
    assert_eq!(verified.display_name_hint, "My Space");
    assert_eq!(verified.approach_nick_hint, "host");
    assert_eq!(verified.approach_routes.len(), 1);
    assert!(verified.admission.is_none());
}

#[test]
fn link_roundtrips() {
    let coords = valid_coordinates();
    let link = coords.render();
    assert!(link
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    let back = SignedCoordinatesV1::parse_link(&link).unwrap();
    assert_eq!(coords, back);
}

#[test]
fn signing_is_deterministic() {
    // Ed25519 + fixed seeds → byte-stable Coordinates, a golden anchor.
    assert_eq!(valid_coordinates().encode(), valid_coordinates().encode());
}

#[test]
fn unsupported_version_is_rejected_like_a_spaceticket() {
    // Coordinates v1 (and the pre-carve SpaceTicket tag) are rejected — only
    // wire version 2 is accepted, never negotiated.
    let mut coords = valid_coordinates();
    coords.version = 1;
    assert_eq!(
        coords.verify(),
        Err(CoordinatesError::UnsupportedVersion(1))
    );
    let mut coords = valid_coordinates();
    coords.version = 3;
    assert_eq!(
        coords.verify(),
        Err(CoordinatesError::UnsupportedVersion(3))
    );
}

#[test]
fn unusable_routes_are_rejected() {
    use runtime::coordinates::canonical_routes;
    // A signed route that is unspecified, multicast, or zero-port fails verify.
    for bad in [
        ApproachRoute::DirectV4 {
            ip: [0, 0, 0, 0],
            port: 4242,
        },
        ApproachRoute::DirectV4 {
            ip: [224, 0, 0, 1],
            port: 4242,
        },
        ApproachRoute::DirectV4 {
            ip: [10, 0, 0, 1],
            port: 0,
        },
    ] {
        assert!(!bad.is_usable());
        let (_ws, mut payload) = valid_payload();
        payload.approach_routes = vec![bad];
        let coords = SignedCoordinatesV1::sign(payload, &STATION_SEED);
        assert_eq!(coords.verify(), Err(CoordinatesError::BadAddresses));
    }
    // Canonicalization drops the unusable ones and sorts/dedups the rest.
    let socks: Vec<std::net::SocketAddr> = [
        "0.0.0.0:4242",
        "10.0.0.2:1",
        "10.0.0.1:1",
        "10.0.0.1:1",
        "224.0.0.1:5",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    let routes = canonical_routes(&socks);
    assert_eq!(routes.len(), 2, "unusable dropped, duplicate deduped");
    assert!(routes.windows(2).all(|w| w[0] < w[1]), "sorted, unique");
}

#[test]
fn unsupported_signature_algorithm_is_rejected() {
    let mut coords = valid_coordinates();
    coords.signature_algorithm = 2;
    assert_eq!(
        coords.verify(),
        Err(CoordinatesError::UnsupportedSignatureAlgorithm(2))
    );
}

#[test]
fn issuer_must_equal_approach_station() {
    let mut coords = valid_coordinates();
    coords.issuer = [0xABu8; 32];
    assert_eq!(coords.verify(), Err(CoordinatesError::IssuerMismatch));
}

#[test]
fn tampered_payload_breaks_the_outer_signature() {
    let mut coords = valid_coordinates();
    // Flip a byte the outer signature covers, without touching issuer/station.
    coords.payload.approach_nick_hint = "hostx".into();
    assert_eq!(coords.verify(), Err(CoordinatesError::BadSignature));
}

#[test]
fn unsorted_or_duplicate_addresses_are_rejected() {
    let (_ws, mut payload) = valid_payload();
    payload.approach_routes = vec![
        ApproachRoute::DirectV4 {
            ip: [10, 0, 0, 2],
            port: 1,
        },
        ApproachRoute::DirectV4 {
            ip: [10, 0, 0, 1],
            port: 1,
        },
    ];
    let coords = SignedCoordinatesV1::sign(payload, &STATION_SEED);
    assert_eq!(coords.verify(), Err(CoordinatesError::BadAddresses));
}

#[test]
fn oversized_name_hint_is_rejected() {
    let (_ws, mut payload) = valid_payload();
    payload.display_name_hint = "a".repeat(MAX_NAME + 1);
    let coords = SignedCoordinatesV1::sign(payload, &STATION_SEED);
    assert_eq!(coords.verify(), Err(CoordinatesError::BadNameHint));
}

#[test]
fn non_nfc_name_hint_is_rejected() {
    let (_ws, mut payload) = valid_payload();
    // "e" + combining acute is NFD, not NFC (which would be the single "é").
    payload.display_name_hint = "e\u{0301}".into();
    let coords = SignedCoordinatesV1::sign(payload, &STATION_SEED);
    assert_eq!(coords.verify(), Err(CoordinatesError::BadNameHint));
}

#[test]
fn oversized_inception_is_rejected() {
    let (_ws, mut payload) = valid_payload();
    payload.founder_inception = vec![0u8; MAX_INCEPTION + 1];
    let coords = SignedCoordinatesV1::sign(payload, &STATION_SEED);
    assert_eq!(coords.verify(), Err(CoordinatesError::InceptionTooLarge));
}

#[test]
fn founding_that_the_space_id_does_not_commit_to_is_rejected() {
    let (_ws, mut payload) = valid_payload();
    // A different salt breaks the SpaceId ← founder commitment.
    payload.salt = [0xEEu8; 16];
    let coords = SignedCoordinatesV1::sign(payload, &STATION_SEED);
    assert_eq!(coords.verify(), Err(CoordinatesError::FoundingInvalid));
}

#[test]
fn trailing_bytes_are_non_canonical() {
    let coords = valid_coordinates();
    let mut bytes = coords.encode();
    bytes.push(0x00);
    assert_eq!(
        SignedCoordinatesV1::decode_canonical(&bytes),
        Err(CoordinatesError::NonCanonical)
    );
}

#[test]
fn cross_space_admission_is_rejected() {
    let (ws, _) = valid_payload();
    // An admission bound to a *different* Space cannot ride these Coordinates.
    let (other_ws, _rc, _incept) = founding([77u8; 32], [3u8; 16]);
    assert_ne!(ws, other_ws);
    let cap =
        AdmissionCapabilityV1::sign(&other_ws, [5u8; 16], 100, 200, true, &STATION_SEED).unwrap();

    let (_ws2, mut payload) = valid_payload();
    payload.admission = CoordinatesAdmission::Some(cap);
    let coords = SignedCoordinatesV1::sign(payload, &STATION_SEED);
    assert_eq!(coords.verify(), Err(CoordinatesError::BadAdmission));
}

#[test]
fn valid_admission_verifies_and_reports_expiry() {
    let (ws, _) = valid_payload();
    let cap = AdmissionCapabilityV1::sign(&ws, [5u8; 16], 100, 200, true, &STATION_SEED).unwrap();

    let (_ws, mut payload) = valid_payload();
    payload.admission = CoordinatesAdmission::Some(cap.clone());
    let coords = SignedCoordinatesV1::sign(payload, &STATION_SEED);
    let verified = coords.verify().unwrap();
    let redeemed = verified.admission.expect("admission present");
    assert!(!redeemed.is_expired(150), "before expiry");
    assert!(redeemed.is_expired(200), "at/after expiry");
}

#[test]
fn admission_with_a_tampered_signature_is_rejected() {
    let (ws, _) = valid_payload();
    let mut cap =
        AdmissionCapabilityV1::sign(&ws, [5u8; 16], 100, 200, true, &STATION_SEED).unwrap();
    cap.signature[0] ^= 0xff;
    assert_eq!(
        cap.verify_structure(&ws),
        Err(CoordinatesError::BadSignature)
    );
}
