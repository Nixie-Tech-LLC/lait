//! S5b fixtures: BodyTransactionV1 protection-boundary matrix and store-marker
//! classification.

use lait_kernel::ids::SpaceId;
use replica::body::ContentCommitment;
use replica::frontier::AuthorityFrontier as AF;
use replica::frontier::{AuthorityFrontier, ReplicaFrontier, TransactionId};
use replica::ids::{BodyId, EncodingId, SchemaId, WorldId};
use replica::marker::{MarkerError, StoreMarkerV1, STORE_MAGIC};
use replica::transaction::{
    AuthoritySource, BodyDescriptorV1, BodyTransactionV1, TransactionError,
};

const SIGNER_SEED: [u8; 32] = [12u8; 32];

fn space() -> SpaceId {
    SpaceId::from_digest([6u8; 16])
}
fn space_bytes() -> [u8; 29] {
    <[u8; 29]>::try_from(space().as_str().as_bytes()).unwrap()
}
fn signer_key() -> [u8; 32] {
    lait_kernel::crypto::device_from_seed(&SIGNER_SEED)
        .key_bytes()
        .unwrap()
}
fn auth() -> AuthorityFrontier {
    AuthorityFrontier::from_canonical_bytes(vec![0xA1, 0xB2])
}

fn descriptor(body: [u8; 16], payload: &[u8]) -> BodyDescriptorV1 {
    BodyDescriptorV1 {
        space: space_bytes(),
        world: WorldId::parse("com.example.issues").unwrap(),
        body: BodyId::from_bytes(body),
        schema: SchemaId::parse("issue").unwrap(),
        schema_version: 1,
        encoding: EncodingId::parse("lait.body.v1").unwrap(),
        replica_frontier: ReplicaFrontier::new([1u8; 32], 1),
        content_commitment: ContentCommitment::over_protected_payload(payload).as_bytes(),
        transaction: [3u8; 16],
        signer: signer_key(),
        authority_frontier: auth(),
    }
}

/// A valid two-descriptor transaction (descriptors sorted by BodyId).
fn valid_tx() -> BodyTransactionV1 {
    let d0 = descriptor([0u8; 16], b"cipher-0");
    let d1 = descriptor([1u8; 16], b"cipher-1");
    BodyTransactionV1::sign(
        &space(),
        TransactionId::from_bytes([3u8; 16]),
        ReplicaFrontier::new([1u8; 32], 1),
        auth(),
        vec![d0, d1],
        &SIGNER_SEED,
    )
    .unwrap()
}

#[test]
fn valid_transaction_verifies_and_roundtrips() {
    let tx = valid_tx();
    tx.verify().unwrap();
    let bytes = tx.encode();
    let back = BodyTransactionV1::decode_canonical(&bytes).unwrap();
    assert_eq!(tx, back);
}

#[test]
fn opaque_ciphertext_commitment_check_needs_no_key() {
    // An opaque retainer validates the ciphertext against the descriptor with no
    // decryption key and no plaintext hash.
    let d = descriptor([0u8; 16], b"the-ciphertext");
    assert!(d.commits_to(b"the-ciphertext"));
    assert!(!d.commits_to(b"other-ciphertext"));
}

#[test]
fn version_and_algorithm_rejection() {
    let mut tx = valid_tx();
    tx.version = 2;
    assert_eq!(tx.verify(), Err(TransactionError::UnsupportedVersion(2)));
    let mut tx = valid_tx();
    tx.signature_algorithm = 9;
    assert_eq!(
        tx.verify(),
        Err(TransactionError::UnsupportedSignatureAlgorithm(9))
    );
}

#[test]
fn empty_descriptor_set_is_rejected() {
    let tx = BodyTransactionV1::sign(
        &space(),
        TransactionId::from_bytes([3u8; 16]),
        ReplicaFrontier::new([1u8; 32], 1),
        auth(),
        vec![],
        &SIGNER_SEED,
    )
    .unwrap();
    assert_eq!(tx.verify(), Err(TransactionError::BadDescriptorCount));
}

#[test]
fn unsorted_or_duplicate_descriptors_are_rejected() {
    let mut tx = valid_tx();
    tx.descriptors.reverse();
    // Re-sign so the signature is valid but ordering is wrong.
    let resigned = BodyTransactionV1::sign(
        &space(),
        TransactionId::from_bytes([3u8; 16]),
        ReplicaFrontier::new([1u8; 32], 1),
        auth(),
        tx.descriptors.clone(),
        &SIGNER_SEED,
    )
    .unwrap();
    assert_eq!(
        resigned.verify(),
        Err(TransactionError::UnsortedOrDuplicate)
    );

    // Duplicate key.
    let d = descriptor([0u8; 16], b"x");
    let dup = BodyTransactionV1::sign(
        &space(),
        TransactionId::from_bytes([3u8; 16]),
        ReplicaFrontier::new([1u8; 32], 1),
        auth(),
        vec![d.clone(), d],
        &SIGNER_SEED,
    )
    .unwrap();
    assert_eq!(dup.verify(), Err(TransactionError::UnsortedOrDuplicate));
}

#[test]
fn a_transplanted_descriptor_is_rejected() {
    // A descriptor bound to a different transaction id cannot ride this one.
    let mut foreign = descriptor([0u8; 16], b"c");
    foreign.transaction = [9u8; 16];
    let tx = BodyTransactionV1::sign(
        &space(),
        TransactionId::from_bytes([3u8; 16]),
        ReplicaFrontier::new([1u8; 32], 1),
        auth(),
        vec![foreign],
        &SIGNER_SEED,
    )
    .unwrap();
    assert_eq!(tx.verify(), Err(TransactionError::Transplanted));
}

/// A stub mechanics authority view: authorizes only a named signer key.
struct OnlyAuthorizes([u8; 32]);
impl AuthoritySource for OnlyAuthorizes {
    fn signer_authorized(&self, signer: &[u8; 32], _frontier: &AF) -> bool {
        *signer == self.0
    }
}

#[test]
fn structural_verify_is_not_an_authority_check() {
    // A structurally valid, correctly-signed transaction passes verify() even
    // when its signer has no standing — this is why retention must use
    // verify_authorized.
    let tx = valid_tx();
    tx.verify().unwrap();

    // Mechanics view that authorizes nobody: the transaction is refused.
    struct Nobody;
    impl AuthoritySource for Nobody {
        fn signer_authorized(&self, _s: &[u8; 32], _f: &AF) -> bool {
            false
        }
    }
    assert_eq!(
        tx.verify_authorized(&Nobody),
        Err(TransactionError::AuthorityUnverified)
    );

    // A view that authorizes the actual signer: accepted.
    assert!(tx.verify_authorized(&OnlyAuthorizes(signer_key())).is_ok());
}

#[test]
fn tampered_signature_is_rejected() {
    let mut tx = valid_tx();
    tx.signature[0] ^= 0xff;
    assert_eq!(tx.verify(), Err(TransactionError::BadSignature));
}

#[test]
fn trailing_bytes_are_non_canonical() {
    let mut bytes = valid_tx().encode();
    bytes.push(0);
    assert_eq!(
        BodyTransactionV1::decode_canonical(&bytes),
        Err(TransactionError::NonCanonical)
    );
}

// ---- store marker ----

#[test]
fn a_valid_marker_classifies_to_its_space() {
    let marker = StoreMarkerV1::new(&space()).unwrap();
    let bytes = marker.encode();
    let back = StoreMarkerV1::classify(&bytes).unwrap();
    assert_eq!(back.space(), Some(space()));
}

#[test]
fn a_foreign_directory_is_not_a_replica_store() {
    assert_eq!(
        StoreMarkerV1::classify(b"some other file entirely"),
        Err(MarkerError::NotAReplicaStore)
    );
}

#[test]
fn an_unsupported_version_is_named() {
    let mut marker = StoreMarkerV1::new(&space()).unwrap();
    marker.version = 2;
    // Recompute checksum so it is the version, not the checksum, that trips.
    let bytes = marker.encode();
    assert_eq!(
        StoreMarkerV1::classify(&bytes),
        Err(MarkerError::UnsupportedStoreVersion { found: 2 })
    );
}

#[test]
fn a_corrupt_marker_is_detected() {
    let mut marker = StoreMarkerV1::new(&space()).unwrap();
    marker.checksum[0] ^= 0xff;
    let bytes = marker.encode();
    assert_eq!(
        StoreMarkerV1::classify(&bytes),
        Err(MarkerError::CorruptStoreMarker)
    );
}

#[test]
fn a_corrupt_lait_marker_is_distinct_from_a_foreign_directory() {
    // Magic + version present, but the postcard body is truncated: this is our
    // marker gone bad, not someone else's file.
    let mut bytes = STORE_MAGIC.to_vec();
    bytes.push(1); // version
    bytes.extend_from_slice(&[0x00, 0x01]); // a stub, not a full body
    assert_eq!(
        StoreMarkerV1::classify(&bytes),
        Err(MarkerError::CorruptStoreMarker)
    );
}

#[test]
fn the_magic_is_the_canonical_store_string() {
    assert_eq!(STORE_MAGIC, b"lait/replica/1");
}
