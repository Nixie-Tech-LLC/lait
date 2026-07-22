//! BodyTransaction envelope protection-boundary matrix and store-marker
//! classification (the semantic-named transaction, `lait/body-transaction/2`).

use mechanics::demand::{AuthorizationDemand, PolicyCapability, PolicyResource};
use mechanics::ids::SpaceId;
use replica::body::ContentCommitment;
use replica::frontier::AuthorityFrontier as AF;
use replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use replica::ids::{BodyId, EncodingId, SchemaId, WorldId};
use replica::marker::{MarkerError, StoreMarker, STORE_MAGIC};
use replica::transaction::{
    AuthoritySource, BodyDescriptor, BodyTransaction, SeedSigner, TransactionError,
    TransactionSignRequest, NO_PARENT_ROOT,
};
use replica::{StaticAuthorizer, TransactionAuthorizer};

const SIGNER_SEED: [u8; 32] = [12u8; 32];

fn space() -> SpaceId {
    SpaceId::from_digest([6u8; 16])
}
fn world() -> WorldId {
    WorldId::parse("com.example.issues").unwrap()
}
fn signer_key() -> [u8; 32] {
    mechanics::crypto::device_from_seed(&SIGNER_SEED)
        .key_bytes()
        .unwrap()
}
fn auth() -> AuthorityFrontier {
    AuthorityFrontier::from_canonical_bytes(vec![0xA1, 0xB2])
}
fn demand() -> Vec<u8> {
    AuthorizationDemand::require(
        PolicyCapability::new("com.example.issues", "write"),
        PolicyResource::space("com.example.issues"),
    )
    .encode_canonical()
    .unwrap()
}

fn descriptor(body: [u8; 16], payload: &[u8]) -> BodyDescriptor {
    BodyDescriptor {
        world: world(),
        body: BodyId::from_bytes(body),
        schema: SchemaId::parse("issue").unwrap(),
        schema_version: 1,
        encoding: EncodingId::parse("lait.body.v1").unwrap(),
        content_commitment: ContentCommitment::over_protected_payload(payload).as_bytes(),
    }
}

fn sign(descriptors: Vec<BodyDescriptor>) -> Result<BodyTransaction, String> {
    let authorizer = StaticAuthorizer {
        world: world(),
        implementation_id: [0u8; 32],
    };
    BodyTransaction::sign_with(
        TransactionSignRequest {
            space: &space(),
            parent_manifest_root: NO_PARENT_ROOT,
            replica_frontier: ReplicaFrontier::new([1u8; 32], 1),
            authority_frontier: auth(),
            actor: "actor",
            intent_digest: [4u8; 32],
            operations_digest: [5u8; 32],
            demand: demand(),
            descriptors,
        },
        &SeedSigner(&SIGNER_SEED),
        |core| authorizer.authorize(core),
    )
}

/// A valid two-descriptor transaction (descriptors sorted by BodyId).
fn valid_tx() -> BodyTransaction {
    sign(vec![
        descriptor([0u8; 16], b"cipher-0"),
        descriptor([1u8; 16], b"cipher-1"),
    ])
    .unwrap()
}

#[test]
fn valid_transaction_verifies_and_roundtrips() {
    let tx = valid_tx();
    tx.verify().unwrap();
    let bytes = tx.encode();
    let back = BodyTransaction::decode_canonical(&bytes).unwrap();
    assert_eq!(tx, back);
    // The id is the full signed-envelope digest and is stable across decode.
    assert_eq!(tx.id(), back.id());
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
    tx.core.version = 2;
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
    let tx = sign(vec![]).unwrap();
    assert_eq!(tx.verify(), Err(TransactionError::BadDescriptorCount));
}

#[test]
fn unsorted_or_duplicate_descriptors_are_rejected() {
    // Re-signed with reversed order: the signature is valid but ordering wrong.
    let resigned = sign(vec![
        descriptor([1u8; 16], b"cipher-1"),
        descriptor([0u8; 16], b"cipher-0"),
    ])
    .unwrap();
    assert_eq!(
        resigned.verify(),
        Err(TransactionError::UnsortedOrDuplicate)
    );

    // Duplicate key.
    let d = descriptor([0u8; 16], b"x");
    let dup = sign(vec![d.clone(), d]).unwrap();
    assert_eq!(dup.verify(), Err(TransactionError::UnsortedOrDuplicate));
}

#[test]
fn a_tampered_receipt_binding_is_rejected() {
    // The receipt is byte-bound to the core: flip the receipt's core-digest
    // binding and verify refuses (the envelope-positional heir of the old
    // "transplanted descriptor" rule).
    let mut tx = valid_tx();
    let mut receipt =
        mechanics::demand::AuthorizationReceipt::decode(&tx.authorization_receipt).unwrap();
    receipt.body_transaction_core_digest[0] ^= 0xff;
    tx.authorization_receipt = receipt.encode();
    assert!(matches!(
        tx.verify(),
        Err(TransactionError::ReceiptUnbound(_)) | Err(TransactionError::BadSignature)
    ));
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

    // A view that authorizes the actual signer: accepted (the default
    // verify_transaction checks signer standing at the referenced frontier).
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
        BodyTransaction::decode_canonical(&bytes),
        Err(TransactionError::NonCanonical)
    );
}

// ---- store marker ----

#[test]
fn a_valid_marker_classifies_to_its_space() {
    let marker = StoreMarker::new(&space()).unwrap();
    let bytes = marker.encode();
    let back = StoreMarker::classify(&bytes).unwrap();
    assert_eq!(back.space(), Some(space()));
}

#[test]
fn a_foreign_directory_is_not_a_replica_store() {
    assert_eq!(
        StoreMarker::classify(b"some other file entirely"),
        Err(MarkerError::NotAReplicaStore)
    );
}

#[test]
fn an_unsupported_version_is_named() {
    let mut marker = StoreMarker::new(&space()).unwrap();
    marker.version = 2;
    // Recompute checksum so it is the version, not the checksum, that trips.
    let bytes = marker.encode();
    assert_eq!(
        StoreMarker::classify(&bytes),
        Err(MarkerError::UnsupportedStoreVersion { found: 2 })
    );
}

#[test]
fn a_corrupt_marker_is_detected() {
    let mut marker = StoreMarker::new(&space()).unwrap();
    marker.checksum[0] ^= 0xff;
    let bytes = marker.encode();
    assert_eq!(
        StoreMarker::classify(&bytes),
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
        StoreMarker::classify(&bytes),
        Err(MarkerError::CorruptStoreMarker)
    );
}

#[test]
fn the_magic_is_the_canonical_store_string() {
    assert_eq!(STORE_MAGIC, b"lait/replica/1");
}
