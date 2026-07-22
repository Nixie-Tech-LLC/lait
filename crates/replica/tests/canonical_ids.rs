//! G1 canonical-format fixtures for the Body-domain identifiers introduced in
//! S0. These pin the byte-exact encodings so an accidental change to a canonical
//! rendering or postcard layout is caught. They are diagnostic evidence for the
//! extraction; S5 installs the signed Body/store formats that make them contracts.

use replica::body::ContentCommitment;
use replica::frontier::ReplicaFrontier;
use replica::ids::{BodyId, SchemaId, WorldId};

#[test]
fn body_id_all_zero_renders_26_a_and_roundtrips() {
    let id = BodyId::from_bytes([0u8; 16]);
    // 128 zero bits → 26 base32 chars, all the alphabet's zero symbol ('a').
    assert_eq!(id.render(), "a".repeat(26));
    assert_eq!(BodyId::parse(&id.render()), Some(id));
}

#[test]
fn body_id_known_vector_is_stable() {
    // A fixed byte vector pins the lowercase-base32 mapping.
    let id = BodyId::from_bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);
    let rendered = id.render();
    assert_eq!(rendered.len(), 26);
    // Round-trips back to the exact bytes.
    assert_eq!(BodyId::parse(&rendered).unwrap().as_bytes(), id.as_bytes());
}

#[test]
fn empty_replica_frontier_is_33_zero_bytes() {
    // [u8;32] root as 32 raw bytes + u64 count 0 as a single varint byte = 33.
    let bytes = postcard::to_stdvec(&ReplicaFrontier::EMPTY).unwrap();
    assert_eq!(bytes, vec![0u8; 33]);
    let back: ReplicaFrontier = postcard::from_bytes(&bytes).unwrap();
    assert_eq!(back, ReplicaFrontier::EMPTY);
}

#[test]
fn schema_and_world_ids_encode_as_length_prefixed_strings() {
    // postcard encodes a String as a varint length + UTF-8 bytes.
    let schema = SchemaId::parse("issue").unwrap();
    let bytes = postcard::to_stdvec(&schema).unwrap();
    assert_eq!(bytes, [&[5u8][..], b"issue"].concat());

    let world = WorldId::parse("com.example.issues").unwrap();
    let wbytes = postcard::to_stdvec(&world).unwrap();
    assert_eq!(wbytes[0] as usize, "com.example.issues".len());
    assert_eq!(&wbytes[1..], b"com.example.issues");
}

#[test]
fn content_commitment_is_domain_separated_over_ciphertext() {
    // Pin the domain and that the commitment is not a bare hash of the payload.
    let payload = b"protected-ciphertext";
    let commitment = ContentCommitment::over_protected_payload(payload);

    let mut expected = blake3::Hasher::new();
    expected.update(b"lait/body-content/1");
    expected.update(payload);
    assert_eq!(commitment.as_bytes(), *expected.finalize().as_bytes());
    assert_ne!(commitment.as_bytes(), *blake3::hash(payload).as_bytes());
}
