//! Contact v1 fixtures: the signed Hello/Ack matrix, the frame codec, and the
//! transcript matrix over the pure state machines — happy path, reflection/
//! substitution, wrong-state, duplicate/conflicting/overlapping chunks, gaps,
//! commitment and transcript mismatches, and limit overflows.

use mechanics::ids::{SpaceId, StationId};
use replica::body::ContentCommitment;
use replica::ids::{BodyId, BodyKey, WorldId};
use runtime::contact::{
    abort, authority_record_hash, authority_set_hash, body_chunk_hash, manifest_page_hash,
    manifest_root_ref, AccepterEvent, AccepterValidator, ContactFrame, ContactHello,
    ContactHelloAck, ContactId, ContactWireError, InitiatorReceiver, InitiatorState, Progress,
};

const INITIATOR_SEED: [u8; 32] = [71u8; 32];
const RESPONDER_SEED: [u8; 32] = [72u8; 32];

fn station_of(seed: &[u8; 32]) -> StationId {
    StationId::from_device(&mechanics::crypto::device_from_seed(seed)).unwrap()
}

fn space_bytes() -> [u8; 29] {
    <[u8; 29]>::try_from(SpaceId::from_digest([8u8; 16]).as_str().as_bytes()).unwrap()
}

fn contact() -> ContactId {
    ContactId::from_bytes([9u8; 16])
}

fn body_key() -> BodyKey {
    BodyKey::new(
        WorldId::parse("com.example.notes").unwrap(),
        BodyId::from_bytes([1u8; 16]),
    )
}

// ---------------------------------------------------------------------------
// Hello / HelloAck
// ---------------------------------------------------------------------------

fn hello() -> ContactHello {
    ContactHello::sign(
        1,
        space_bytes(),
        station_of(&RESPONDER_SEED).key_bytes(),
        [3u8; 32],
        contact(),
        &INITIATOR_SEED,
    )
    .unwrap()
}

#[test]
fn a_valid_hello_exchange_completes() {
    let h = hello();
    h.verify(&space_bytes(), &station_of(&INITIATOR_SEED))
        .unwrap();
    let ack = ContactHelloAck::sign(&h, [4u8; 32], &RESPONDER_SEED).unwrap();
    ack.verify(&h, &station_of(&RESPONDER_SEED)).unwrap();
}

#[test]
fn an_unsupported_contact_protocol_is_refused() {
    let h = ContactHello::sign(
        99,
        space_bytes(),
        station_of(&RESPONDER_SEED).key_bytes(),
        [3u8; 32],
        contact(),
        &INITIATOR_SEED,
    )
    .unwrap();
    assert_eq!(
        h.verify(&space_bytes(), &station_of(&INITIATOR_SEED)),
        Err(ContactWireError::UnsupportedProtocol(99))
    );
}

#[test]
fn hello_substitution_and_replay_are_rejected() {
    let h = hello();
    // Cross-Space replay.
    let other = <[u8; 29]>::try_from(SpaceId::from_digest([9u8; 16]).as_str().as_bytes()).unwrap();
    assert_eq!(
        h.verify(&other, &station_of(&INITIATOR_SEED)),
        Err(ContactWireError::SpaceMismatch)
    );
    // Transport substitution: the connection peer is not the signer.
    assert_eq!(
        h.verify(&space_bytes(), &station_of(&RESPONDER_SEED)),
        Err(ContactWireError::IdentityMismatch)
    );
    // Tampered signature.
    let mut bad = hello();
    bad.signature[0] ^= 0xff;
    assert_eq!(
        bad.verify(&space_bytes(), &station_of(&INITIATOR_SEED)),
        Err(ContactWireError::BadSignature)
    );
}

#[test]
fn ack_binds_the_exact_hello_and_a_fresh_nonce() {
    let h1 = hello();
    let h2 = ContactHello::sign(
        1,
        space_bytes(),
        station_of(&RESPONDER_SEED).key_bytes(),
        [30u8; 32],
        contact(),
        &INITIATOR_SEED,
    )
    .unwrap();
    let ack = ContactHelloAck::sign(&h1, [4u8; 32], &RESPONDER_SEED).unwrap();
    // Presented against a different hello: commitment mismatch.
    assert_eq!(
        ack.verify(&h2, &station_of(&RESPONDER_SEED)),
        Err(ContactWireError::ChallengeMismatch)
    );
    // A reflected nonce is refused.
    let reflected = ContactHelloAck::sign(&h1, h1.nonce, &RESPONDER_SEED).unwrap();
    assert_eq!(
        reflected.verify(&h1, &station_of(&RESPONDER_SEED)),
        Err(ContactWireError::ChallengeMismatch)
    );
}

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

#[test]
fn frame_tags_are_the_canonical_wire_values() {
    let frames: Vec<(u8, ContactFrame)> = vec![
        (
            1,
            ContactFrame::AuthorityOffer {
                authority_frontier: vec![1],
                record_count: 0,
                total_bytes: 0,
                set_hash: [0u8; 32],
            },
        ),
        (
            2,
            ContactFrame::AuthorityChunk {
                index: 0,
                record_hash: [0u8; 32],
                bytes: vec![1],
            },
        ),
        (
            3,
            ContactFrame::AuthorityEnd {
                record_count: 0,
                set_hash: [0u8; 32],
            },
        ),
        (
            4,
            ContactFrame::ManifestOffer {
                root_bytes: vec![1],
            },
        ),
        (
            5,
            ContactFrame::ManifestRequest {
                root: [0u8; 32],
                first_page: 0,
                page_count: 1,
            },
        ),
        (
            6,
            ContactFrame::ManifestPage {
                root: [0u8; 32],
                page_index: 0,
                page_hash: [0u8; 32],
                page_bytes: vec![1],
            },
        ),
        (
            7,
            ContactFrame::BodyRequest {
                transaction: [0u8; 32],
                body: body_key(),
                offset: 0,
                length: 1,
            },
        ),
        (
            8,
            ContactFrame::BodyChunk {
                transaction: [0u8; 32],
                body: body_key(),
                offset: 0,
                total: 1,
                chunk_hash: [0u8; 32],
                bytes: vec![1],
            },
        ),
        (
            9,
            ContactFrame::BodyEnd {
                transaction: [0u8; 32],
                body: body_key(),
                total: 0,
                content_commitment: [0u8; 32],
            },
        ),
        (
            10,
            ContactFrame::TransferEnd {
                authority_set_hash: [0u8; 32],
                manifest_root: [0u8; 32],
                body_count: 0,
                transcript_hash: [0u8; 32],
            },
        ),
        (
            11,
            ContactFrame::TransferAck {
                transcript_hash: [0u8; 32],
                received_bytes: 0,
            },
        ),
        (12, ContactFrame::Abort { code: 3 }),
    ];
    for (tag, frame) in frames {
        assert_eq!(frame.tag(), tag);
        let raw = frame.encode(&contact());
        assert_eq!(raw[0], tag, "tag byte leads the frame");
        assert_eq!(&raw[1..17], &contact().as_bytes(), "contact id follows");
        let (cid, back) = ContactFrame::decode(&raw).unwrap();
        assert_eq!(cid, contact());
        assert_eq!(back, frame, "roundtrip for tag {tag}");
    }
}

#[test]
fn unknown_tags_and_trailing_bytes_are_rejected() {
    let mut raw = ContactFrame::Abort { code: 1 }.encode(&contact());
    raw[0] = 99;
    assert_eq!(
        ContactFrame::decode(&raw),
        Err(ContactWireError::UnknownTag(99))
    );
    let mut raw = ContactFrame::Abort { code: 1 }.encode(&contact());
    raw.push(0);
    assert_eq!(
        ContactFrame::decode(&raw),
        Err(ContactWireError::NonCanonical)
    );
}

// ---------------------------------------------------------------------------
// Transcript matrix
// ---------------------------------------------------------------------------

/// Build the accepter's happy-path frame sequence: 2 authority records, a
/// manifest with one page, one body in two chunks, and the closing TransferEnd
/// (with the correct transcript hash over everything before it).
fn happy_frames() -> Vec<Vec<u8>> {
    let records: Vec<Vec<u8>> = vec![b"rec-0".to_vec(), b"rec-1".to_vec()];
    let record_hashes: Vec<[u8; 32]> = records.iter().map(|r| authority_record_hash(r)).collect();
    let set_hash = authority_set_hash(&record_hashes);
    let root_bytes = b"canonical-manifest-root".to_vec();
    let root = manifest_root_ref(&root_bytes);
    let page_bytes = b"canonical-page-0".to_vec();
    let payload = b"protected-body-payload".to_vec();
    let (c0, c1) = payload.split_at(10);
    let commitment = ContentCommitment::over_protected_payload(&payload).as_bytes();

    let mut frames: Vec<ContactFrame> = vec![
        ContactFrame::AuthorityOffer {
            authority_frontier: vec![0xAA],
            record_count: 2,
            total_bytes: records.iter().map(|r| r.len() as u64).sum(),
            set_hash,
        },
        ContactFrame::AuthorityChunk {
            index: 0,
            record_hash: record_hashes[0],
            bytes: records[0].clone(),
        },
        ContactFrame::AuthorityChunk {
            index: 1,
            record_hash: record_hashes[1],
            bytes: records[1].clone(),
        },
        ContactFrame::AuthorityEnd {
            record_count: 2,
            set_hash,
        },
        ContactFrame::ManifestOffer {
            root_bytes: root_bytes.clone(),
        },
        ContactFrame::ManifestPage {
            root,
            page_index: 0,
            page_hash: manifest_page_hash(&page_bytes),
            page_bytes,
        },
        ContactFrame::BodyChunk {
            transaction: [2u8; 32],
            body: body_key(),
            offset: 0,
            total: payload.len() as u64,
            chunk_hash: body_chunk_hash(c0),
            bytes: c0.to_vec(),
        },
        ContactFrame::BodyChunk {
            transaction: [2u8; 32],
            body: body_key(),
            offset: c0.len() as u64,
            total: payload.len() as u64,
            chunk_hash: body_chunk_hash(c1),
            bytes: c1.to_vec(),
        },
        ContactFrame::BodyEnd {
            transaction: [2u8; 32],
            body: body_key(),
            total: payload.len() as u64,
            content_commitment: commitment,
        },
    ];

    // The transcript covers every raw frame before TransferEnd.
    let mut raw: Vec<Vec<u8>> = frames.drain(..).map(|f| f.encode(&contact())).collect();
    let mut t = blake3::Hasher::new();
    t.update(b"lait/contact/1/transcript");
    for r in &raw {
        t.update(r);
    }
    raw.push(
        ContactFrame::TransferEnd {
            authority_set_hash: set_hash,
            manifest_root: root,
            body_count: 1,
            transcript_hash: *t.finalize().as_bytes(),
        }
        .encode(&contact()),
    );
    raw
}

#[test]
fn a_complete_transfer_stages_acks_and_yields_the_material() {
    let mut rx = InitiatorReceiver::new(contact());
    let frames = happy_frames();
    let last = frames.len() - 1;
    let mut accepter = AccepterValidator::new(contact());
    for (i, raw) in frames.iter().enumerate() {
        accepter.record_sent(raw);
        let progress = rx.on_frame(raw).unwrap();
        if i < last {
            assert_eq!(progress, Progress::Continue);
        } else {
            let Progress::SendAck(ack) = progress else {
                panic!("TransferEnd must yield an ack");
            };
            assert_eq!(rx.state(), InitiatorState::AckSent);
            // The accepter accepts exactly this ack, once.
            let raw_ack = ack.encode(&contact());
            assert!(matches!(
                accepter.on_frame(&raw_ack).unwrap(),
                AccepterEvent::Acked { .. }
            ));
            assert_eq!(accepter.on_frame(&raw_ack), Err(abort::WRONG_STATE));
        }
    }
    let material = rx.into_received().expect("clean transfer yields material");
    assert_eq!(
        material.authority_records,
        vec![b"rec-0".to_vec(), b"rec-1".to_vec()]
    );
    assert_eq!(material.authority_frontier, vec![0xAA]);
    assert_eq!(material.manifest_root_bytes, b"canonical-manifest-root");
    assert_eq!(material.manifest_pages[&0], b"canonical-page-0");
    assert_eq!(
        material.bodies[&([2u8; 32], body_key())],
        b"protected-body-payload"
    );
}

#[test]
fn transfer_ack_means_receipt_not_convergence() {
    // Structural: the machine yields ReceivedMaterial whose docs and type carry
    // no frontier/commit — Convergence is a separate, later step. This test
    // pins that a completed Contact produced *bytes*, nothing more.
    let mut rx = InitiatorReceiver::new(contact());
    for raw in happy_frames() {
        rx.on_frame(&raw).unwrap();
    }
    let material = rx.into_received().unwrap();
    // The material is inert bytes; nothing here is a commit receipt.
    assert!(!material.bodies.is_empty());
}

#[test]
fn wrong_state_and_unknown_tag_abort() {
    // A body chunk before any authority material is wrong-state.
    let mut rx = InitiatorReceiver::new(contact());
    let stray = ContactFrame::BodyChunk {
        transaction: [2u8; 32],
        body: body_key(),
        offset: 0,
        total: 1,
        chunk_hash: body_chunk_hash(b"x"),
        bytes: b"x".to_vec(),
    }
    .encode(&contact());
    assert_eq!(rx.on_frame(&stray), Err(abort::WRONG_STATE));
    // After an abort the machine refuses everything.
    assert_eq!(rx.state(), InitiatorState::Aborted);

    let mut rx = InitiatorReceiver::new(contact());
    let mut raw = ContactFrame::Abort { code: 1 }.encode(&contact());
    raw[0] = 42;
    assert_eq!(rx.on_frame(&raw), Err(abort::UNKNOWN_TAG));
}

#[test]
fn a_foreign_contact_id_aborts() {
    let mut rx = InitiatorReceiver::new(contact());
    let foreign = ContactFrame::AuthorityOffer {
        authority_frontier: vec![],
        record_count: 0,
        total_bytes: 0,
        set_hash: authority_set_hash(&[]),
    }
    .encode(&ContactId::from_bytes([0xEE; 16]));
    assert_eq!(rx.on_frame(&foreign), Err(abort::CONTACT_MISMATCH));
}

#[test]
fn chunk_rules_exact_dup_ok_conflict_and_overlap_abort() {
    // Reach BodiesReceiving with an empty authority set + manifest.
    let preamble = |rx: &mut InitiatorReceiver| {
        let set = authority_set_hash(&[]);
        for f in [
            ContactFrame::AuthorityOffer {
                authority_frontier: vec![],
                record_count: 0,
                total_bytes: 0,
                set_hash: set,
            },
            ContactFrame::AuthorityEnd {
                record_count: 0,
                set_hash: set,
            },
            ContactFrame::ManifestOffer {
                root_bytes: b"root".to_vec(),
            },
        ] {
            rx.on_frame(&f.encode(&contact())).unwrap();
        }
    };
    let chunk = |bytes: &[u8], offset: u64| ContactFrame::BodyChunk {
        transaction: [2u8; 32],
        body: body_key(),
        offset,
        total: 8,
        chunk_hash: body_chunk_hash(bytes),
        bytes: bytes.to_vec(),
    };

    // Exact duplicate is idempotent.
    let mut rx = InitiatorReceiver::new(contact());
    preamble(&mut rx);
    rx.on_frame(&chunk(b"aaaa", 0).encode(&contact())).unwrap();
    assert_eq!(
        rx.on_frame(&chunk(b"aaaa", 0).encode(&contact())),
        Ok(Progress::Continue)
    );

    // Conflicting duplicate (same offset, different bytes) aborts.
    let mut rx = InitiatorReceiver::new(contact());
    preamble(&mut rx);
    rx.on_frame(&chunk(b"aaaa", 0).encode(&contact())).unwrap();
    assert_eq!(
        rx.on_frame(&chunk(b"bbbb", 0).encode(&contact())),
        Err(abort::CHUNK_CONFLICT)
    );

    // Partial overlap aborts.
    let mut rx = InitiatorReceiver::new(contact());
    preamble(&mut rx);
    rx.on_frame(&chunk(b"aaaa", 0).encode(&contact())).unwrap();
    assert_eq!(
        rx.on_frame(&chunk(b"cccc", 2).encode(&contact())),
        Err(abort::CHUNK_CONFLICT)
    );

    // A zero-length nonterminal chunk aborts.
    let mut rx = InitiatorReceiver::new(contact());
    preamble(&mut rx);
    assert_eq!(
        rx.on_frame(&chunk(b"", 0).encode(&contact())),
        Err(abort::EMPTY_CHUNK)
    );
}

#[test]
fn a_gap_at_body_end_aborts_and_a_bad_commitment_aborts() {
    let set = authority_set_hash(&[]);
    let preamble = [
        ContactFrame::AuthorityOffer {
            authority_frontier: vec![],
            record_count: 0,
            total_bytes: 0,
            set_hash: set,
        },
        ContactFrame::AuthorityEnd {
            record_count: 0,
            set_hash: set,
        },
        ContactFrame::ManifestOffer {
            root_bytes: b"root".to_vec(),
        },
    ];

    // Gap: only bytes [0,4) of an 8-byte body arrived.
    let mut rx = InitiatorReceiver::new(contact());
    for f in preamble.clone() {
        rx.on_frame(&f.encode(&contact())).unwrap();
    }
    rx.on_frame(
        &ContactFrame::BodyChunk {
            transaction: [2u8; 32],
            body: body_key(),
            offset: 0,
            total: 8,
            chunk_hash: body_chunk_hash(b"aaaa"),
            bytes: b"aaaa".to_vec(),
        }
        .encode(&contact()),
    )
    .unwrap();
    assert_eq!(
        rx.on_frame(
            &ContactFrame::BodyEnd {
                transaction: [2u8; 32],
                body: body_key(),
                total: 8,
                content_commitment: [0u8; 32],
            }
            .encode(&contact()),
        ),
        Err(abort::GAP)
    );

    // Bad commitment: complete coverage but the payload hash disagrees.
    let mut rx = InitiatorReceiver::new(contact());
    for f in preamble {
        rx.on_frame(&f.encode(&contact())).unwrap();
    }
    rx.on_frame(
        &ContactFrame::BodyChunk {
            transaction: [2u8; 32],
            body: body_key(),
            offset: 0,
            total: 4,
            chunk_hash: body_chunk_hash(b"aaaa"),
            bytes: b"aaaa".to_vec(),
        }
        .encode(&contact()),
    )
    .unwrap();
    assert_eq!(
        rx.on_frame(
            &ContactFrame::BodyEnd {
                transaction: [2u8; 32],
                body: body_key(),
                total: 4,
                content_commitment: [0u8; 32],
            }
            .encode(&contact()),
        ),
        Err(abort::HASH_MISMATCH)
    );
}

#[test]
fn a_tampered_transcript_aborts() {
    let mut rx = InitiatorReceiver::new(contact());
    let mut frames = happy_frames();
    let last = frames.len() - 1;
    // Tamper the TransferEnd's transcript hash.
    let (cid, decoded) = ContactFrame::decode(&frames[last]).unwrap();
    let ContactFrame::TransferEnd {
        authority_set_hash,
        manifest_root,
        body_count,
        ..
    } = decoded
    else {
        panic!("last frame is TransferEnd");
    };
    frames[last] = ContactFrame::TransferEnd {
        authority_set_hash,
        manifest_root,
        body_count,
        transcript_hash: [0xEE; 32],
    }
    .encode(&cid);
    for (i, raw) in frames.iter().enumerate() {
        if i < last {
            rx.on_frame(raw).unwrap();
        } else {
            assert_eq!(rx.on_frame(raw), Err(abort::TRANSCRIPT_MISMATCH));
        }
    }
}

#[test]
fn frame_count_overflow_fails_closed() {
    let mut rx = InitiatorReceiver::new(contact());
    let set_hash = authority_set_hash(&[[0u8; 32]; 0]);
    // An offer promising many records, then tiny chunks until the frame cap.
    let record: Vec<u8> = vec![7u8];
    let rh = authority_record_hash(&record);
    rx.on_frame(
        &ContactFrame::AuthorityOffer {
            authority_frontier: vec![],
            record_count: 10_000,
            total_bytes: 10_000,
            set_hash,
        }
        .encode(&contact()),
    )
    .unwrap();
    let mut aborted = None;
    for i in 0..5000u32 {
        let raw = ContactFrame::AuthorityChunk {
            index: i,
            record_hash: rh,
            bytes: record.clone(),
        }
        .encode(&contact());
        match rx.on_frame(&raw) {
            Ok(_) => {}
            Err(code) => {
                aborted = Some((i, code));
                break;
            }
        }
    }
    let (at, code) = aborted.expect("the frame cap must trip");
    assert_eq!(code, abort::LIMITS);
    assert!(at < 4096, "aborted at frame {at} within the cap");
}

// ---------------------------------------------------------------------------
// Accepter request validation
// ---------------------------------------------------------------------------

#[test]
fn manifest_requests_must_reference_the_offer_in_range() {
    let mut acc = AccepterValidator::new(contact());
    let root_bytes = b"the-root".to_vec();
    let root = manifest_root_ref(&root_bytes);
    // No offer yet: any request is bad.
    assert_eq!(
        acc.on_frame(
            &ContactFrame::ManifestRequest {
                root,
                first_page: 0,
                page_count: 1,
            }
            .encode(&contact()),
        ),
        Err(abort::BAD_REQUEST)
    );
    // Offer + two pages sent.
    acc.record_sent(&ContactFrame::ManifestOffer { root_bytes }.encode(&contact()));
    for i in 0..2u32 {
        acc.record_sent(
            &ContactFrame::ManifestPage {
                root,
                page_index: i,
                page_hash: manifest_page_hash(b"p"),
                page_bytes: b"p".to_vec(),
            }
            .encode(&contact()),
        );
    }
    // In-range request is accepted.
    assert!(matches!(
        acc.on_frame(
            &ContactFrame::ManifestRequest {
                root,
                first_page: 0,
                page_count: 2,
            }
            .encode(&contact()),
        )
        .unwrap(),
        AccepterEvent::ManifestRequest { .. }
    ));
    // Out-of-range and wrong-root requests are refused.
    assert_eq!(
        acc.on_frame(
            &ContactFrame::ManifestRequest {
                root,
                first_page: 1,
                page_count: 2,
            }
            .encode(&contact()),
        ),
        Err(abort::BAD_REQUEST)
    );
    assert_eq!(
        acc.on_frame(
            &ContactFrame::ManifestRequest {
                root: [0xEE; 32],
                first_page: 0,
                page_count: 1,
            }
            .encode(&contact()),
        ),
        Err(abort::BAD_REQUEST)
    );
    // An ack before TransferEnd is wrong-state.
    assert_eq!(
        acc.on_frame(
            &ContactFrame::TransferAck {
                transcript_hash: [0u8; 32],
                received_bytes: 0,
            }
            .encode(&contact()),
        ),
        Err(abort::WRONG_STATE)
    );
}
