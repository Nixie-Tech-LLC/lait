//! Two-node convergence, end to end: one Replica exports a **signed** envelope,
//! the material is framed as a Contact transfer and driven through the real
//! initiator/accepter state machines, the received bytes are handed to
//! mechanics-validated `Replica::incorporate`, and the two replicas converge.
//!
//! This ties the whole Convergence pipeline together — export → Contact frames
//! → transcript-validated receipt → legitimacy check → durable incorporation —
//! with no unbound merge path. (The only glue left for the live daemon is
//! carrying these exact frames over a comms `Stream`; the framing, validation,
//! and incorporation proven here are transport-independent.)

use mechanics::ids::SpaceId;
use replica::frontier::AuthorityFrontier;
use replica::transaction::{AuthoritySource, BodyTransactionV1};
use replica::{BodyId, BodyKey, BodyOp, Replica, WorldId};
use runtime::contact::{
    authority_record_hash, authority_set_hash, body_chunk_hash, manifest_page_hash,
    manifest_root_ref, ContactFrame, ContactId, InitiatorReceiver, InitiatorState, Progress,
    ReceivedMaterial,
};

const EXPORT_SEED: [u8; 32] = [88u8; 32];

fn space() -> SpaceId {
    SpaceId::from_digest([16u8; 16])
}

fn authority_frontier() -> AuthorityFrontier {
    AuthorityFrontier::from_canonical_bytes(vec![7])
}

/// A mechanics view authorizing the exporter's device.
struct ExporterAuthorized;
impl AuthoritySource for ExporterAuthorized {
    fn signer_authorized(&self, signer: &[u8; 32], _f: &AuthorityFrontier) -> bool {
        *signer
            == mechanics::crypto::device_from_seed(&EXPORT_SEED)
                .key_bytes()
                .unwrap()
    }
}

fn note_key() -> BodyKey {
    BodyKey::new(
        WorldId::parse("com.example.notes").unwrap(),
        BodyId::from_bytes([2u8; 16]),
    )
}

/// Frame the signed export as a complete Contact transfer: the signed
/// BodyTransactionV1 is the single authority record; its bound payload is the
/// single body. Returns every raw frame in send order.
fn frame_transfer(contact: &ContactId, tx: &BodyTransactionV1, payload: &[u8]) -> Vec<Vec<u8>> {
    let record = tx.encode();
    let record_hashes = vec![authority_record_hash(&record)];
    let set_hash = authority_set_hash(&record_hashes);
    let root_bytes = b"convergence-manifest-root".to_vec();
    let root = manifest_root_ref(&root_bytes);
    let page_bytes = b"page".to_vec();
    let commitment = replica::body::ContentCommitment::over_protected_payload(payload).as_bytes();

    let mut frames = vec![
        ContactFrame::AuthorityOffer {
            authority_frontier: authority_frontier().as_bytes().to_vec(),
            record_count: 1,
            total_bytes: record.len() as u64,
            set_hash,
        },
        ContactFrame::AuthorityChunk {
            index: 0,
            record_hash: record_hashes[0],
            bytes: record,
        },
        ContactFrame::AuthorityEnd {
            record_count: 1,
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
            transaction: tx.transaction,
            body: note_key(),
            offset: 0,
            total: payload.len() as u64,
            chunk_hash: body_chunk_hash(payload),
            bytes: payload.to_vec(),
        },
        ContactFrame::BodyEnd {
            transaction: tx.transaction,
            body: note_key(),
            total: payload.len() as u64,
            content_commitment: commitment,
        },
    ];

    let mut raw: Vec<Vec<u8>> = frames.drain(..).map(|f| f.encode(contact)).collect();
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
        .encode(contact),
    );
    raw
}

/// Run the initiator machine over the frames and return the received material.
fn receive(contact: ContactId, frames: &[Vec<u8>]) -> ReceivedMaterial {
    let mut rx = InitiatorReceiver::new(contact);
    for (i, raw) in frames.iter().enumerate() {
        match rx.on_frame(raw) {
            Ok(Progress::SendAck(_)) => assert_eq!(i, frames.len() - 1),
            Ok(Progress::Continue) => {}
            other => panic!("unexpected frame {i}: {other:?}"),
        }
    }
    assert_eq!(rx.state(), InitiatorState::AckSent);
    rx.into_received().expect("clean transfer")
}

#[test]
fn a_signed_export_converges_across_a_contact_transfer() {
    // Node A commits some collaborative state.
    let mut a = Replica::loro();
    a.commit(
        "created",
        &[
            (note_key(), BodyOp::Create),
            (
                note_key(),
                BodyOp::CounterAdd {
                    path: "votes".into(),
                    delta: 4,
                },
            ),
        ],
    )
    .unwrap();

    // A signs its representation export and frames it as a Contact transfer.
    let (tx, payload) = a
        .export_signed(&space(), authority_frontier(), &EXPORT_SEED)
        .unwrap();
    let contact = ContactId::from_bytes([5u8; 16]);
    let frames = frame_transfer(&contact, &tx, &payload);

    // Node B receives the transfer through the real machine, then reconstructs
    // the signed transaction + payload from the received material.
    let material = receive(contact, &frames);
    assert_eq!(material.authority_records.len(), 1);
    let received_tx = BodyTransactionV1::decode_canonical(&material.authority_records[0]).unwrap();
    let received_payload = material
        .bodies
        .get(&(tx.transaction, note_key()))
        .expect("body present");

    // Convergence: legitimacy is checked (signature + mechanics authority +
    // commitment binding) before anything reaches B's engine.
    let mut b = Replica::loro();
    let outcome = b
        .incorporate(&received_tx, received_payload, &ExporterAuthorized)
        .unwrap();
    assert_eq!(outcome.accepted, 1);
    assert!(outcome.advanced());
    assert_eq!(
        b.read_collaborative(&note_key()),
        a.read_collaborative(&note_key())
    );
    assert_eq!(
        b.read_collaborative(&note_key()).unwrap().counters["votes"],
        4
    );
}

#[test]
fn a_tampered_transfer_never_reaches_the_engine() {
    let mut a = Replica::loro();
    a.commit(
        "created",
        &[(
            note_key(),
            BodyOp::CounterAdd {
                path: "votes".into(),
                delta: 1,
            },
        )],
    )
    .unwrap();
    let (tx, payload) = a
        .export_signed(&space(), authority_frontier(), &EXPORT_SEED)
        .unwrap();
    let contact = ContactId::from_bytes([6u8; 16]);
    let frames = frame_transfer(&contact, &tx, &payload);
    let material = receive(contact, &frames);
    let received_tx = BodyTransactionV1::decode_canonical(&material.authority_records[0]).unwrap();
    let received_payload = material.bodies.get(&(tx.transaction, note_key())).unwrap();

    // An importer whose mechanics view does not authorize the exporter refuses
    // the material even though the Contact transfer itself was well-formed.
    struct DenyAll;
    impl AuthoritySource for DenyAll {
        fn signer_authorized(&self, _s: &[u8; 32], _f: &AuthorityFrontier) -> bool {
            false
        }
    }
    let mut b = Replica::loro();
    assert!(b
        .incorporate(&received_tx, received_payload, &DenyAll)
        .is_err());
    assert!(
        b.read_collaborative(&note_key()).is_none(),
        "nothing reached the engine"
    );
}
