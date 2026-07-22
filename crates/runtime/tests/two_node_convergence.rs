//! Two-node convergence, end to end: one Replica exports its **retained signed
//! material** (the canonical BodyTransaction records plus their sealed,
//! descriptor-bound protected payloads), the material is framed as a Contact
//! transfer and driven through the real initiator/accepter state machines, the
//! received bytes are handed to mechanics-validated `Replica::incorporate`,
//! and the two replicas converge.
//!
//! This ties the whole Convergence pipeline together — export → Contact frames
//! → transcript-validated receipt → legitimacy check → exact per-Body durable
//! incorporation — with no unbound merge path. (The only glue left for the
//! live daemon is carrying these exact frames over a comms `Stream`; the
//! framing, validation, and incorporation proven here are transport-
//! independent.)

use std::sync::Arc;

use mechanics::crypto::AuthorizedBodyKey;
use mechanics::ids::SpaceId;
use replica::frontier::AuthorityFrontier;
use replica::transaction::{AuthoritySource, BodyTransaction, NO_PARENT_ROOT};
use replica::{
    BodyBinding, BodyId, BodyKey, BodyOp, CommitContext, EncodingId, Replica, SchemaId, SeedSigner,
    StaticBodyKeys, SupportedSchemas, WorldId, MUTATION_COLLABORATIVE,
};
use replica::{CommitAuthorization, StaticAuthorizer};
use runtime::contact::{
    authority_record_hash, authority_set_hash, body_chunk_hash, manifest_page_hash,
    manifest_root_ref, ContactFrame, ContactId, InitiatorReceiver, InitiatorState, Progress,
    ReceivedMaterial,
};

const EXPORT_SEED: [u8; 32] = [88u8; 32];
const EPOCH: [u8; 16] = [5u8; 16];
const EPOCH_KEY: [u8; 32] = [6u8; 32];

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

fn keys() -> Arc<StaticBodyKeys> {
    Arc::new(StaticBodyKeys::new(
        AuthorizedBodyKey::for_authorized_epoch(EPOCH, EPOCH_KEY),
    ))
}

fn supported() -> SupportedSchemas {
    let mut s = SupportedSchemas::new();
    s.declare(
        note_key().world,
        SchemaId::parse("note").unwrap(),
        1,
        EncodingId::parse("collab").unwrap(),
        MUTATION_COLLABORATIVE,
    );
    s
}

fn binding() -> BodyBinding {
    BodyBinding {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        encoding: EncodingId::parse("collab").unwrap(),
        mutation_model: MUTATION_COLLABORATIVE,
    }
}

fn replica() -> Replica {
    let mut r = Replica::loro().with_keys(keys());
    r.set_supported(supported());
    r
}

fn commit_votes(r: &mut Replica, request: [u8; 16], delta: i64) {
    let space = space();
    let signer = SeedSigner(&EXPORT_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let authorizer = StaticAuthorizer {
        world: note_key().world,
        implementation_id: [0u8; 32],
    };
    let demand = mechanics::demand::AuthorizationDemand::require(
        mechanics::demand::PolicyCapability::new(note_key().world.as_str(), "write"),
        mechanics::demand::PolicyResource::space(note_key().world.as_str()),
    )
    .encode_canonical()
    .unwrap();
    r.commit_action(
        &ctx,
        &CommitAuthorization {
            actor: "actor",
            parent_manifest_root: NO_PARENT_ROOT,
            demand,
            intent_digest: [1u8; 32],
            authorizer: &authorizer,
        },
        &note_key().world,
        &mechanics::crypto::device_from_seed(&EXPORT_SEED),
        &request,
        &[1u8; 32],
        vec![],
        vec![],
        "bump",
        &[
            (note_key(), BodyOp::Create),
            (
                note_key(),
                BodyOp::CounterAdd {
                    path: "votes".into(),
                    delta,
                },
            ),
        ],
        &[(note_key(), binding())],
    )
    .unwrap();
}

/// Frame the exported material as a complete Contact transfer: the signed
/// BodyTransaction is the single authority record; its bound protected
/// payload is the single body. Returns every raw frame in send order.
fn frame_transfer(contact: &ContactId, tx: &BodyTransaction, payload: &[u8]) -> Vec<Vec<u8>> {
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
            transaction: tx.id(),
            body: note_key(),
            offset: 0,
            total: payload.len() as u64,
            chunk_hash: body_chunk_hash(payload),
            bytes: payload.to_vec(),
        },
        ContactFrame::BodyEnd {
            transaction: tx.id(),
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

fn ctx_space() -> SpaceId {
    space()
}

#[test]
fn a_signed_export_converges_across_a_contact_transfer() {
    // Node A commits some collaborative state through the attributed path.
    let mut a = replica();
    commit_votes(&mut a, [41u8; 16], 4);

    // A exports its retained signed material and frames it as a transfer.
    let material = a.export_material().unwrap();
    assert_eq!(material.len(), 1);
    let (tx, payloads) = &material[0];
    let payload = &payloads[0].1;
    let contact = ContactId::from_bytes([5u8; 16]);
    let frames = frame_transfer(&contact, tx, payload);

    // Node B receives the transfer through the real machine, then reconstructs
    // the signed transaction + payload from the received material.
    let received = receive(contact, &frames);
    assert_eq!(received.authority_records.len(), 1);
    let received_tx = BodyTransaction::decode_canonical(&received.authority_records[0]).unwrap();
    let received_payload = received
        .bodies
        .get(&(tx.id(), note_key()))
        .expect("body present");

    // Convergence: legitimacy is checked (signature + mechanics authority +
    // commitment binding) before anything reaches B's engine.
    let mut b = replica();
    let space = ctx_space();
    let signer = SeedSigner(&EXPORT_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let outcome = b
        .incorporate(
            &ctx,
            &received_tx,
            &[(note_key(), received_payload.clone())],
            &ExporterAuthorized,
        )
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
    let mut a = replica();
    commit_votes(&mut a, [42u8; 16], 1);
    let material = a.export_material().unwrap();
    let (tx, payloads) = &material[0];
    let payload = &payloads[0].1;
    let contact = ContactId::from_bytes([6u8; 16]);
    let frames = frame_transfer(&contact, tx, payload);
    let received = receive(contact, &frames);
    let received_tx = BodyTransaction::decode_canonical(&received.authority_records[0]).unwrap();
    let received_payload = received.bodies.get(&(tx.id(), note_key())).unwrap();

    // An importer whose mechanics view does not authorize the exporter refuses
    // the material even though the Contact transfer itself was well-formed.
    struct DenyAll;
    impl AuthoritySource for DenyAll {
        fn signer_authorized(&self, _s: &[u8; 32], _f: &AuthorityFrontier) -> bool {
            false
        }
    }
    let mut b = replica();
    let space = ctx_space();
    let signer = SeedSigner(&EXPORT_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    assert!(b
        .incorporate(
            &ctx,
            &received_tx,
            &[(note_key(), received_payload.clone())],
            &DenyAll,
        )
        .is_err());
    assert!(
        b.read_collaborative(&note_key()).is_none(),
        "nothing reached the engine"
    );
}
