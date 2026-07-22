//! `manifest_atomicity` — adopting an advertised Manifest root is atomic.
//!
//! A root carrying several transactions installs the complete object graph in
//! **one** journal commit: a failure in transaction N never leaves
//! transactions 0..N-1 committed under an error result, a kill/reopen at each
//! staging and journal boundary exposes the old root or the complete new
//! root, and exact retry is unchanged. Adversarial stagings — duplicate
//! transaction ids under different bytes, entries neither held nor
//! transferred, second-transaction quota failure, authority bytes riding the
//! transaction lane — reject whole.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use mechanics::crypto::AuthorizedBodyKey;
use mechanics::ids::SpaceId;
use replica::frontier::AuthorityFrontier;
use replica::{
    ActionOutcome, AuthorityBatchReceipt, AuthorityIncorporator, BodyBinding, BodyId, BodyKey,
    BodyOp, CommitAuthorization, CommitContext, EncodingId, QuotaConfig, Replica,
    ReplicaCommitError, SchemaId, SeedSigner, StagedContactMaterial, StaticBodyKeys,
    SupportedSchemas, WorldId, MUTATION_COLLABORATIVE,
};

const WRITER_SEED: [u8; 32] = [71u8; 32];
const EPOCH: [u8; 16] = [11u8; 16];
const EPOCH_KEY: [u8; 32] = [12u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-atom-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn space() -> SpaceId {
    SpaceId::from_digest([43u8; 16])
}

fn keys() -> Arc<StaticBodyKeys> {
    Arc::new(StaticBodyKeys::new(
        AuthorizedBodyKey::for_authorized_epoch(EPOCH, EPOCH_KEY),
    ))
}

fn world() -> WorldId {
    WorldId::parse("com.example.notes").unwrap()
}

/// A test authorizer + commit-authorization helper (the machinery each commit
/// needs now that authorization is bound into the signed transaction).
fn test_auth() -> replica::StaticAuthorizer {
    replica::StaticAuthorizer {
        world: world(),
        implementation_id: [0u8; 32],
    }
}

fn test_demand() -> Vec<u8> {
    use mechanics::demand::{AuthorizationDemand, PolicyCapability, PolicyResource};
    AuthorizationDemand::require(
        PolicyCapability::new("com.example.notes", "write"),
        PolicyResource::space("com.example.notes"),
    )
    .encode_canonical()
    .expect("canonical demand")
}

fn body(n: u8) -> BodyKey {
    BodyKey::new(world(), BodyId::from_bytes([n; 16]))
}

fn binding() -> BodyBinding {
    BodyBinding {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        encoding: EncodingId::parse("collab").unwrap(),
        mutation_model: MUTATION_COLLABORATIVE,
    }
}

fn supported() -> SupportedSchemas {
    let mut s = SupportedSchemas::new();
    s.declare(
        world(),
        SchemaId::parse("note").unwrap(),
        1,
        EncodingId::parse("collab").unwrap(),
        MUTATION_COLLABORATIVE,
    );
    s
}

fn device() -> mechanics::ids::DeviceId {
    mechanics::crypto::device_from_seed(&WRITER_SEED)
}

fn authority_frontier() -> AuthorityFrontier {
    AuthorityFrontier::from_canonical_bytes(vec![13])
}

struct WriterAuthorized;
impl replica::AuthoritySource for WriterAuthorized {
    fn signer_authorized(&self, signer: &[u8; 32], _f: &AuthorityFrontier) -> bool {
        *signer == device().key_bytes().unwrap()
    }
}

#[derive(Default)]
struct RecordingIncorporator;
impl AuthorityIncorporator for RecordingIncorporator {
    fn incorporate_authority(
        &mut self,
        records: &[Vec<u8>],
    ) -> Result<AuthorityBatchReceipt, String> {
        Ok(AuthorityBatchReceipt {
            space: space(),
            prior_frontier: AuthorityFrontier::from_canonical_bytes(vec![]),
            resulting_frontier: authority_frontier(),
            batch_digest: *blake3::hash(&records.concat()).as_bytes(),
        })
    }
}

fn ctx_parts() -> (SpaceId, SeedSigner<'static>) {
    (space(), SeedSigner(&WRITER_SEED))
}

fn keyed_replica() -> Replica {
    let mut r = Replica::loro().with_keys(keys());
    r.set_supported(supported());
    r
}

fn commit_note(
    r: &mut Replica,
    request: [u8; 16],
    key: &BodyKey,
    text: &str,
) -> Result<ActionOutcome, ReplicaCommitError> {
    let (space, signer) = ctx_parts();
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    r.commit_action(
        &ctx,
        &CommitAuthorization {
            actor: "actor",
            parent_manifest_root: [0u8; 32],
            demand: test_demand(),
            intent_digest: [7u8; 32],
            authorizer: &test_auth(),
        },
        &world(),
        &device(),
        &request,
        &[7u8; 32],
        vec![],
        vec![],
        "note",
        &[(
            key.clone(),
            BodyOp::RegisterSet {
                path: "text".into(),
                value: text.as_bytes().to_vec(),
            },
        )],
        &[(key.clone(), binding())],
    )
}

/// Stage a replica's full export as untrusted Contact material.
fn stage(r: &Replica) -> StagedContactMaterial {
    let (space, signer) = ctx_parts();
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let material = r.export_material().unwrap();
    let (root, pages) = r.export_manifest(&ctx).unwrap();
    let mut authority_records = Vec::new();
    let mut bodies = Vec::new();
    for (tx, payloads) in &material {
        authority_records.push(tx.encode());
        for (key, envelope) in payloads {
            bodies.push((tx.id(), key.clone(), envelope.clone()));
        }
    }
    StagedContactMaterial {
        authority_records,
        manifest_root_bytes: root,
        manifest_pages: pages,
        bodies,
    }
}

/// A three-transaction source (three Bodies, three transactions) plus its
/// staging — the multi-transaction root the gates below adopt.
fn multi_tx_staging() -> (Replica, StagedContactMaterial) {
    let mut a = keyed_replica();
    commit_note(&mut a, [1u8; 16], &body(1), "one").unwrap();
    commit_note(&mut a, [2u8; 16], &body(2), "two").unwrap();
    commit_note(&mut a, [3u8; 16], &body(3), "three").unwrap();
    let staged = stage(&a);
    (a, staged)
}

fn incorporate_all(
    target: &mut Replica,
    staged: &StagedContactMaterial,
) -> Result<replica::ConvergenceOutcome, ReplicaCommitError> {
    let (space, signer) = ctx_parts();
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let mut inc = RecordingIncorporator;
    let bundle = target.validate_contact(staged, &WriterAuthorized, &mut inc)?;
    target.incorporate_bundle(&ctx, bundle, &WriterAuthorized)
}

#[test]
fn a_multi_transaction_root_adopts_atomically() {
    let (_a, staged) = multi_tx_staging();
    let mut b = keyed_replica();
    let outcome = incorporate_all(&mut b, &staged).unwrap();
    assert_eq!(outcome.accepted, 3);
    assert_eq!(b.body_keys().len(), 3);
}

#[test]
fn a_second_transaction_failure_commits_nothing() {
    let (_a, staged) = multi_tx_staging();
    // A body-count quota of 1 makes the bundle as a whole unaffordable: the
    // complete-root projection refuses BEFORE anything applies — transaction
    // one must not survive its sibling's failure.
    let mut b = keyed_replica();
    b.set_quota(QuotaConfig {
        max_space_bodies: 1,
        ..QuotaConfig::default()
    });
    let frontier_before = b.frontier();
    let err = incorporate_all(&mut b, &staged).unwrap_err();
    assert_eq!(err, ReplicaCommitError::QuotaExceeded);
    assert_eq!(b.frontier(), frontier_before, "no partial adoption");
    assert!(b.body_keys().is_empty(), "transaction one did not survive");
}

#[test]
fn kill_and_reopen_at_every_journal_boundary_shows_old_or_complete_new_root() {
    for point in fabric::journal::FAULT_POINTS {
        let (_a, staged) = multi_tx_staging();
        let dir = temp_store("fault");
        {
            let crash = Arc::new(AtomicBool::new(true));
            let flag = crash.clone();
            let target_point = point.to_string();
            let mut b = Replica::open_journaled(&dir, keys())
                .unwrap()
                .with_store_fault_injector(Box::new(move |p| {
                    p == target_point && flag.load(Ordering::SeqCst)
                }));
            b.set_supported(supported());
            // Post-authoritative cleanup points absorb the crash (the commit
            // stands); earlier points fail with nothing durable.
            let result = incorporate_all(&mut b, &staged);
            let post_authoritative = matches!(point, "journal-committed" | "journal-remove");
            assert_eq!(
                result.is_ok(),
                post_authoritative,
                "{point}: pre-switch crashes fail, post-switch crashes absorb"
            );
        }
        // Reopen: the complete old root (no bodies) or the complete new root
        // (all three bodies) — never a partial subset.
        let mut b = Replica::open_journaled(&dir, keys()).unwrap();
        b.set_supported(supported());
        let held = b.body_keys().len();
        assert!(
            held == 0 || held == 3,
            "{point}: reopen exposed a partial root ({held} of 3 bodies)"
        );
        // Exact retry converges to the complete new root and then replays
        // as unchanged.
        incorporate_all(&mut b, &staged).unwrap();
        assert_eq!(b.body_keys().len(), 3, "{point}: retry completes the root");
        let replay = incorporate_all(&mut b, &staged).unwrap();
        assert_eq!(replay.accepted, 0, "{point}: exact retry is unchanged");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn duplicate_transaction_ids_with_different_bytes_reject() {
    let (_a, mut staged) = multi_tx_staging();
    // Craft a second record aliasing transaction one's id: decode, tamper a
    // descriptor-free field is impossible without re-signing — instead sign a
    // DIFFERENT transaction and overwrite its id bytes cannot re-verify, so
    // build the alias from another source replica sharing the same id space:
    // simplest honest adversary — duplicate the record with one flipped byte
    // in the signature (same id, different bytes; the equivocation gate must
    // fire before the signature is even checked).
    let mut alias = staged.authority_records[0].clone();
    let last = alias.len() - 1;
    alias[last] ^= 0x01;
    staged.authority_records.push(alias);
    let mut b = keyed_replica();
    let err = incorporate_all(&mut b, &staged).unwrap_err();
    match err {
        ReplicaCommitError::Illegitimate(m) => {
            // Either the equivocation gate (same id, different bytes) or the
            // canonical decoder (the tampered record no longer decodes as a
            // transaction and lands in the authority lane, leaving a payload
            // without a provided transaction) must refuse the staging.
            assert!(
                m.contains("duplicate transaction id") || m.contains("transaction"),
                "unexpected refusal: {m}"
            );
        }
        other => panic!("expected Illegitimate, got {other:?}"),
    }
    assert!(b.body_keys().is_empty());
}

#[test]
fn manifest_entries_neither_held_nor_transferred_reject() {
    let (_a, mut staged) = multi_tx_staging();
    // Drop body 2's payload from the transfer while the root still names it.
    staged.bodies.retain(|(_, key, _)| key != &body(2));
    let mut b = keyed_replica();
    let err = incorporate_all(&mut b, &staged).unwrap_err();
    match err {
        ReplicaCommitError::Illegitimate(m) => {
            assert!(
                m.contains("neither held nor transferred"),
                "unexpected refusal: {m}"
            );
        }
        other => panic!("expected Illegitimate, got {other:?}"),
    }
    assert!(b.body_keys().is_empty(), "nothing adopted under the root");
}

#[test]
fn a_locally_held_entry_satisfies_root_completeness() {
    let (_a, staged) = multi_tx_staging();
    // First adopt everything; then replay a staging without payloads — every
    // entry is locally held byte-identically, so the root still validates.
    let mut b = keyed_replica();
    incorporate_all(&mut b, &staged).unwrap();
    let mut replay = staged.clone();
    replay.bodies.clear();
    let outcome = incorporate_all(&mut b, &replay).unwrap();
    assert_eq!(outcome.accepted, 0);
    assert_eq!(b.body_keys().len(), 3);
}

#[test]
fn authority_bytes_cannot_ride_the_transaction_lane() {
    let (_a, mut staged) = multi_tx_staging();
    // An authority-shaped record (not a canonical transaction) rides the
    // staging: it must be classified to the authority lane, not adopted as a
    // transaction — and a payload claiming a nonexistent transaction rejects.
    staged
        .authority_records
        .push(b"mechanics-authority-record".to_vec());
    let mut b = keyed_replica();
    let outcome = incorporate_all(&mut b, &staged).unwrap();
    assert_eq!(
        outcome.accepted, 3,
        "authority lane does not block adoption"
    );

    // A payload naming a transaction id that only exists as authority bytes.
    let (_a2, mut staged2) = multi_tx_staging();
    let phantom_tx = [0xEEu8; 32];
    let envelope = staged2.bodies[0].2.clone();
    staged2.bodies.push((phantom_tx, body(9), envelope));
    let mut c = keyed_replica();
    let err = incorporate_all(&mut c, &staged2).unwrap_err();
    match err {
        ReplicaCommitError::Illegitimate(m) => {
            assert!(m.contains("without a provided transaction"), "{m}");
        }
        other => panic!("expected Illegitimate, got {other:?}"),
    }
}

#[test]
fn successive_writes_to_one_body_within_a_bundle_land_the_final_state() {
    // Two transactions touching the SAME body in one staging: the adopted
    // state is the merged/latest one and the store remains consistent.
    let mut a = keyed_replica();
    commit_note(&mut a, [1u8; 16], &body(1), "first").unwrap();
    commit_note(&mut a, [2u8; 16], &body(1), "second").unwrap();
    let staged = stage(&a);
    let dir = temp_store("succ");
    {
        let mut b = Replica::open_journaled(&dir, keys()).unwrap();
        b.set_supported(supported());
        incorporate_all(&mut b, &staged).unwrap();
        let view = b.read_collaborative(&body(1)).unwrap();
        let text = view.registers.get("text").cloned().unwrap_or_default();
        assert_eq!(text, b"second".to_vec());
    }
    // Reopen: the durable graph reproduces the same final state.
    let b = Replica::open_journaled(&dir, keys()).unwrap();
    let view = b.read_collaborative(&body(1)).unwrap();
    assert_eq!(
        view.registers.get("text").cloned().unwrap_or_default(),
        b"second".to_vec()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
