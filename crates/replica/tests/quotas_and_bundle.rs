//! C1.1 / C1.5 — the sealed validated Contact bundle and quota enforcement.
//!
//! Bundle: staged (untrusted) Contact material becomes incorporable **only**
//! through `Replica::validate_contact`, whose sealed output binds exactly the
//! chain authority → verified Manifest root → complete pages → authorized
//! transactions → descriptor-bound payloads. Authority incorporation is an
//! explicit first durable phase with its own receipt. Adversarial stagings —
//! stray payloads, omitted pages, tampered bytes, unauthorized signers —
//! reject with nothing (but the independently valid authority batch) retained.
//!
//! Quotas: Body count, Space material bytes, and the unknown-World retention
//! subquota enforce transactionally at exact-1/exact/exact+1 boundaries;
//! overflow performs no eviction, changes neither manifest nor frontier, and
//! leaves no staging.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mechanics::crypto::AuthorizedBodyKey;
use mechanics::ids::SpaceId;
use replica::frontier::AuthorityFrontier;
use replica::{
    ActionOutcome, AuthorityIncorporator, AuthorityReceipt, BodyBinding, BodyId, BodyKey, BodyOp,
    CommitContext, EncodingId, QuotaConfig, Replica, ReplicaCommitError, SchemaId, SeedSigner,
    StagedContactMaterial, StaticBodyKeys, SupportedSchemas, WorldId, MUTATION_COLLABORATIVE,
};

const WRITER_SEED: [u8; 32] = [71u8; 32];
const EPOCH: [u8; 16] = [11u8; 16];
const EPOCH_KEY: [u8; 32] = [12u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-quota-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn space() -> SpaceId {
    SpaceId::from_digest([41u8; 16])
}

fn keys() -> Arc<StaticBodyKeys> {
    Arc::new(StaticBodyKeys::new(
        AuthorizedBodyKey::for_authorized_epoch(EPOCH, EPOCH_KEY),
    ))
}

fn world() -> WorldId {
    WorldId::parse("com.example.notes").unwrap()
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
    s.declare(
        world(),
        SchemaId::parse("blob").unwrap(),
        1,
        EncodingId::parse("bytes").unwrap(),
        replica::MUTATION_ATOMIC,
    );
    s
}

fn atomic_binding() -> BodyBinding {
    BodyBinding {
        schema: SchemaId::parse("blob").unwrap(),
        schema_version: 1,
        encoding: EncodingId::parse("bytes").unwrap(),
        mutation_model: replica::MUTATION_ATOMIC,
    }
}

/// Commit an ATOMIC body — every byte of its ledger footprint is
/// deterministic (unlike a collaborative Loro export, whose peer ids and
/// timestamps vary), which is what the exact byte-boundary test needs.
fn commit_blob(
    r: &mut Replica,
    request: [u8; 16],
    key: &BodyKey,
    bytes: &[u8],
) -> Result<ActionOutcome, ReplicaCommitError> {
    let (space, signer) = ctx_parts();
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    r.commit_action(
        &ctx,
        &world(),
        &device(),
        &request,
        &[7u8; 32],
        vec![],
        vec![],
        "blob",
        &[(
            key.clone(),
            BodyOp::ReplaceAtomic {
                value: bytes.to_vec(),
            },
        )],
        &[(key.clone(), atomic_binding())],
    )
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

/// The fixture mechanics authority store: records batches, idempotent receipt.
#[derive(Default)]
struct RecordingIncorporator {
    batches: Vec<Vec<Vec<u8>>>,
}
impl AuthorityIncorporator for RecordingIncorporator {
    fn incorporate_authority(&mut self, records: &[Vec<u8>]) -> Result<AuthorityReceipt, String> {
        self.batches.push(records.to_vec());
        Ok(AuthorityReceipt {
            frontier: authority_frontier(),
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
    let mut authority_records = vec![b"mechanics-authority-record".to_vec()];
    let mut bodies = Vec::new();
    for (tx, payloads) in &material {
        authority_records.push(tx.encode());
        for (key, envelope) in payloads {
            bodies.push((tx.transaction, key.clone(), envelope.clone()));
        }
    }
    StagedContactMaterial {
        authority_records,
        manifest_root_bytes: root,
        manifest_pages: pages,
        bodies,
    }
}

#[test]
fn a_valid_staging_validates_and_incorporates_with_authority_first() {
    let mut a = keyed_replica();
    commit_note(&mut a, [1u8; 16], &body(1), "hello").unwrap();
    let staged = stage(&a);

    let mut b = keyed_replica();
    let (space, signer) = ctx_parts();
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let mut incorporator = RecordingIncorporator::default();
    let bundle = b
        .validate_contact(&staged, &WriterAuthorized, &mut incorporator)
        .unwrap();
    // The authority batch (the non-transaction record) was committed FIRST,
    // as its own phase, and the receipt rode into the bundle.
    assert_eq!(incorporator.batches.len(), 1);
    assert_eq!(
        incorporator.batches[0],
        vec![b"mechanics-authority-record".to_vec()]
    );
    assert_eq!(bundle.authority_receipt().frontier, authority_frontier());
    assert_eq!(bundle.transaction_count(), 1);

    let outcome = b
        .incorporate_bundle(&ctx, bundle, &WriterAuthorized)
        .unwrap();
    assert_eq!(outcome.accepted, 1);
    assert_eq!(
        b.read_collaborative(&body(1)).unwrap().registers["text"],
        b"hello".to_vec()
    );
}

#[test]
fn adversarial_stagings_are_rejected_whole() {
    let mut a = keyed_replica();
    commit_note(&mut a, [2u8; 16], &body(2), "target").unwrap();
    let staged = stage(&a);
    let b = keyed_replica();
    let mut incorporator = RecordingIncorporator::default();

    // A stray payload naming a Body outside the verified graph.
    let mut stray = staged.clone();
    let tx_id = stray.bodies[0].0;
    stray
        .bodies
        .push((tx_id, body(9), stray.bodies[0].2.clone()));
    assert!(matches!(
        b.validate_contact(&stray, &WriterAuthorized, &mut incorporator),
        Err(ReplicaCommitError::Illegitimate(_))
    ));

    // An omitted manifest page.
    let mut omitted = staged.clone();
    omitted.manifest_pages.clear();
    assert!(matches!(
        b.validate_contact(&omitted, &WriterAuthorized, &mut incorporator),
        Err(ReplicaCommitError::Illegitimate(_))
    ));

    // A tampered payload byte.
    let mut tampered = staged.clone();
    let last = tampered.bodies[0].2.len() - 1;
    tampered.bodies[0].2[last] ^= 0xff;
    assert!(matches!(
        b.validate_contact(&tampered, &WriterAuthorized, &mut incorporator),
        Err(ReplicaCommitError::Illegitimate(_))
    ));

    // An authority view that refuses the signer rejects root and transactions.
    struct DenyAll;
    impl replica::AuthoritySource for DenyAll {
        fn signer_authorized(&self, _s: &[u8; 32], _f: &AuthorityFrontier) -> bool {
            false
        }
    }
    assert!(matches!(
        b.validate_contact(&staged, &DenyAll, &mut incorporator),
        Err(ReplicaCommitError::Illegitimate(_))
    ));

    // Nothing reached the engine through any of it.
    assert!(b.read_collaborative(&body(2)).is_none());
    assert!(b.body_keys().is_empty());
}

#[test]
fn body_count_quota_has_exact_boundaries() {
    let dir = temp_store("count");
    let mut r = Replica::open_journaled(&dir, keys()).unwrap();
    r.set_supported(supported());
    r.set_quota(QuotaConfig {
        max_space_bodies: 2,
        ..QuotaConfig::default()
    });
    // exact-1 and exact both commit.
    commit_note(&mut r, [3u8; 16], &body(3), "one").unwrap();
    commit_note(&mut r, [4u8; 16], &body(4), "two").unwrap();
    let frontier = r.frontier();
    // exact+1 refuses cleanly BEFORE anything applies…
    assert_eq!(
        commit_note(&mut r, [5u8; 16], &body(5), "three").unwrap_err(),
        ReplicaCommitError::QuotaExceeded
    );
    assert_eq!(r.frontier(), frontier, "no frontier change");
    // …and the handle still works: updating an EXISTING Body is fine.
    commit_note(&mut r, [6u8; 16], &body(4), "two-again").unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn space_byte_quota_has_exact_boundaries() {
    // Measure the exact ledger of one deterministic commit…
    let dir = temp_store("bytes-measure");
    let mut probe = Replica::open_journaled(&dir, keys()).unwrap();
    probe.set_supported(supported());
    commit_blob(&mut probe, [7u8; 16], &body(6), b"measured").unwrap();
    let (usage, _) = probe.usage();
    drop(probe);
    let _ = std::fs::remove_dir_all(&dir);

    // …exact: a fresh store configured to exactly that usage accepts it.
    let dir = temp_store("bytes-exact");
    let mut r = Replica::open_journaled(&dir, keys()).unwrap();
    r.set_supported(supported());
    r.set_quota(QuotaConfig {
        max_space_bytes: usage,
        ..QuotaConfig::default()
    });
    commit_blob(&mut r, [7u8; 16], &body(6), b"measured").unwrap();
    assert_eq!(r.usage().0, usage);
    drop(r);
    let _ = std::fs::remove_dir_all(&dir);

    // exact-1: one byte less refuses (fail-stop after apply; reopen shows the
    // old — empty — durable state).
    let dir = temp_store("bytes-under");
    let mut r = Replica::open_journaled(&dir, keys()).unwrap();
    r.set_supported(supported());
    r.set_quota(QuotaConfig {
        max_space_bytes: usage - 1,
        ..QuotaConfig::default()
    });
    assert_eq!(
        commit_blob(&mut r, [7u8; 16], &body(6), b"measured").unwrap_err(),
        ReplicaCommitError::QuotaExceeded
    );
    drop(r);
    let r = Replica::open_journaled(&dir, keys()).unwrap();
    assert!(r.body_keys().is_empty(), "nothing durable");
    drop(r);
    let _ = std::fs::remove_dir_all(&dir);

    // exact+1: one byte more accepts.
    let dir = temp_store("bytes-over");
    let mut r = Replica::open_journaled(&dir, keys()).unwrap();
    r.set_supported(supported());
    r.set_quota(QuotaConfig {
        max_space_bytes: usage + 1,
        ..QuotaConfig::default()
    });
    commit_blob(&mut r, [7u8; 16], &body(6), b"measured").unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_world_retention_subquota_evicts_nothing_and_stages_nothing() {
    // A commits two bodies; B supports nothing and may retain only ONE.
    let mut a = keyed_replica();
    commit_note(&mut a, [8u8; 16], &body(7), "first").unwrap();
    let first = stage(&a);
    commit_note(&mut a, [9u8; 16], &body(8), "second").unwrap();

    let dir = temp_store("opaque");
    let mut b = Replica::open_journaled(&dir, keys()).unwrap();
    // no supported schemas: everything is opaque
    b.set_quota(QuotaConfig {
        max_unknown_world_bodies: 1,
        ..QuotaConfig::default()
    });
    let (space, signer) = ctx_parts();
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    // First body retains (exact).
    let (tx, payloads) = &a
        .export_material()
        .unwrap()
        .into_iter()
        .find(|(_, p)| p.iter().any(|(k, _)| k == &body(7)))
        .unwrap();
    let first_payload: Vec<(BodyKey, Vec<u8>)> = payloads
        .iter()
        .filter(|(k, _)| k == &body(7))
        .cloned()
        .collect();
    let outcome = b
        .incorporate(&ctx, tx, &first_payload, &WriterAuthorized)
        .unwrap();
    assert_eq!(outcome.unsupported_retained, 1);
    let frontier = b.frontier();

    // The second opaque body is exact+1: refused, no eviction, no staging,
    // no frontier change.
    let (tx2, payloads2) = &a
        .export_material()
        .unwrap()
        .into_iter()
        .find(|(_, p)| p.iter().any(|(k, _)| k == &body(8)))
        .unwrap();
    let second_payload: Vec<(BodyKey, Vec<u8>)> = payloads2
        .iter()
        .filter(|(k, _)| k == &body(8))
        .cloned()
        .collect();
    assert_eq!(
        b.incorporate(&ctx, tx2, &second_payload, &WriterAuthorized)
            .unwrap_err(),
        ReplicaCommitError::OpaqueQuotaExceeded
    );
    assert_eq!(b.frontier(), frontier);
    assert!(
        b.is_opaque(&body(7)),
        "the retained body survives untouched"
    );
    assert!(!b.is_opaque(&body(8)));
    assert_eq!(b.opaque_usage(&world()).1, 1);
    drop(b);
    // And nothing about the refused material is in the durable store.
    let b = Replica::open_journaled(&dir, keys()).unwrap();
    assert_eq!(b.opaque_usage(&world()).1, 1);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = first; // first staging kept alive for clarity
}

#[test]
fn operator_configuration_lowers_but_never_raises_protocol_maxima() {
    let q = QuotaConfig {
        max_body_bytes: u64::MAX,
        max_space_bytes: u64::MAX,
        max_space_bodies: u64::MAX,
        max_unknown_world_bytes: u64::MAX,
        max_unknown_world_bodies: u64::MAX,
    }
    .clamped();
    assert_eq!(
        q,
        QuotaConfig::default(),
        "raising clamps to protocol maxima"
    );
    let lowered = QuotaConfig {
        max_space_bodies: 5,
        ..QuotaConfig::default()
    }
    .clamped();
    assert_eq!(lowered.max_space_bodies, 5, "lowering is allowed");
}

#[test]
fn configured_limits_persist_so_restart_cannot_raise_capacity() {
    let dir = temp_store("persist");
    let mut r = Replica::open_journaled(&dir, keys()).unwrap();
    r.set_supported(supported());
    r.set_quota(QuotaConfig {
        max_space_bodies: 1,
        ..QuotaConfig::default()
    });
    commit_note(&mut r, [10u8; 16], &body(9), "only").unwrap();
    drop(r);

    // A reopen WITHOUT reconfiguring still enforces the persisted limit.
    let mut r = Replica::open_journaled(&dir, keys()).unwrap();
    r.set_supported(supported());
    assert_eq!(r.quota().max_space_bodies, 1);
    assert_eq!(
        commit_note(&mut r, [11u8; 16], &body(10), "more").unwrap_err(),
        ReplicaCommitError::QuotaExceeded
    );
    let _ = std::fs::remove_dir_all(&dir);
}
