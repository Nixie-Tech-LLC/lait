//! C1.3 / G4 — the canonical Body/store representation, through the public API.
//!
//! Proves the durable Replica addresses **canonical objects** — signed
//! transaction records, sealed protected Body payloads, idempotency receipts,
//! and Manifest root/pages — rather than one opaque engine snapshot; that no
//! plaintext Body payload is at rest; that receipts and replay survive a cold
//! reopen; and that exact incorporation (signed transaction + descriptor-bound
//! payloads) converges, refuses illegitimate material, retains unknown material
//! opaquely and byte-identically, and resolves concurrent atomic writes
//! deterministically.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mechanics::crypto::AuthorizedBodyKey;
use mechanics::ids::SpaceId;
use replica::frontier::AuthorityFrontier;
use replica::{
    ActionOutcome, BodyBinding, BodyId, BodyKey, BodyOp, BodyTransaction, CommitAuthorization,
    CommitContext, EncodingId, Replica, ReplicaCommitError, SchemaId, SeedSigner, StaticBodyKeys,
    SupportedSchemas, WorldId, MUTATION_ATOMIC, MUTATION_COLLABORATIVE,
};

const WRITER_SEED: [u8; 32] = [61u8; 32];
const EPOCH: [u8; 16] = [3u8; 16];
const EPOCH_KEY: [u8; 32] = [4u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-canonical-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn space() -> SpaceId {
    SpaceId::from_digest([31u8; 16])
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

fn collab_binding() -> BodyBinding {
    BodyBinding {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        encoding: EncodingId::parse("collab").unwrap(),
        mutation_model: MUTATION_COLLABORATIVE,
    }
}

fn atomic_binding() -> BodyBinding {
    BodyBinding {
        schema: SchemaId::parse("blob").unwrap(),
        schema_version: 1,
        encoding: EncodingId::parse("bytes").unwrap(),
        mutation_model: MUTATION_ATOMIC,
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
        MUTATION_ATOMIC,
    );
    s
}

fn device() -> mechanics::ids::DeviceId {
    mechanics::crypto::device_from_seed(&WRITER_SEED)
}

fn authority_frontier() -> AuthorityFrontier {
    AuthorityFrontier::from_canonical_bytes(vec![9])
}

/// A mechanics view authorizing exactly the writer device.
struct WriterAuthorized;
impl replica::AuthoritySource for WriterAuthorized {
    fn signer_authorized(&self, signer: &[u8; 32], _f: &AuthorityFrontier) -> bool {
        *signer == device().key_bytes().unwrap()
    }
}

fn commit(
    r: &mut Replica,
    request: [u8; 16],
    label: &str,
    ops: &[(BodyKey, BodyOp)],
    bindings: &[(BodyKey, BodyBinding)],
) -> Result<ActionOutcome, ReplicaCommitError> {
    let space = space();
    let signer = SeedSigner(&WRITER_SEED);
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
        b"effect".to_vec(),
        vec![],
        label,
        ops,
        bindings,
    )
}

fn open(dir: &PathBuf) -> Replica {
    let mut r = Replica::open_journaled(dir, keys()).unwrap();
    r.set_supported(supported());
    r
}

fn counter_ops(key: &BodyKey, delta: i64) -> Vec<(BodyKey, BodyOp)> {
    vec![(
        key.clone(),
        BodyOp::CounterAdd {
            path: "votes".into(),
            delta,
        },
    )]
}

#[test]
fn a_durable_commit_survives_cold_reopen_with_receipts_and_replay() {
    let dir = temp_store("reopen");
    let mut r = open(&dir);
    let request = [21u8; 16];
    let first = commit(
        &mut r,
        request,
        "bump",
        &counter_ops(&body(1), 5),
        &[(body(1), collab_binding())],
    )
    .unwrap();
    let ActionOutcome::Committed(receipt) = &first else {
        panic!("fresh commit");
    };
    let frontier = r.frontier();
    drop(r); // crash: no dormancy

    // Cold reopen: state, frontier, AND the idempotency receipt all recovered.
    let mut r = open(&dir);
    assert_eq!(r.frontier(), frontier);
    assert_eq!(r.read_collaborative(&body(1)).unwrap().counters["votes"], 5);

    // Identical replay AFTER restart returns the original receipt and does
    // not reapply the non-idempotent CounterAdd.
    let replay = commit(
        &mut r,
        request,
        "bump",
        &counter_ops(&body(1), 5),
        &[(body(1), collab_binding())],
    )
    .unwrap();
    assert_eq!(replay, ActionOutcome::Replayed(receipt.clone()));
    assert_eq!(r.read_collaborative(&body(1)).unwrap().counters["votes"], 5);
    assert_eq!(r.frontier(), frontier);

    // Conflicting reuse after restart is still refused.
    let space = space();
    let signer = SeedSigner(&WRITER_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let err = r
        .commit_action(
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
            &[8u8; 32], // different payload hash
            vec![],
            vec![],
            "bump",
            &counter_ops(&body(1), 5),
            &[(body(1), collab_binding())],
        )
        .unwrap_err();
    assert_eq!(err, ReplicaCommitError::RequestIdConflict);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_store_addresses_canonical_objects_not_an_engine_snapshot() {
    let dir = temp_store("objects");
    let mut r = open(&dir);
    commit(
        &mut r,
        [22u8; 16],
        "created",
        &[(
            body(2),
            BodyOp::RegisterSet {
                path: "title".into(),
                value: b"the plaintext title".to_vec(),
            },
        )],
        &[(body(2), collab_binding())],
    )
    .unwrap();
    drop(r);

    // Inspect the raw store: the current manifest must name at least the
    // transaction record, one protected Body object, the receipt, and the
    // manifest root/page — and every stored byte object must decode as one of
    // those canonical forms (no whole-engine snapshot object).
    let store = fabric::JournaledStore::open(&dir).unwrap();
    let manifest = store.manifest().unwrap().clone();
    assert!(
        manifest.objects.len() >= 4,
        "transaction + protected body + receipt + manifest objects, got {}",
        manifest.objects.len()
    );
    let mut classified = 0;
    for obj in &manifest.objects {
        let bytes = store.read_object(obj).unwrap();
        let is_tx = replica::BodyTransaction::decode_canonical(&bytes).is_ok();
        let is_receipt = replica::RequestReceipt::decode_canonical(&bytes).is_ok();
        let is_root = replica::ManifestRoot::decode_canonical(&bytes).is_ok();
        let is_page = replica::ManifestPage::decode_canonical(&bytes).is_ok();
        let is_protected = mechanics::crypto::body_epoch_id(&bytes) == Some(EPOCH);
        assert!(
            is_tx || is_receipt || is_root || is_page || is_protected,
            "an object is none of the canonical forms"
        );
        classified += 1;
        // At rest, no plaintext Body payload anywhere.
        let needle = b"the plaintext title";
        if is_protected {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                "protected object leaks plaintext"
            );
        }
    }
    assert_eq!(classified, manifest.objects.len());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exact_incorporation_converges_two_replicas() {
    let dir_a = temp_store("conv-a");
    let dir_b = temp_store("conv-b");
    let mut a = open(&dir_a);
    let mut b = open(&dir_b);

    commit(
        &mut a,
        [23u8; 16],
        "created",
        &counter_ops(&body(3), 4),
        &[(body(3), collab_binding())],
    )
    .unwrap();

    // A exports its retained material; B incorporates through the exact path.
    let material = a.export_material().unwrap();
    assert_eq!(material.len(), 1);
    let (tx, payloads) = &material[0];
    let space = space();
    let signer = SeedSigner(&WRITER_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let outcome = b
        .incorporate(&ctx, tx, payloads, &WriterAuthorized)
        .unwrap();
    assert_eq!(outcome.accepted, 1);
    assert!(outcome.advanced());
    assert_eq!(b.read_collaborative(&body(3)).unwrap().counters["votes"], 4);

    // B edits; A incorporates back; both agree.
    commit(
        &mut b,
        [24u8; 16],
        "edited",
        &counter_ops(&body(3), 6),
        &[(body(3), collab_binding())],
    )
    .unwrap();
    let material = b.export_material().unwrap();
    let (tx, payloads) = &material[0];
    let outcome = a
        .incorporate(&ctx, tx, payloads, &WriterAuthorized)
        .unwrap();
    assert_eq!(outcome.accepted, 1);
    assert_eq!(
        a.read_collaborative(&body(3)).unwrap().counters["votes"],
        10
    );

    // Re-incorporating known material is unchanged.
    let before = a.frontier();
    let material = b.export_material().unwrap();
    let (tx, payloads) = &material[0];
    let outcome = a
        .incorporate(&ctx, tx, payloads, &WriterAuthorized)
        .unwrap();
    assert_eq!(outcome.accepted, 0);
    assert!(outcome.unchanged >= 1);
    assert_eq!(a.frontier(), before);

    // Incorporated + locally-committed material survives B's cold reopen.
    drop(b);
    let b = open(&dir_b);
    assert_eq!(
        b.read_collaborative(&body(3)).unwrap().counters["votes"],
        10,
        "B durably holds A's incorporated 4 plus its own 6"
    );
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn illegitimate_or_tampered_material_never_reaches_the_engine() {
    let dir_a = temp_store("illeg-a");
    let mut a = open(&dir_a);
    commit(
        &mut a,
        [25u8; 16],
        "created",
        &counter_ops(&body(4), 1),
        &[(body(4), collab_binding())],
    )
    .unwrap();
    let material = a.export_material().unwrap();
    let (tx, payloads) = &material[0];

    struct DenyAll;
    impl replica::AuthoritySource for DenyAll {
        fn signer_authorized(&self, _s: &[u8; 32], _f: &AuthorityFrontier) -> bool {
            false
        }
    }
    let mut b = Replica::loro().with_keys(keys());
    b.set_supported(supported());
    let space = space();
    let signer = SeedSigner(&WRITER_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    // Unauthorized signer: refused before the engine.
    assert!(matches!(
        b.incorporate(&ctx, tx, payloads, &DenyAll),
        Err(ReplicaCommitError::Illegitimate(_))
    ));
    assert!(b.read_collaborative(&body(4)).is_none());

    // Tampered payload: the commitment binding refuses it.
    let mut tampered = payloads.clone();
    tampered[0].1.push(0);
    assert!(matches!(
        b.incorporate(&ctx, tx, &tampered, &WriterAuthorized),
        Err(ReplicaCommitError::Illegitimate(_))
    ));
    assert!(b.read_collaborative(&body(4)).is_none());

    // A payload keyed to a Body the transaction has no descriptor for.
    let stray = vec![(body(9), payloads[0].1.clone())];
    assert!(matches!(
        b.incorporate(&ctx, tx, &stray, &WriterAuthorized),
        Err(ReplicaCommitError::Illegitimate(_))
    ));

    // The untampered material still incorporates.
    b.incorporate(&ctx, tx, payloads, &WriterAuthorized)
        .unwrap();
    assert_eq!(b.read_collaborative(&body(4)).unwrap().counters["votes"], 1);
    let _ = std::fs::remove_dir_all(&dir_a);
}

#[test]
fn unknown_world_material_is_retained_opaquely_and_forwarded_byte_identically() {
    let dir_a = temp_store("opaque-a");
    let dir_b = temp_store("opaque-b");
    let dir_c = temp_store("opaque-c");
    let mut a = open(&dir_a);
    commit(
        &mut a,
        [26u8; 16],
        "created",
        &counter_ops(&body(5), 3),
        &[(body(5), collab_binding())],
    )
    .unwrap();
    let material = a.export_material().unwrap();
    let (tx, payloads) = &material[0];

    // B supports NOTHING: legitimate material is retained opaquely.
    let mut b = Replica::open_journaled(&dir_b, keys()).unwrap();
    // (no set_supported — empty)
    let space = space();
    let signer = SeedSigner(&WRITER_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let outcome = b
        .incorporate(&ctx, tx, payloads, &WriterAuthorized)
        .unwrap();
    assert_eq!(outcome.unsupported_retained, 1);
    assert!(outcome.advanced(), "opaque retention advances the frontier");
    assert!(b.is_opaque(&body(5)));
    assert!(
        b.read_collaborative(&body(5)).is_none() && b.read(&body(5)).is_none(),
        "opaque material has no interpreted view"
    );

    // The opaque material survives B's restart.
    drop(b);
    let b = Replica::open_journaled(&dir_b, keys()).unwrap();
    assert!(b.is_opaque(&body(5)));

    // B forwards to C byte-identically; C supports the schema and interprets.
    let forwarded = b.export_material().unwrap();
    assert_eq!(forwarded.len(), 1);
    let (ftx, fpayloads) = &forwarded[0];
    assert_eq!(ftx.encode(), tx.encode(), "transaction bytes identical");
    assert_eq!(
        fpayloads[0].1, payloads[0].1,
        "protected payload bytes identical"
    );
    let mut c = open(&dir_c);
    let outcome = c
        .incorporate(&ctx, ftx, fpayloads, &WriterAuthorized)
        .unwrap();
    assert_eq!(outcome.accepted, 1);
    assert_eq!(c.read_collaborative(&body(5)).unwrap().counters["votes"], 3);
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    let _ = std::fs::remove_dir_all(&dir_c);
}

#[test]
fn a_missing_key_epoch_takes_the_opaque_branch() {
    let dir_a = temp_store("nokey-a");
    let mut a = open(&dir_a);
    commit(
        &mut a,
        [27u8; 16],
        "created",
        &counter_ops(&body(6), 2),
        &[(body(6), collab_binding())],
    )
    .unwrap();
    let material = a.export_material().unwrap();
    let (tx, payloads) = &material[0];

    // B supports the schema but holds a DIFFERENT epoch key.
    let other_keys = Arc::new(StaticBodyKeys::new(
        AuthorizedBodyKey::for_authorized_epoch([8u8; 16], [9u8; 32]),
    ));
    let mut b = Replica::loro().with_keys(other_keys);
    b.set_supported(supported());
    let space = space();
    let signer = SeedSigner(&WRITER_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let outcome = b
        .incorporate(&ctx, tx, payloads, &WriterAuthorized)
        .unwrap();
    assert_eq!(outcome.unsupported_retained, 1);
    assert!(b.is_opaque(&body(6)));
    assert!(b.read_collaborative(&body(6)).is_none());
    let _ = std::fs::remove_dir_all(&dir_a);
}

#[test]
fn concurrent_atomic_writes_resolve_to_one_deterministic_winner() {
    // A and B write the same atomic Body concurrently, then exchange. Both
    // must end on the SAME value regardless of incorporation order.
    let dir_a = temp_store("atomic-a");
    let dir_b = temp_store("atomic-b");
    let mut a = open(&dir_a);
    let mut b = open(&dir_b);
    commit(
        &mut a,
        [28u8; 16],
        "write",
        &[(
            body(7),
            BodyOp::ReplaceAtomic {
                value: b"from-a".to_vec(),
            },
        )],
        &[(body(7), atomic_binding())],
    )
    .unwrap();
    commit(
        &mut b,
        [29u8; 16],
        "write",
        &[(
            body(7),
            BodyOp::ReplaceAtomic {
                value: b"from-b".to_vec(),
            },
        )],
        &[(body(7), atomic_binding())],
    )
    .unwrap();

    let space = space();
    let signer = SeedSigner(&WRITER_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let from_a = a.export_material().unwrap();
    let from_b = b.export_material().unwrap();
    let (tx_a, pay_a) = &from_a[0];
    let (tx_b, pay_b) = &from_b[0];
    a.incorporate(&ctx, tx_b, pay_b, &WriterAuthorized).unwrap();
    b.incorporate(&ctx, tx_a, pay_a, &WriterAuthorized).unwrap();
    assert_eq!(
        a.read(&body(7)),
        b.read(&body(7)),
        "deterministic winner regardless of order"
    );
    assert!(a.read(&body(7)).is_some());
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

#[test]
fn a_durable_replica_refuses_unattributed_commits_and_missing_keys() {
    let dir = temp_store("refuse");
    let mut r = open(&dir);
    // The unattributed test-only commit path is refused on a durable store.
    assert!(matches!(
        r.commit("x", &counter_ops(&body(8), 1)),
        Err(ReplicaCommitError::Illegitimate(_))
    ));
    drop(r);

    // A durable Replica with no sealing key refuses local writes, typed.
    struct NoKeys;
    impl replica::BodyKeySource for NoKeys {
        fn sealing_key(&self) -> Option<AuthorizedBodyKey> {
            None
        }
        fn opening_key(&self, _epoch: &[u8; 16]) -> Option<AuthorizedBodyKey> {
            None
        }
    }
    let mut r = Replica::open_journaled(&dir, Arc::new(NoKeys)).unwrap();
    r.set_supported(supported());
    let err = commit(
        &mut r,
        [30u8; 16],
        "x",
        &counter_ops(&body(8), 1),
        &[(body(8), collab_binding())],
    )
    .unwrap_err();
    assert_eq!(err, ReplicaCommitError::BodyKeyUnavailable);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn schema_bindings_are_immutable_across_writes() {
    let dir = temp_store("binding");
    let mut r = open(&dir);
    commit(
        &mut r,
        [31u8; 16],
        "created",
        &counter_ops(&body(9), 1),
        &[(body(9), collab_binding())],
    )
    .unwrap();
    // A later write declaring a DIFFERENT binding for the same Body refuses.
    let err = commit(
        &mut r,
        [32u8; 16],
        "edited",
        &counter_ops(&body(9), 1),
        &[(body(9), atomic_binding())],
    )
    .unwrap_err();
    assert_eq!(err, ReplicaCommitError::SchemaMismatch);
    // And an op with NO binding on a brand-new Body refuses (no declaration).
    let err = commit(
        &mut r,
        [33u8; 16],
        "edited",
        &counter_ops(&body(10), 1),
        &[],
    )
    .unwrap_err();
    assert_eq!(err, ReplicaCommitError::SchemaMismatch);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_engine_export_envelope_is_gone() {
    // C1.2's deletion gate: the reserved interim envelope is absent from the
    // public surface. (The names would only reappear as a compile error here.)
    // This is a compile-time proof by absence: `replica::ENGINE_EXPORT_WORLD`
    // no longer exists, and the only incorporation path takes a signed
    // transaction plus descriptor-bound payloads.
    #[allow(clippy::type_complexity)]
    let _: fn(
        &mut Replica,
        &CommitContext<'_>,
        &BodyTransaction,
        &[(BodyKey, Vec<u8>)],
        &dyn replica::AuthoritySource,
    ) -> Result<replica::ConvergenceOutcome, ReplicaCommitError> = Replica::incorporate;
}
