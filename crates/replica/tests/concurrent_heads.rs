//! Multi-writer convergence — the constituent-head model.
//!
//! A Body written concurrently by two authorized devices has no single
//! envelope containing its merged state: each replica's index carries the SET
//! of author-signed heads whose engine merge is the state, the manifest
//! advertises one entry per head, transfers move every head, restart re-merges
//! every head, and a later local commit collapses the set to one (its sealed
//! envelope is the full merged snapshot). Only original author-signed material
//! ever crosses a wire — a replica never re-signs what it merged, so a
//! read-only member can relay merged state it could never have authored.
//!
//! This pins the defect the 32-actor reference corpus surfaced: a replica that
//! incorporated concurrent catalog writes re-served a stale single-author
//! envelope (or nothing), so peers either rejected the root whole or silently
//! never converged, and a restart lost the merge.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use mechanics::crypto::AuthorizedBodyKey;
use mechanics::ids::SpaceId;
use replica::frontier::AuthorityFrontier;
use replica::{
    ActionOutcome, AuthorityBatchReceipt, AuthorityIncorporator, BodyBinding, BodyId, BodyKey,
    BodyOp, CommitAuthorization, CommitContext, Replica, ReplicaCommitError, SchemaId, SeedSigner,
    StagedContactMaterial, StaticBodyKeys, SupportedSchemas, WorldId, MUTATION_COLLABORATIVE,
};

const SEED_A: [u8; 32] = [81u8; 32];
const SEED_B: [u8; 32] = [82u8; 32];
const SEED_C: [u8; 32] = [83u8; 32];
const EPOCH: [u8; 16] = [21u8; 16];
const EPOCH_KEY: [u8; 32] = [22u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_store(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-heads-{tag}-{}-{n}", std::process::id()));
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

fn shared_body() -> BodyKey {
    BodyKey::new(world(), BodyId::from_bytes([9u8; 16]))
}

fn binding() -> BodyBinding {
    BodyBinding {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        encoding: replica::EncodingId::parse("collab").unwrap(),
        mutation_model: MUTATION_COLLABORATIVE,
    }
}

fn supported() -> SupportedSchemas {
    let mut s = SupportedSchemas::new();
    s.declare(
        world(),
        SchemaId::parse("note").unwrap(),
        1,
        replica::EncodingId::parse("collab").unwrap(),
        MUTATION_COLLABORATIVE,
    );
    s
}

/// Any of the three test devices is an authorized signer.
struct AnyWriter;
impl replica::AuthoritySource for AnyWriter {
    fn signer_authorized(&self, signer: &[u8; 32], _f: &AuthorityFrontier) -> bool {
        [SEED_A, SEED_B, SEED_C]
            .iter()
            .any(|seed| mechanics::crypto::device_from_seed(seed).key_bytes() == Some(*signer))
    }
}

#[derive(Default)]
struct AcceptingIncorporator;
impl AuthorityIncorporator for AcceptingIncorporator {
    fn incorporate_authority(
        &mut self,
        records: &[Vec<u8>],
    ) -> Result<AuthorityBatchReceipt, String> {
        Ok(replica::AuthorityBatchReceipt {
            space: space(),
            prior_frontier: AuthorityFrontier::from_canonical_bytes(vec![]),
            resulting_frontier: authority_frontier(),
            batch_digest: *blake3::hash(&records.concat()).as_bytes(),
        })
    }
}

fn authority_frontier() -> AuthorityFrontier {
    AuthorityFrontier::from_canonical_bytes(vec![17])
}

fn ctx_for(seed: &'static [u8; 32]) -> (SpaceId, SeedSigner<'static>) {
    (space(), SeedSigner(seed))
}

fn keyed_replica() -> Replica {
    let mut r = Replica::loro().with_keys(keys());
    r.set_supported(supported());
    r
}

fn durable_replica(tag: &str) -> (Replica, PathBuf) {
    let root = temp_store(tag);
    let mut r = Replica::open_journaled(&root, keys()).unwrap();
    r.set_supported(supported());
    (r, root)
}

fn reopen(root: &PathBuf) -> Replica {
    let mut r = Replica::open_journaled(root, keys()).unwrap();
    r.set_supported(supported());
    r
}

/// Commit `RegisterSet(path=value)` on the shared body, signed by `seed`.
fn commit_register(
    r: &mut Replica,
    seed: &'static [u8; 32],
    request: [u8; 16],
    path: &str,
    value: &str,
) -> Result<ActionOutcome, ReplicaCommitError> {
    let (space, signer) = ctx_for(seed);
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
        &mechanics::crypto::device_from_seed(seed),
        &request,
        &[7u8; 32],
        vec![],
        vec![],
        "note",
        &[(
            shared_body(),
            BodyOp::RegisterSet {
                path: path.into(),
                value: value.as_bytes().to_vec(),
            },
        )],
        &[(shared_body(), binding())],
    )
}

/// Stage a replica's full export as untrusted Contact material.
fn stage(r: &Replica, seed: &'static [u8; 32]) -> StagedContactMaterial {
    let (space, signer) = ctx_for(seed);
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

/// Pull `from`'s full staging into `into` (validate + incorporate).
fn pull(
    into: &mut Replica,
    into_seed: &'static [u8; 32],
    from: &Replica,
    from_seed: &'static [u8; 32],
) -> replica::ConvergenceOutcome {
    let staged = stage(from, from_seed);
    let (space, signer) = ctx_for(into_seed);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: authority_frontier(),
    };
    let mut incorporator = AcceptingIncorporator;
    let bundle = into
        .validate_contact(&staged, &AnyWriter, &mut incorporator)
        .unwrap();
    into.incorporate_bundle(&ctx, bundle, &AnyWriter).unwrap()
}

fn register_of(r: &Replica, path: &str) -> Option<String> {
    r.read_collaborative(&shared_body()).and_then(|v| {
        v.registers
            .get(path)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    })
}

#[test]
fn concurrent_writers_converge_and_reserve_the_union() {
    // A and B write concurrently (each from the empty base).
    let mut a = keyed_replica();
    let mut b = keyed_replica();
    commit_register(&mut a, &SEED_A, [1u8; 16], "froma", "alpha").unwrap();
    commit_register(&mut b, &SEED_B, [2u8; 16], "fromb", "beta").unwrap();

    // A pulls B: the union is readable, and BOTH heads are advertised.
    let outcome = pull(&mut a, &SEED_A, &b, &SEED_B);
    assert!(outcome.advanced(), "concurrent head incorporates");
    assert_eq!(register_of(&a, "froma").as_deref(), Some("alpha"));
    assert_eq!(register_of(&a, "fromb").as_deref(), Some("beta"));

    // B pulls A: symmetric union.
    pull(&mut b, &SEED_B, &a, &SEED_A);
    assert_eq!(register_of(&b, "froma").as_deref(), Some("alpha"));
    assert_eq!(register_of(&b, "fromb").as_deref(), Some("beta"));

    // TRANSITIVE relay: C (a third party that authored nothing) pulls ONLY A
    // and still receives both authors' heads — merged state relays through an
    // intermediary without that intermediary re-signing anything.
    let mut c = keyed_replica();
    pull(&mut c, &SEED_C, &a, &SEED_A);
    assert_eq!(register_of(&c, "froma").as_deref(), Some("alpha"));
    assert_eq!(register_of(&c, "fromb").as_deref(), Some("beta"));

    // Idempotent re-pull: nothing new, nothing rejected.
    let again = pull(&mut c, &SEED_C, &a, &SEED_A);
    assert!(!again.advanced(), "re-pulling known heads changes nothing");
    assert_eq!(again.rejected, 0);
}

#[test]
fn merged_heads_survive_a_durable_restart() {
    let (mut a, root) = durable_replica("restart");
    let mut b = keyed_replica();
    commit_register(&mut a, &SEED_A, [3u8; 16], "froma", "alpha").unwrap();
    commit_register(&mut b, &SEED_B, [4u8; 16], "fromb", "beta").unwrap();
    pull(&mut a, &SEED_A, &b, &SEED_B);
    assert_eq!(register_of(&a, "fromb").as_deref(), Some("beta"));
    drop(a);

    // Reopen: the union is rebuilt from the persisted head set, and the
    // reopened replica can still serve BOTH heads to a third party.
    let a = reopen(&root);
    assert_eq!(register_of(&a, "froma").as_deref(), Some("alpha"));
    assert_eq!(register_of(&a, "fromb").as_deref(), Some("beta"));
    let mut c = keyed_replica();
    pull(&mut c, &SEED_C, &a, &SEED_A);
    assert_eq!(register_of(&c, "froma").as_deref(), Some("alpha"));
    assert_eq!(register_of(&c, "fromb").as_deref(), Some("beta"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_local_commit_collapses_the_head_set() {
    let mut a = keyed_replica();
    let mut b = keyed_replica();
    commit_register(&mut a, &SEED_A, [5u8; 16], "froma", "alpha").unwrap();
    commit_register(&mut b, &SEED_B, [6u8; 16], "fromb", "beta").unwrap();
    pull(&mut a, &SEED_A, &b, &SEED_B);

    // A's next local commit seals the FULL merged snapshot: one head again.
    commit_register(&mut a, &SEED_A, [7u8; 16], "sealed", "yes").unwrap();

    // A fresh C pulling only A gets everything from that single-author head.
    let mut c = keyed_replica();
    pull(&mut c, &SEED_C, &a, &SEED_A);
    assert_eq!(register_of(&c, "froma").as_deref(), Some("alpha"));
    assert_eq!(register_of(&c, "fromb").as_deref(), Some("beta"));
    assert_eq!(register_of(&c, "sealed").as_deref(), Some("yes"));
}
