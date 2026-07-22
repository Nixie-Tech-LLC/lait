//! `authority_history` — exact-frontier authorization and atomic durable
//! authority batches, proven through the real mechanics composition
//! (`OrbitalMechanics` over the authority ledger) and the real Replica
//! validation chain.
//!
//! The M0.2 controlled matrix:
//! - an author authorized at its referenced historical frontier but removed
//!   currently: the old signed transaction remains legitimate;
//! - an author unauthorized at the referenced frontier but authorized
//!   currently: rejected;
//! - a valid record followed by an invalid record: the authority store is
//!   unchanged, including after restart;
//! - reordered/substituted/truncated batches cannot ride an honest receipt;
//! - the authority phase durable, then the Body phase crashes: authority
//!   survives and the Body retry incorporates exactly once.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use lait::orbital::{AuthorityRecord, OrbitalMechanics};
use mechanics::ledger::LedgerEffect;
use replica::transaction::NO_PARENT_ROOT;
use replica::{
    AuthorityIncorporator, BodyBinding, BodyId, BodyKey, BodyOp, CommitAuthorization,
    CommitContext, EncodingId, Replica, SchemaId, SeedSigner, StagedContactMaterial,
    StaticAuthorizer, SupportedSchemas, WorldId, MUTATION_COLLABORATIVE,
};

const FOUNDER_SEED: [u8; 32] = [21u8; 32];
const JOINER_SEED: [u8; 32] = [22u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_home(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-authist-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn world() -> WorldId {
    WorldId::parse("com.example.notes").unwrap()
}

fn commit_demand() -> Vec<u8> {
    mechanics::demand::AuthorizationDemand::require(
        mechanics::demand::PolicyCapability::new("com.example.notes", "write"),
        mechanics::demand::PolicyResource::space("com.example.notes"),
    )
    .encode_canonical()
    .unwrap()
}

fn static_auth() -> StaticAuthorizer {
    StaticAuthorizer {
        world: world(),
        implementation_id: [0u8; 32],
    }
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

/// Found a Space and return its mechanics handle (root stays on disk).
fn form(tag: &str) -> (PathBuf, OrbitalMechanics) {
    let root = temp_home(tag);
    let (mech, _coords) = OrbitalMechanics::form(&root, &FOUNDER_SEED, "authist", vec![]).unwrap();
    (root, mech)
}

/// Incept + admit the joiner through the real incorporator + member_add path.
/// Returns the joiner's actor id.
fn admit_joiner(mech: &OrbitalMechanics) -> mechanics::ids::ActorId {
    let space = mech.space();
    let (inception, actor_id) =
        mechanics::actor::incept_single(&JOINER_SEED, &space, [9u8; 16], [8u8; 16], None);
    let mut m = mech.clone();
    m.incorporate_authority(&[
        AuthorityRecord::Effect(LedgerEffect::Actor(inception).encode()).encode(),
    ])
    .unwrap();
    mech.member_add(actor_id.as_str(), false).unwrap();
    actor_id
}

/// Sign one collaborative-note transaction at the given authority frontier.
fn signed_note_tx(
    mech: &OrbitalMechanics,
    signer_seed: &[u8; 32],
    frontier: replica::frontier::AuthorityFrontier,
    n: u8,
) -> (
    replica::transaction::BodyTransaction,
    Vec<(BodyKey, Vec<u8>)>,
) {
    let space = mech.space();
    let mut r = Replica::loro().with_keys(Arc::new(mech.clone()));
    r.set_supported(supported());
    let signer = SeedSigner(signer_seed);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: frontier,
    };
    let device = mechanics::crypto::device_from_seed(signer_seed);
    r.commit_action(
        &ctx,
        &CommitAuthorization {
            actor: "actor",
            parent_manifest_root: NO_PARENT_ROOT,
            demand: commit_demand(),
            intent_digest: [7u8; 32],
            authorizer: &static_auth(),
        },
        &world(),
        &device,
        &[n; 16],
        &[7u8; 32],
        vec![],
        vec![],
        "note",
        &[(
            body(n),
            BodyOp::RegisterSet {
                path: "text".into(),
                value: format!("note {n}").into_bytes(),
            },
        )],
        &[(body(n), binding())],
    )
    .unwrap();
    let material = r.export_material().unwrap();
    material.into_iter().next().unwrap()
}

#[test]
fn historical_authorized_but_currently_removed_remains_legitimate() {
    let (_root, mech) = form("hist-ok");
    let joiner = admit_joiner(&mech);
    let member_frontier = mech.current_frontier();
    let (tx, _) = signed_note_tx(&mech, &JOINER_SEED, member_frontier.clone(), 1);

    mech.member_remove(joiner.as_str()).unwrap();
    let removed_frontier = mech.current_frontier();
    assert_ne!(member_frontier, removed_frontier);

    // The old transaction — referencing the frontier where the author WAS a
    // member — remains legitimate after the removal.
    tx.verify_authorized(&mech)
        .expect("historically authorized transaction stays legitimate");

    // The same author signing at the *current* frontier is rejected.
    let (tx_now, _) = signed_note_tx(&mech, &JOINER_SEED, removed_frontier, 2);
    assert!(
        tx_now.verify_authorized(&mech).is_err(),
        "a removed author cannot author at the removal frontier"
    );
}

#[test]
fn unauthorized_at_referenced_frontier_despite_current_standing_rejects() {
    let (_root, mech) = form("hist-no");
    let before_frontier = mech.current_frontier();
    // Sign BEFORE admission, referencing the pre-admission frontier.
    let (tx, _) = signed_note_tx(&mech, &JOINER_SEED, before_frontier, 1);
    // Now admit the author.
    let _ = admit_joiner(&mech);
    assert!(
        mech.am_i_member(),
        "sanity: the founder's handle is a member"
    );
    // Current standing does not rescue a historically unauthorized signature.
    assert!(
        tx.verify_authorized(&mech).is_err(),
        "authorization is at the referenced frontier, not current state"
    );
}

#[test]
fn a_valid_record_followed_by_an_invalid_one_changes_nothing_even_after_restart() {
    let (root, mech) = form("atomic");
    let space = mech.space();
    let frontier_before = mech.current_frontier();
    let (inception, _) =
        mechanics::actor::incept_single(&JOINER_SEED, &space, [9u8; 16], [8u8; 16], None);
    let valid = AuthorityRecord::Effect(LedgerEffect::Actor(inception).encode()).encode();
    let invalid = AuthorityRecord::Effect(vec![0xDE, 0xAD, 0xBE, 0xEF]).encode();

    let mut m = mech.clone();
    let err = m.incorporate_authority(&[valid, invalid]).unwrap_err();
    assert!(err.contains("invalid"), "typed refusal, got: {err}");
    assert_eq!(mech.current_frontier(), frontier_before, "nothing adopted");

    // Restart: the durable ledger never saw the batch.
    drop(m);
    drop(mech);
    let reopened = OrbitalMechanics::open(&root, &space, &FOUNDER_SEED).unwrap();
    assert_eq!(reopened.current_frontier(), frontier_before);
}

#[test]
fn reorder_substitute_truncate_cannot_ride_an_honest_receipt() {
    let (_root, mech) = form("digest");
    let space = mech.space();
    let (i1, _) = mechanics::actor::incept_single(&JOINER_SEED, &space, [9u8; 16], [8u8; 16], None);
    let (i2, _) = mechanics::actor::incept_single(&[23u8; 32], &space, [7u8; 16], [6u8; 16], None);
    let r1 = AuthorityRecord::Effect(LedgerEffect::Actor(i1).encode()).encode();
    let r2 = AuthorityRecord::Effect(LedgerEffect::Actor(i2).encode()).encode();

    let mut m = mech.clone();
    let receipt = m.incorporate_authority(&[r1.clone(), r2.clone()]).unwrap();

    // Reordered: a different batch identity (a receipt is not transferable).
    let reordered = m.incorporate_authority(&[r2.clone(), r1.clone()]).unwrap();
    assert_ne!(
        receipt.batch_digest, reordered.batch_digest,
        "reordering changes the batch digest"
    );
    // Truncated: again a different identity.
    let truncated = m.incorporate_authority(std::slice::from_ref(&r1)).unwrap();
    assert_ne!(receipt.batch_digest, truncated.batch_digest);
    // Substituted: a tampered record refuses the whole batch.
    let mut tampered_bytes = r2.clone();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 0xFF;
    assert!(m
        .incorporate_authority(&[r1.clone(), tampered_bytes])
        .is_err());
    // Exact replay of the original: the identical receipt.
    let replay = m.incorporate_authority(&[r1, r2]).unwrap();
    assert_eq!(receipt.batch_digest, replay.batch_digest);
    assert_eq!(receipt.resulting_frontier, replay.resulting_frontier);
}

#[test]
fn authority_survives_a_body_crash_and_the_retry_incorporates_exactly_once() {
    let (_root_a, mech_a) = form("crash");
    let space = mech_a.space();

    // Source: the founder commits one note; export the full staging.
    let mut source = Replica::loro().with_keys(Arc::new(mech_a.clone()));
    source.set_supported(supported());
    let signer = SeedSigner(&FOUNDER_SEED);
    let ctx = CommitContext {
        space: &space,
        signer: &signer,
        authority_frontier: mech_a.current_frontier(),
    };
    let device = mechanics::crypto::device_from_seed(&FOUNDER_SEED);
    source
        .commit_action(
            &ctx,
            &CommitAuthorization {
                actor: "actor",
                parent_manifest_root: NO_PARENT_ROOT,
                demand: commit_demand(),
                intent_digest: [7u8; 32],
                authorizer: &static_auth(),
            },
            &world(),
            &device,
            &[1u8; 16],
            &[7u8; 32],
            vec![],
            vec![],
            "note",
            &[(
                body(1),
                BodyOp::RegisterSet {
                    path: "text".into(),
                    value: b"crash test".to_vec(),
                },
            )],
            &[(body(1), binding())],
        )
        .unwrap();
    let material = source.export_material().unwrap();
    let (root_bytes, pages) = source.export_manifest(&ctx).unwrap();
    let mut authority_records: Vec<Vec<u8>> = mech_a.export_records();
    let mut bodies = Vec::new();
    for (tx, payloads) in &material {
        authority_records.push(tx.encode());
        for (key, envelope) in payloads {
            bodies.push((tx.id(), key.clone(), envelope.clone()));
        }
    }
    let staged = StagedContactMaterial {
        authority_records,
        manifest_root_bytes: root_bytes,
        manifest_pages: pages,
        bodies,
    };

    // Target: a fresh durable replica on a second home, whose mechanics is a
    // separate handle over ITS OWN ledger (entered via the founder's records).
    let root_b = temp_home("crash-b");
    let coords = mech_a
        .mint_coordinates(&FOUNDER_SEED, "", vec![], None)
        .unwrap();
    // The receiving process runs the founder's device (a second home of
    // the same device), so the sealed epoch key riding the authority records
    // opens the Body material after incorporation.
    let mech_b = OrbitalMechanics::enter(&root_b, &FOUNDER_SEED, &coords).unwrap();

    let store_dir = root_b.join("replica-store");
    std::fs::create_dir_all(&store_dir).unwrap();
    let crash_now = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let crash_flag = crash_now.clone();
    let mut target = Replica::open_journaled(&store_dir, Arc::new(mech_b.clone()))
        .unwrap()
        .with_store_fault_injector(Box::new(move |point| {
            point == "manifest-rename" && crash_flag.load(Ordering::SeqCst)
        }));
    target.set_supported(supported());

    let incorporator: Arc<Mutex<OrbitalMechanics>> = Arc::new(Mutex::new(mech_b.clone()));
    let frontier_before_contact = mech_b.current_frontier();

    // Phase 1: validation (authority incorporates durably) then a Body-phase
    // crash at the manifest rename.
    let bundle = {
        let mut inc = incorporator.lock().unwrap();
        target
            .validate_contact(&staged, &mech_b, &mut *inc)
            .expect("validation succeeds; authority phase is durable")
    };
    let frontier_after_authority = mech_b.current_frontier();
    assert_ne!(
        frontier_before_contact, frontier_after_authority,
        "the authority phase advanced durably before the Body phase"
    );
    let err = target.incorporate_bundle(&ctx_for(&space, &mech_b), bundle, &mech_b);
    assert!(
        err.is_err(),
        "the injected Body-phase crash fails the commit"
    );
    drop(target);

    // Authority survived the crash: a reopened mechanics still shows it.
    let mech_b2 = OrbitalMechanics::open(&root_b, &space, &FOUNDER_SEED).unwrap();
    assert_eq!(mech_b2.current_frontier(), frontier_after_authority);

    // Phase 2: retry after "reboot" — incorporates exactly once.
    crash_now.store(false, Ordering::SeqCst);
    let mut target = Replica::open_journaled(&store_dir, Arc::new(mech_b2.clone())).unwrap();
    target.set_supported(supported());
    let bundle = {
        let mut inc = mech_b2.clone();
        target
            .validate_contact(&staged, &mech_b2, &mut inc)
            .unwrap()
    };
    let outcome = target
        .incorporate_bundle(&ctx_for(&space, &mech_b2), bundle, &mech_b2)
        .unwrap();
    assert_eq!(outcome.accepted, 1, "the retry incorporates the material");

    // A second retry is pure replay: unchanged, no double-apply.
    let bundle = {
        let mut inc = mech_b2.clone();
        target
            .validate_contact(&staged, &mech_b2, &mut inc)
            .unwrap()
    };
    let outcome = target
        .incorporate_bundle(&ctx_for(&space, &mech_b2), bundle, &mech_b2)
        .unwrap();
    assert_eq!(outcome.accepted, 0, "exactly-once: replay accepts nothing");
    assert_eq!(outcome.rejected, 0);
}

fn ctx_for<'a>(space: &'a mechanics::ids::SpaceId, mech: &OrbitalMechanics) -> CommitContext<'a> {
    static SIGNER: SeedSigner<'static> = SeedSigner(&FOUNDER_SEED);
    CommitContext {
        space,
        signer: &SIGNER,
        authority_frontier: mech.current_frontier(),
    }
}
