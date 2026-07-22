//! `ceremony_frontier_isolation` — ceremony packets never enlarge ordinary
//! authority frontiers; one terminal SpaceAuthority effect does (plan 50).
//!
//! Proves, over 10,000+ valid ceremony packets across many completed and
//! aborted transcripts:
//! - the ordinary `AuthorityFrontier` stays byte-identical and bounded until a
//!   terminal SpaceAuthority effect lands;
//! - cross-domain substitution between ceremony material and SpaceAuthority
//!   effects rejects before journal mutation;
//! - restart preserves the ceremony log, its cursor, and the frontier;
//! - synchronization resumes from the bounded ceremony cursor (an incremental
//!   pull transfers only the suffix);
//! - terminal compaction is durable behind its audit commitment and cannot
//!   remove active or validation-required material.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use mechanics::authority::{AuthorityId, PrincipalId};
use mechanics::ceremony::terminal_compactable;
use mechanics::dkg::{self, CeremonyOp, SignTarget, TranscriptId};
use mechanics::genesis::Genesis;
use mechanics::ids::{ActorId, SpaceId, SystemUlidSource};
use mechanics::ledger::{AuthorityLedger, CeremonyMaterial, LedgerEffect};
use mechanics::space::{self, SignedSpaceEvent, SpaceOp};
use mechanics::{actor, crypto};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn tempdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("lait-cfi-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

struct Fx {
    space: SpaceId,
    genesis: Genesis,
    founder_incept: actor::SignedEvent,
    recovery_seed: [u8; 32],
}

fn fx() -> Fx {
    let recovery_seed = seed(40);
    let recovery_root = space::recovery_commit(&space::recovery_pub_of(&recovery_seed)).unwrap();
    let space_id = SpaceId::mint(&SystemUlidSource);
    let (founder_incept, founder) =
        actor::incept_single(&seed(1), &space_id, [1; 16], [71; 16], None);
    Fx {
        space: space_id.clone(),
        genesis: Genesis {
            space_id,
            founding_actors: vec![founder],
            salt: [0u8; 16],
            recovery_root,
        },
        founder_incept,
        recovery_seed,
    }
}

/// One complete signing transcript over `op_bytes`: request + two round-1
/// commitments + the coordinator's plan + two round-2 shares — six valid
/// ceremony packets. The round payloads are opaque bytes at this layer; the
/// signatures and grammar are real.
fn signing_transcript(fx: &Fx, nonce_tag: u32, op_bytes: Vec<u8>) -> Vec<SignedSpaceEvent> {
    let mut nonce = [0u8; 16];
    nonce[..4].copy_from_slice(&nonce_tag.to_be_bytes());
    let authority = TranscriptId::parse_hex(&"ab".repeat(32)).unwrap();
    let coordinator = crypto::device_from_seed(&seed(1));
    let request = dkg::sign_ceremony(
        &seed(1),
        &CeremonyOp::SignRequest {
            nonce,
            authority,
            target: SignTarget::SpaceOp,
            coordinator,
            op: op_bytes,
        },
        &fx.space,
    );
    let signing = TranscriptId::of(&request).unwrap();
    let mut nodes = vec![request];
    for participant in [1u8, 2u8] {
        nodes.push(dkg::sign_ceremony(
            &seed(participant),
            &CeremonyOp::SignRound1 {
                signing,
                commitments: vec![participant; 32],
            },
            &fx.space,
        ));
    }
    nodes.push(dkg::sign_ceremony(
        &seed(1),
        &CeremonyOp::SignPlan {
            signing,
            plan: vec![9; 48],
        },
        &fx.space,
    ));
    for participant in [1u8, 2u8] {
        nodes.push(dkg::sign_ceremony(
            &seed(participant),
            &CeremonyOp::SignRound2 {
                signing,
                share: vec![participant; 32],
            },
            &fx.space,
        ));
    }
    nodes
}

fn recover_op(fx: &Fx, gen: u32) -> Vec<u8> {
    postcard::to_stdvec(&SpaceOp::Recover {
        new_root: vec![ActorId::from_incept_hash(&fx.founder_incept.hash())],
        gen,
    })
    .unwrap()
}

#[test]
fn ceremony_traffic_never_enlarges_the_ordinary_frontier() {
    let dir = tempdir("main");
    let fx = fx();
    let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
    ledger
        .commit_batch(
            &[LedgerEffect::Actor(fx.founder_incept.clone()).encode()],
            &[],
        )
        .unwrap();
    let baseline_frontier = ledger.frontier();
    assert!(
        baseline_frontier.len() < 512,
        "the ordinary frontier is bounded"
    );

    // ---- 10,002 valid ceremony packets across 1,667 transcripts ----------
    // Every transcript requests a gen-1 Recover: once gen 1 installs (or is
    // fenced) they are all "completed or aborted" — terminal either way.
    let mut packets: Vec<Vec<u8>> = Vec::new();
    for t in 0..1_667u32 {
        for node in signing_transcript(&fx, t, recover_op(&fx, 1)) {
            packets.push(CeremonyMaterial::new(node).encode());
        }
    }
    assert!(packets.len() >= 10_000, "at least 10,000 ceremony packets");
    for chunk in packets.chunks(500) {
        ledger.commit_ceremony_batch(chunk).unwrap();
        assert_eq!(
            ledger.frontier(),
            baseline_frontier,
            "ceremony packets never become authority-frontier heads"
        );
    }
    let total = packets.len() as u64;
    assert_eq!(ledger.ceremony_cursor(), total);
    assert_eq!(
        ledger.frontier(),
        baseline_frontier,
        "10,000+ ceremony packets left the ordinary frontier byte-identical"
    );

    // ---- cross-domain substitution rejects before journal mutation -------
    let seq_before = ledger.journal_sequence();
    let cursor_before = ledger.ceremony_cursor();
    // A ceremony-domain node smuggled in as a SpaceAuthority effect:
    let ceremony_node = dkg::sign_ceremony(
        &seed(1),
        &CeremonyOp::SignPlan {
            signing: TranscriptId::parse_hex(&"cd".repeat(32)).unwrap(),
            plan: vec![1],
        },
        &fx.space,
    );
    let err = ledger
        .commit_batch(&[LedgerEffect::SpaceAuthority(ceremony_node).encode()], &[])
        .unwrap_err();
    assert!(
        matches!(err, mechanics::ledger::LedgerError::InvalidRecord(_)),
        "ceremony-domain bytes cannot enter the authority plane: {err:?}"
    );
    // A Space-event-domain terminal effect smuggled in as ceremony material:
    let terminal_node = space::sign_op(
        &fx.recovery_seed,
        &SpaceOp::Recover {
            new_root: vec![ActorId::from_incept_hash(&fx.founder_incept.hash())],
            gen: 1,
        },
        vec![],
        &fx.space,
    );
    let err = ledger
        .commit_ceremony_batch(&[CeremonyMaterial::new(terminal_node.clone()).encode()])
        .unwrap_err();
    assert!(
        matches!(err, mechanics::ledger::LedgerError::InvalidRecord(_)),
        "space-domain bytes cannot enter the ceremony class: {err:?}"
    );
    assert_eq!(ledger.journal_sequence(), seq_before, "no journal mutation");
    assert_eq!(ledger.ceremony_cursor(), cursor_before);
    assert_eq!(ledger.frontier(), baseline_frontier);

    // ---- exactly one terminal SpaceAuthority effect moves the frontier ----
    ledger
        .commit_batch(&[LedgerEffect::SpaceAuthority(terminal_node).encode()], &[])
        .unwrap();
    let terminal_frontier = ledger.frontier();
    assert_ne!(
        terminal_frontier, baseline_frontier,
        "the ONE terminal effect advances the frontier"
    );
    assert!(
        terminal_frontier.len() < 512,
        "the frontier stays bounded after the terminal effect"
    );
    assert_eq!(ledger.space_authority_events().len(), 1);

    // ---- restart preserves the log, cursor, audits and frontier -----------
    drop(ledger);
    let mut ledger = AuthorityLedger::open(&dir).unwrap();
    assert_eq!(ledger.ceremony_cursor(), total);
    assert_eq!(ledger.ceremony_nodes().len(), packets.len());
    assert_eq!(ledger.frontier(), terminal_frontier);

    // ---- synchronization resumes from the bounded cursor ------------------
    let dir_b = tempdir("peer");
    let mut peer = AuthorityLedger::create(&dir_b, fx.genesis.clone()).unwrap();
    // Full initial sync (a cold peer pulls everything once)...
    for chunk in ledger.export_ceremony().chunks(1000) {
        peer.commit_ceremony_batch(chunk).unwrap();
    }
    assert_eq!(peer.ceremony_nodes().len(), ledger.ceremony_nodes().len());
    // ...then remembers the source's cursor and pulls only the suffix.
    let synced_to = ledger.ceremony_cursor();
    let mut active: Vec<Vec<u8>> = Vec::new();
    for node in signing_transcript(&fx, 9_999, recover_op(&fx, 2)) {
        active.push(CeremonyMaterial::new(node).encode());
    }
    ledger.commit_ceremony_batch(&active).unwrap();
    let suffix = ledger.ceremony_after(synced_to);
    assert_eq!(
        suffix.len(),
        active.len(),
        "an incremental pull transfers only the suffix past the cursor"
    );
    peer.commit_ceremony_batch(&suffix.iter().map(|(_, b)| b.clone()).collect::<Vec<_>>())
        .unwrap();
    assert_eq!(peer.ceremony_nodes().len(), ledger.ceremony_nodes().len());

    // ---- terminal compaction: durable audit, active material retained -----
    let root_state = space::replay(&fx.genesis, &fx.space, &ledger.space_authority_events());
    assert_eq!(root_state.gen, 1, "the terminal Recover installed");
    let drop_set = terminal_compactable(&ledger.ceremony_nodes(), &fx.space, &root_state);
    assert!(
        drop_set.len() >= 10_000,
        "every gen-1 transcript is terminal (installed or fenced): {}",
        drop_set.len()
    );
    // The ACTIVE gen-2 transcript is not in the drop set.
    let active_hashes: Vec<String> = active
        .iter()
        .map(|b| CeremonyMaterial::decode(b).unwrap().hash())
        .collect();
    for h in &active_hashes {
        assert!(
            !drop_set.contains(h),
            "an active transcript may not be compacted"
        );
    }
    let cursor_before_compaction = ledger.ceremony_cursor();
    let commitment = ledger.compact_ceremony(&drop_set).unwrap();
    assert_eq!(
        ledger.ceremony_cursor(),
        cursor_before_compaction,
        "compaction never renumbers the cursor"
    );
    let remaining: Vec<String> = ledger.ceremony_nodes().iter().map(|n| n.hash()).collect();
    for h in &active_hashes {
        assert!(remaining.contains(h), "active material survives compaction");
    }
    assert!(
        ledger.ceremony_nodes().len() < 20,
        "terminal transcript traffic was reclaimed"
    );
    assert_eq!(ledger.ceremony_audit_commitments(), vec![commitment]);

    // The audit commitment is durable across restart.
    drop(ledger);
    let mut ledger = AuthorityLedger::open(&dir).unwrap();
    assert_eq!(ledger.ceremony_audit_commitments(), vec![commitment]);
    assert_eq!(ledger.ceremony_cursor(), cursor_before_compaction);
    for h in &active_hashes {
        assert!(
            ledger.ceremony_nodes().iter().any(|n| n.hash() == *h),
            "active material survives compaction + restart"
        );
    }

    // Compacting an unheld record refuses.
    let err = ledger.compact_ceremony(&["ff".repeat(32)]).unwrap_err();
    assert!(matches!(
        err,
        mechanics::ledger::LedgerError::InvalidRecord(_)
    ));

    let _ = (
        AuthorityId::single(space::recovery_pub_of(&seed(40))),
        PrincipalId::of_device(&crypto::device_from_seed(&seed(1))),
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir_b);
}
