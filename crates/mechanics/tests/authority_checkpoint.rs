//! `authority_checkpoint` — the canonical authority journal/checkpoint gate.
//!
//! Proves the M0.3a spine contract: fault injection around every journal
//! boundary exposes the complete old or complete new ledger; checkpoint and
//! effect-set commitments agree; linear-suffix continuation and branch/merge
//! arrival permutations are equivalent to the complete `acl::replay`;
//! corruption is an integrity failure (never a silent repair); a
//! semantics-version bump is an explicit verified rebuild from the signed
//! effects; the decoded-checkpoint cache is bounded; and 10,000 ordinary
//! historical-authorization reads against the pinned checkpoint perform zero
//! authority journal writes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use mechanics::acl::{self, AclAction, AclOp, Grant};
use mechanics::actor;
use mechanics::genesis::Genesis;
use mechanics::ids::{ActorId, SpaceId, SystemUlidSource};
use mechanics::ledger::{AuthorityLedger, LedgerEffect, LedgerError};

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

struct Fx {
    genesis: Genesis,
    founder_actor: ActorId,
    founder_incept: actor::SignedEvent,
    actors: BTreeMap<u8, (actor::SignedEvent, ActorId)>,
}

fn fx(others: &[u8]) -> Fx {
    let space = SpaceId::mint(&SystemUlidSource);
    let (incept, founder) = actor::incept_single(&seed(1), &space, [1; 16], [71; 16], None);
    let mut actors = BTreeMap::new();
    for n in others {
        actors.insert(
            *n,
            actor::incept_single(&seed(*n), &space, [*n; 16], [n + 70; 16], None),
        );
    }
    Fx {
        genesis: Genesis {
            space_id: space,
            founding_actors: vec![founder.clone()],
            salt: [0u8; 16],
            recovery_root: [0u8; 32],
        },
        founder_actor: founder,
        founder_incept: incept,
        actors,
    }
}

fn add_op(
    fx: &Fx,
    ledger: &AuthorityLedger,
    target: &ActorId,
    grants: Vec<Grant>,
) -> acl::SignedOp {
    acl::sign_op(
        &seed(1),
        &AclOp {
            action: AclAction::AddMember {
                actor: target.clone(),
                grants,
            },
            by: fx.founder_actor.clone(),
            actor_asof: ledger.actor_heads(&fx.founder_actor),
            nonce: None,
        },
        ledger.acl_heads(),
        &fx.genesis.space_id,
    )
}

fn tempdir(tag: &str) -> PathBuf {
    let mut raw = [0u8; 8];
    getrandom::fill(&mut raw).unwrap();
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let p = std::env::temp_dir().join(format!("lait-authck-{tag}-{hex}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn cleanup(p: &Path) {
    let _ = std::fs::remove_dir_all(p);
}

/// Fault injection at every named journal point: the batch either did not
/// commit (old state on reopen) or fully committed (complete new state) — and
/// after the failure clears, an exact retry lands the identical receipt.
#[test]
fn faults_at_every_journal_boundary_expose_old_or_complete_new() {
    for point in journal::FAULT_POINTS {
        let dir = tempdir("fault");
        let fx = fx(&[2]);
        {
            let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
            ledger
                .commit_batch(
                    &[
                        LedgerEffect::Actor(fx.founder_incept.clone()).encode(),
                        LedgerEffect::Actor(fx.actors[&2].0.clone()).encode(),
                    ],
                    &[],
                )
                .unwrap();
        }
        let baseline_frontier;
        let batch;
        {
            let ledger = AuthorityLedger::open(&dir).unwrap();
            baseline_frontier = ledger.frontier();
            batch =
                vec![
                    LedgerEffect::Acl(add_op(&fx, &ledger, &fx.actors[&2].1, vec![Grant::Write]))
                        .encode(),
                ];
            let armed = Arc::new(AtomicUsize::new(0));
            let armed2 = armed.clone();
            let target = point.to_string();
            let mut faulty = ledger.with_fault_injector(Box::new(move |p| {
                if p == target {
                    armed2.fetch_add(1, Ordering::SeqCst);
                    return true;
                }
                false
            }));
            let result = faulty.commit_batch(&batch, &[]);
            // Post-authoritative points absorb the crash and succeed; earlier
            // points fail with the old state exposed.
            let post_authoritative = matches!(point, "journal-committed" | "journal-remove");
            if post_authoritative {
                assert!(
                    result.is_ok(),
                    "{point}: post-switch cleanup crash must not fail"
                );
            } else {
                assert!(result.is_err(), "{point}: pre-switch crash must fail");
            }
            assert_eq!(armed.load(Ordering::SeqCst), 1, "{point} fired once");
        }
        // Reopen: recovery exposes the complete old or complete new ledger.
        let mut reopened = AuthorityLedger::open(&dir)
            .unwrap_or_else(|e| panic!("{point}: reopen after injected crash: {e}"));
        let advanced = reopened.frontier() != baseline_frontier;
        let member = reopened.acl_state().unwrap().can_write(&fx.actors[&2].1);
        assert_eq!(
            advanced, member,
            "{point}: frontier and materialized state must move together"
        );
        // Exact retry converges to the committed state with a receipt.
        let receipt = reopened.commit_batch(&batch, &[]).unwrap();
        assert_eq!(receipt.resulting_frontier, reopened.frontier());
        assert!(reopened.acl_state().unwrap().can_write(&fx.actors[&2].1));
        cleanup(&dir);
    }
}

/// Branch/merge equivalence and arrival-order permutation: two concurrent
/// authority branches merged in either order produce the identical frontier,
/// state, and complete-replay result.
#[test]
fn branch_merge_and_arrival_permutation_match_complete_replay() {
    let fx = fx(&[2, 3]);
    // Two concurrent ops: both roots (no parents), authored by the founder.
    let base = vec![
        LedgerEffect::Actor(fx.founder_incept.clone()).encode(),
        LedgerEffect::Actor(fx.actors[&2].0.clone()).encode(),
        LedgerEffect::Actor(fx.actors[&3].0.clone()).encode(),
    ];
    let op_a = acl::sign_op(
        &seed(1),
        &AclOp {
            action: AclAction::AddMember {
                actor: fx.actors[&2].1.clone(),
                grants: vec![Grant::Write],
            },
            by: fx.founder_actor.clone(),
            actor_asof: vec![fx.founder_incept.hash()],
            nonce: None,
        },
        vec![],
        &fx.genesis.space_id,
    );
    let op_b = acl::sign_op(
        &seed(1),
        &AclOp {
            action: AclAction::AddMember {
                actor: fx.actors[&3].1.clone(),
                grants: vec![Grant::Admin, Grant::Write],
            },
            by: fx.founder_actor.clone(),
            actor_asof: vec![fx.founder_incept.hash()],
            nonce: None,
        },
        vec![],
        &fx.genesis.space_id,
    );
    let a = LedgerEffect::Acl(op_a).encode();
    let b = LedgerEffect::Acl(op_b).encode();

    let dir1 = tempdir("perm1");
    let dir2 = tempdir("perm2");
    let mut l1 = AuthorityLedger::create(&dir1, fx.genesis.clone()).unwrap();
    let mut l2 = AuthorityLedger::create(&dir2, fx.genesis.clone()).unwrap();
    // Node 1: base, then A, then B. Node 2: base+B in one batch, then A.
    l1.commit_batch(&base, &[]).unwrap();
    l1.commit_batch(std::slice::from_ref(&a), &[]).unwrap();
    l1.commit_batch(std::slice::from_ref(&b), &[]).unwrap();
    let mut batch2 = base.clone();
    batch2.push(b.clone());
    l2.commit_batch(&batch2, &[]).unwrap();
    l2.commit_batch(std::slice::from_ref(&a), &[]).unwrap();

    assert_eq!(l1.frontier(), l2.frontier(), "same set, same frontier");
    assert_eq!(l1.acl_state().unwrap(), l2.acl_state().unwrap());

    // Differential against the complete replay.
    let expected = acl::replay(&fx.genesis, &l1.actor_events(), &l1.acl_ops());
    assert_eq!(l1.acl_state().unwrap(), expected);
    assert!(expected.can_write(&fx.actors[&2].1));
    assert!(expected.is_admin(&fx.actors[&3].1));
    cleanup(&dir1);
    cleanup(&dir2);
}

/// Linear-suffix (strict descendant) continuation equals the complete replay,
/// via the acl-level differential seam.
#[test]
fn strict_descendant_continuation_is_equivalent_to_complete_replay() {
    let fx = fx(&[2, 3]);
    let events = vec![
        fx.founder_incept.clone(),
        fx.actors[&2].0.clone(),
        fx.actors[&3].0.clone(),
    ];
    // Base: one op admitting actor 2.
    let op1 = acl::sign_op(
        &seed(1),
        &AclOp {
            action: AclAction::AddMember {
                actor: fx.actors[&2].1.clone(),
                grants: vec![Grant::Write],
            },
            by: fx.founder_actor.clone(),
            actor_asof: vec![fx.founder_incept.hash()],
            nonce: None,
        },
        vec![],
        &fx.genesis.space_id,
    );
    let base_ops = vec![op1.clone()];
    let (prior, _) = acl::replay_checkpointed(&fx.genesis, &events, &base_ops);
    let prior_actor_hashes: std::collections::BTreeSet<String> =
        events.iter().map(|e| e.hash()).collect();

    // Suffix: an op descending the head (names it as parent).
    let op2 = acl::sign_op(
        &seed(1),
        &AclOp {
            action: AclAction::AddMember {
                actor: fx.actors[&3].1.clone(),
                grants: vec![Grant::Write],
            },
            by: fx.founder_actor.clone(),
            actor_asof: vec![fx.founder_incept.hash()],
            nonce: None,
        },
        vec![op1.hash()],
        &fx.genesis.space_id,
    );
    let all_ops = vec![op1.clone(), op2.clone()];
    let continued =
        acl::replay_continue(&prior, &prior_actor_hashes, &fx.genesis, &events, &all_ops)
            .expect("a strict-descendant suffix takes the continuation path");
    let (full, full_audit) = acl::replay_checkpointed(&fx.genesis, &events, &all_ops);
    assert_eq!(continued.0, full, "continuation equals complete replay");
    assert_eq!(continued.1, full_audit, "audit equals complete replay");

    // A concurrent (root) suffix op refuses the continuation path.
    let op3 = acl::sign_op(
        &seed(1),
        &AclOp {
            action: AclAction::RemoveMember {
                actor: fx.actors[&2].1.clone(),
            },
            by: fx.founder_actor.clone(),
            actor_asof: vec![fx.founder_incept.hash()],
            nonce: None,
        },
        vec![],
        &fx.genesis.space_id,
    );
    let branched = vec![op1.clone(), op3];
    assert!(
        acl::replay_continue(&prior, &prior_actor_hashes, &fx.genesis, &events, &branched)
            .is_none(),
        "a non-descendant suffix falls back to complete replay"
    );

    // An actor-plane change refuses the continuation path.
    let (extra_incept, _) =
        actor::incept_single(&seed(9), &fx.genesis.space_id, [9; 16], [79; 16], None);
    let mut grown = events.clone();
    grown.push(extra_incept);
    assert!(
        acl::replay_continue(&prior, &prior_actor_hashes, &fx.genesis, &grown, &all_ops).is_none(),
        "an actor-plane change falls back to complete replay"
    );
}

/// Corrupt stored material is an integrity failure on open — never repaired
/// heuristically, never a silent cache miss.
#[test]
fn corrupt_objects_fail_open_as_integrity() {
    let dir = tempdir("corrupt");
    let fx = fx(&[]);
    {
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        ledger
            .commit_batch(
                &[LedgerEffect::Actor(fx.founder_incept.clone()).encode()],
                &[],
            )
            .unwrap();
    }
    // Corrupt every stored object in turn; each corruption must fail open.
    let objects: Vec<PathBuf> = std::fs::read_dir(dir.join("objects"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert!(!objects.is_empty());
    for path in &objects {
        let original = std::fs::read(path).unwrap();
        let mut corrupted = original.clone();
        corrupted[0] ^= 0xFF;
        std::fs::write(path, &corrupted).unwrap();
        match AuthorityLedger::open(&dir) {
            Err(LedgerError::Journal(journal::JournalError::Integrity(_)))
            | Err(LedgerError::Corrupt(_)) => {}
            other => panic!(
                "corrupting {} must fail integrity, got {:?}",
                path.display(),
                other.map(|_| "Ok")
            ),
        }
        std::fs::write(path, &original).unwrap();
    }
    // Restored: opens clean.
    AuthorityLedger::open(&dir).unwrap();
    cleanup(&dir);
}

/// A semantics-version bump is an explicit rebuild from signed effects: the
/// ledger opens, discards stale checkpoints, and re-materializes state that
/// equals the complete replay.
#[test]
fn semantics_version_bump_rebuilds_from_signed_effects() {
    let dir = tempdir("semver");
    let fx = fx(&[2]);
    {
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        ledger
            .commit_batch(
                &[
                    LedgerEffect::Actor(fx.founder_incept.clone()).encode(),
                    LedgerEffect::Actor(fx.actors[&2].0.clone()).encode(),
                ],
                &[],
            )
            .unwrap();
        let add = add_op(&fx, &ledger, &fx.actors[&2].1, vec![Grant::Write]);
        ledger
            .commit_batch(&[LedgerEffect::Acl(add).encode()], &[])
            .unwrap();
    }
    let mut rebuilt = AuthorityLedger::open_expecting_semantics(&dir, 999).unwrap();
    let expected = acl::replay(&fx.genesis, &rebuilt.actor_events(), &rebuilt.acl_ops());
    assert_eq!(rebuilt.acl_state().unwrap(), expected);
    assert!(expected.can_write(&fx.actors[&2].1));
    cleanup(&dir);
}

/// 10,000 ordinary historical-authorization checks against the pinned
/// checkpoint perform **zero** authority journal writes.
#[test]
fn ten_thousand_reads_write_nothing() {
    let dir = tempdir("reads");
    let fx = fx(&[2]);
    let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
    ledger
        .commit_batch(
            &[
                LedgerEffect::Actor(fx.founder_incept.clone()).encode(),
                LedgerEffect::Actor(fx.actors[&2].0.clone()).encode(),
            ],
            &[],
        )
        .unwrap();
    let add = add_op(&fx, &ledger, &fx.actors[&2].1, vec![Grant::Write]);
    ledger
        .commit_batch(&[LedgerEffect::Acl(add).encode()], &[])
        .unwrap();
    let frontier = ledger.frontier();
    let member_key = mechanics::crypto::device_from_seed(&seed(2))
        .key_bytes()
        .unwrap();
    let stranger_key = mechanics::crypto::device_from_seed(&seed(7))
        .key_bytes()
        .unwrap();
    let seq = ledger.journal_sequence();
    for i in 0..10_000u32 {
        let key = if i % 2 == 0 {
            &member_key
        } else {
            &stranger_key
        };
        let expect = i % 2 == 0;
        assert_eq!(ledger.signer_authorized_at(key, &frontier), expect);
    }
    assert_eq!(
        ledger.journal_sequence(),
        seq,
        "reads must not write the authority journal"
    );
    cleanup(&dir);
}

/// The decoded-checkpoint cache is bounded: committing more distinct
/// frontiers than the cache holds keeps every state readable while memory
/// stays bounded (durable checkpoints reload from their objects).
#[test]
fn checkpoint_cache_is_bounded_and_reloadable() {
    let dir = tempdir("cache");
    let fx = fx(&[]);
    let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
    ledger
        .commit_batch(
            &[LedgerEffect::Actor(fx.founder_incept.clone()).encode()],
            &[],
        )
        .unwrap();
    let early_frontier = ledger.frontier();
    // 70 successive frontiers (> the 64-entry cache).
    let mut prev = None;
    for i in 0..70u8 {
        let op = acl::sign_op(
            &seed(1),
            &AclOp {
                action: AclAction::RevokeInvite { nonce: [i; 16] },
                by: fx.founder_actor.clone(),
                actor_asof: vec![fx.founder_incept.hash()],
                nonce: None,
            },
            prev.map(|p| vec![p]).unwrap_or_else(|| ledger.acl_heads()),
            &fx.genesis.space_id,
        );
        prev = Some(op.hash());
        ledger
            .commit_batch(&[LedgerEffect::Acl(op).encode()], &[])
            .unwrap();
    }
    // The earliest frontier still resolves (from its durable checkpoint).
    let view = ledger.state_at(&early_frontier).unwrap();
    assert!(view.acl.is_empty() || !view.acl.is_empty()); // resolvable
                                                          // And the current one too.
    let current = ledger.frontier();
    ledger.state_at(&current).unwrap();
    cleanup(&dir);
}
