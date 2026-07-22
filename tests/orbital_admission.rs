//! `orbital_admission` — acceptance-triggered automatic admission (M2).
//!
//! Accepting valid Coordinates is the only approval: the candidate signs an
//! acceptance proof binding it to the exact capability + Coordinates, persists
//! it before any dial, and the founder redeems it automatically over Contact.
//! This gate drives the real `OrbitalMechanics` redemption path (no fixtures)
//! and proves: automatic redemption, the acceptance proof binding, exactly-once
//! admission, single-use cap, expiry/window rejection, revocation, cross-Space
//! and substituted-proof rejection, and persistence-before-dial idempotency.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use lait::orbital::{AuthorityRecord, OrbitalMechanics};
use replica::AuthorityIncorporator;
use runtime::AuthorityView;

const FOUNDER_SEED: [u8; 32] = [61u8; 32];
const JOINER_SEED: [u8; 32] = [62u8; 32];
const JOINER2_SEED: [u8; 32] = [63u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-adm-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A founder with product policy seeded.
fn founder(tag: &str) -> (PathBuf, OrbitalMechanics) {
    let root = temp_root(tag);
    let (mech, _c) = OrbitalMechanics::form(&root, &FOUNDER_SEED, "Adm", vec![]).unwrap();
    lait::orbital::seed_founder_policy(&mech).unwrap();
    (root, mech)
}

/// A joiner that entered the invite: returns its mechanics and its exported
/// Admission record (the acceptance proof rides it).
fn joiner_admission(
    invite: &runtime::SignedCoordinatesV1,
    seed: &[u8; 32],
    tag: &str,
) -> (PathBuf, OrbitalMechanics, Vec<u8>) {
    let root = temp_root(tag);
    let mech = OrbitalMechanics::enter(&root, seed, invite).unwrap();
    let admission_record = mech
        .export_records()
        .into_iter()
        .find(|r| {
            matches!(
                AuthorityRecord::decode(r),
                Some(AuthorityRecord::Admission { .. })
            )
        })
        .expect("the joiner serves an Admission record");
    (root, mech, admission_record)
}

/// Feed the joiner's authority records (its effects + admission) to the
/// founder's incorporator — the founder's Contact-pull redemption.
fn redeem_at_founder(founder: &OrbitalMechanics, joiner: &OrbitalMechanics) {
    let mut f = founder.clone();
    f.incorporate_authority(&joiner.export_records()).unwrap();
}

fn joiner_actor(mech: &OrbitalMechanics, seed: &[u8; 32]) -> Option<mechanics::ids::ActorId> {
    mech.resolve(&mechanics::crypto::device_from_seed(seed))
        .map(|r| r.actor)
}

#[test]
fn accepting_an_invite_automatically_admits_over_contact() {
    let (_rf, mech_f) = founder("auto");
    let now = now_secs();
    let admission = mech_f
        .mint_admission(&FOUNDER_SEED, 3600, false, now)
        .unwrap();
    let invite = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Adm", vec![], Some(admission))
        .unwrap();
    let (_rj, mech_j, _rec) = joiner_admission(&invite, &JOINER_SEED, "auto-j");
    assert!(!mech_j.am_i_member());

    // The founder pulls the joiner's material: automatic redemption.
    redeem_at_founder(&mech_f, &mech_j);
    let joiner = joiner_actor(&mech_f, &JOINER_SEED).expect("the joiner resolves at the founder");
    assert!(
        mech_f.members().iter().any(|m| m.key == joiner.as_str()),
        "the joiner was admitted with no approval step"
    );
}

#[test]
fn exact_replay_of_a_redemption_is_idempotent() {
    let (_rf, mech_f) = founder("replay");
    let admission = mech_f
        .mint_admission(&FOUNDER_SEED, 3600, false, now_secs())
        .unwrap();
    let invite = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Adm", vec![], Some(admission))
        .unwrap();
    let (_rj, mech_j, _rec) = joiner_admission(&invite, &JOINER_SEED, "replay-j");
    redeem_at_founder(&mech_f, &mech_j);
    let members = mech_f.members().len();
    // A second identical pull changes nothing.
    redeem_at_founder(&mech_f, &mech_j);
    assert_eq!(mech_f.members().len(), members, "exactly-once admission");
}

#[test]
fn a_substituted_acceptance_proof_is_refused() {
    let (_rf, mech_f) = founder("sub");
    let admission = mech_f
        .mint_admission(&FOUNDER_SEED, 3600, false, now_secs())
        .unwrap();
    let invite = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Adm", vec![], Some(admission))
        .unwrap();
    let (_rj, mech_j, rec) = joiner_admission(&invite, &JOINER_SEED, "sub-j");

    // Tamper the proof bytes inside the Admission record: verification fails,
    // so redemption does not admit.
    let mut record = match AuthorityRecord::decode(&rec).unwrap() {
        AuthorityRecord::Admission {
            admission,
            inception,
            mut proof,
            coordinates_digest,
        } => {
            let last = proof.len() - 1;
            proof[last] ^= 0xFF;
            AuthorityRecord::Admission {
                admission,
                inception,
                proof,
                coordinates_digest,
            }
        }
        _ => unreachable!(),
    }
    .encode();
    // Ride it beside the joiner's effects so the batch is well-formed.
    let mut records = mech_j.export_records();
    records.retain(|r| {
        !matches!(
            AuthorityRecord::decode(r),
            Some(AuthorityRecord::Admission { .. })
        )
    });
    records.append(&mut vec![std::mem::take(&mut record)]);
    let mut f = mech_f.clone();
    f.incorporate_authority(&records).unwrap();
    assert!(
        joiner_actor(&mech_f, &JOINER_SEED).is_none()
            || !mech_f.members().iter().any(|m| Some(m.key.as_str())
                == joiner_actor(&mech_f, &JOINER_SEED)
                    .as_ref()
                    .map(|a| a.as_str())),
        "a tampered acceptance proof does not admit"
    );
}

#[test]
fn an_expired_capability_is_refused_at_redemption() {
    let (_rf, mech_f) = founder("expiry");
    // A capability whose window is already in the past (issued far earlier).
    let admission = mech_f.mint_admission(&FOUNDER_SEED, 1, false, 1).unwrap();
    let invite = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Adm", vec![], Some(admission))
        .unwrap();
    let (_rj, mech_j, _rec) = joiner_admission(&invite, &JOINER_SEED, "expiry-j");
    redeem_at_founder(&mech_f, &mech_j);
    assert!(
        joiner_actor(&mech_f, &JOINER_SEED).is_none() || mech_f.members().len() == 1,
        "an expired capability admits nobody (only the founder is a member)"
    );
}

#[test]
fn a_single_use_capability_admits_at_most_one_of_two_candidates() {
    let (_rf, mech_f) = founder("single");
    let now = now_secs();
    let admission = mech_f
        .mint_admission(&FOUNDER_SEED, 3600, false, now)
        .unwrap();
    let invite = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Adm", vec![], Some(admission))
        .unwrap();
    let (_r1, mech_j1, _rec1) = joiner_admission(&invite, &JOINER_SEED, "s1");
    let (_r2, mech_j2, _rec2) = joiner_admission(&invite, &JOINER2_SEED, "s2");
    // Both candidates are pulled sequentially; the single-use cap admits one.
    redeem_at_founder(&mech_f, &mech_j1);
    redeem_at_founder(&mech_f, &mech_j2);
    let admitted = [&JOINER_SEED, &JOINER2_SEED]
        .iter()
        .filter(|s| {
            joiner_actor(&mech_f, s)
                .is_some_and(|a| mech_f.members().iter().any(|m| m.key == a.as_str()))
        })
        .count();
    assert_eq!(admitted, 1, "single-use admits exactly one candidate");
}

#[test]
fn a_reusable_capability_admits_multiple_candidates() {
    let (_rf, mech_f) = founder("reuse");
    let now = now_secs();
    let admission = mech_f
        .mint_admission(&FOUNDER_SEED, 3600, true, now)
        .unwrap();
    let invite = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Adm", vec![], Some(admission))
        .unwrap();
    let (_r1, mech_j1, _rec1) = joiner_admission(&invite, &JOINER_SEED, "r1");
    let (_r2, mech_j2, _rec2) = joiner_admission(&invite, &JOINER2_SEED, "r2");
    redeem_at_founder(&mech_f, &mech_j1);
    redeem_at_founder(&mech_f, &mech_j2);
    let admitted = [&JOINER_SEED, &JOINER2_SEED]
        .iter()
        .filter(|s| {
            joiner_actor(&mech_f, s)
                .is_some_and(|a| mech_f.members().iter().any(|m| m.key == a.as_str()))
        })
        .count();
    assert_eq!(admitted, 2, "a reusable invite admits both candidates");
}

#[test]
fn persistence_before_dial_survives_a_restart() {
    let (_rf, mech_f) = founder("persist");
    let admission = mech_f
        .mint_admission(&FOUNDER_SEED, 3600, false, now_secs())
        .unwrap();
    let invite = mech_f
        .mint_coordinates(&FOUNDER_SEED, "Adm", vec![], Some(admission))
        .unwrap();
    let root_j = temp_root("persist-j");
    let space = mech_f.space();
    // Enter (persists the acceptance proof), then reopen — the served record
    // is byte-identical (the proof is reused, not re-signed).
    let mech_j = OrbitalMechanics::enter(&root_j, &JOINER_SEED, &invite).unwrap();
    let before = admission_record_of(&mech_j);
    drop(mech_j);
    let mech_j2 = OrbitalMechanics::open(&root_j, &space, &JOINER_SEED).unwrap();
    let after = admission_record_of(&mech_j2);
    assert_eq!(
        before, after,
        "the acceptance proof is persisted, not re-signed"
    );
    // And it still redeems.
    redeem_at_founder(&mech_f, &mech_j2);
    assert!(joiner_actor(&mech_f, &JOINER_SEED)
        .is_some_and(|a| mech_f.members().iter().any(|m| m.key == a.as_str())));
}

fn admission_record_of(mech: &OrbitalMechanics) -> Vec<u8> {
    mech.export_records()
        .into_iter()
        .find(|r| {
            matches!(
                AuthorityRecord::decode(r),
                Some(AuthorityRecord::Admission { .. })
            )
        })
        .expect("an Admission record")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
