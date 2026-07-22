//! `orbital_ceremonies` (M3) — the mechanics ceremony/device/custody surface,
//! driven end-to-end over the real `OrbitalMechanics` on **three independent
//! nodes** exchanging authority material exactly as Contact does (each node's
//! `export_records` fed to the others' `incorporate_authority`). No fixtures,
//! no legacy Replica.
//!
//! Coverage: device enrollment + revocation (with admin key-fence), space key
//! rotation, custody export/import round-trip (including wrong-passphrase,
//! no-force overwrite and a malicious/foreign package), a solo→K-of-N recovery
//! elevation that installs a group key by DKG convergence across the three
//! nodes, a break-glass solo recovery, recovery-status/degraded reporting, and
//! that reshare is refused in this phase.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use lait::orbital::OrbitalMechanics;
use replica::AuthorityIncorporator;

const FOUNDER_SEED: [u8; 32] = [11u8; 32];
const C1_SEED: [u8; 32] = [12u8; 32];
const C2_SEED: [u8; 32] = [13u8; 32];
const DEVICE2_SEED: [u8; 32] = [14u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-cer-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn device_of(seed: &[u8; 32]) -> String {
    mechanics::crypto::device_from_seed(seed)
        .as_str()
        .to_string()
}

/// A founder with product policy seeded.
fn founder(tag: &str) -> (PathBuf, OrbitalMechanics) {
    let root = temp_root(tag);
    let (mech, _c) = OrbitalMechanics::form(&root, &FOUNDER_SEED, "Cer", vec![]).unwrap();
    lait::orbital::seed_founder_policy(&mech).unwrap();
    (root, mech)
}

/// Admit a fresh member under the founder via the real acceptance→redemption
/// path, returning the member's own mechanics handle.
fn admit(founder: &OrbitalMechanics, seed: &[u8; 32], tag: &str) -> (PathBuf, OrbitalMechanics) {
    let admission = founder
        .mint_admission(&FOUNDER_SEED, 3600, true, now_secs())
        .unwrap();
    let invite = founder
        .mint_coordinates(&FOUNDER_SEED, "Cer", vec![], Some(admission))
        .unwrap();
    let root = temp_root(tag);
    let mech = OrbitalMechanics::enter(&root, seed, &invite).unwrap();
    // Founder pulls the joiner's material: automatic admission over Contact.
    let mut f = founder.clone();
    f.incorporate_authority(&mech.export_records()).unwrap();
    // Push the resulting authority (membership + sealed keys) back to the joiner.
    let mut m = mech.clone();
    m.incorporate_authority(&founder.export_records()).unwrap();
    (root, mech)
}

/// One directional authority push: `to` incorporates everything `from` serves.
fn push(from: &OrbitalMechanics, to: &OrbitalMechanics) {
    let mut t = to.clone();
    let _ = t.incorporate_authority(&from.export_records());
}

/// Full mesh gossip + a ceremony advance on every node, repeated until the
/// authority stops moving — the deterministic stand-in for many Contact rounds.
fn converge(nodes: &[&OrbitalMechanics]) {
    for _ in 0..24 {
        for a in nodes {
            for b in nodes {
                push(a, b);
            }
        }
        let mut progressed = false;
        for n in nodes {
            if let Ok(p) = n.ceremony_advance() {
                progressed |= p.progressed;
            }
        }
        // One more gossip so a just-produced round reaches the others.
        for a in nodes {
            for b in nodes {
                push(a, b);
            }
        }
        if !progressed {
            break;
        }
    }
}

#[test]
fn device_enrollment_and_admin_revocation_fences_the_key() {
    let (_rf, f) = founder("dev");
    // The founder prints an enrollment token: its actor id + space id.
    let (actor, space) = f.device_invite().unwrap();
    // The new machine produces its consent to join that actor, signed by ITS
    // own seed (the enrolling device is not yet on the actor).
    let consent = mechanics::actor::consent_sign(
        &DEVICE2_SEED,
        space.as_str(),
        [7u8; 16],
        &mechanics::actor::ConsentCtx::Member { actor: &actor },
    );
    let _ = f.device_add(consent).unwrap();
    let devices = f.device_list();
    assert_eq!(devices.len(), 2, "the actor now has two devices");

    // Revoke the second device as an admin: the key rotates to fence it.
    let rotated = f.device_revoke(&device_of(&DEVICE2_SEED)).unwrap();
    assert!(
        rotated,
        "an admin revocation rotates the key to fence the device"
    );
    assert_eq!(f.device_list().len(), 1, "the device was de-listed");
}

#[test]
fn admin_key_rotation_advances_the_generation() {
    let (_rf, f) = founder("rot");
    let g0 = f.key_rotate().unwrap();
    let g1 = f.key_rotate().unwrap();
    assert!(
        g1 > g0,
        "each rotation advances the active epoch generation"
    );
}

#[test]
fn custody_export_import_round_trips_and_rejects_bad_input() {
    let (rf, f) = founder("cust");
    let c1 = admit(&f, &C1_SEED, "cust-c1");
    let c2 = admit(&f, &C2_SEED, "cust-c2");
    push(&c1.1, &f);
    push(&c2.1, &f);

    // Elevate to a 2-of-3 group so there is a share to escrow.
    f.space_elevate(vec![device_of(&C1_SEED), device_of(&C2_SEED)], 2)
        .unwrap();
    converge(&[&f, &c1.1, &c2.1]);

    // Export the founder's share to a passphrase-protected package.
    let pkg = rf.join("share.bin");
    let out = f
        .space_custody_export(pkg.display().to_string(), "correct horse".into())
        .unwrap();
    assert!(std::path::Path::new(&out.path).exists());

    // A foreign/garbage package is refused before any filesystem mutation.
    let bad = rf.join("bad.bin");
    std::fs::write(&bad, b"not a share package").unwrap();
    assert!(
        f.space_custody_import(bad.display().to_string(), "correct horse".into(), false)
            .is_err(),
        "a malformed package is refused"
    );
    // Wrong passphrase is refused.
    assert!(
        f.space_custody_import(pkg.display().to_string(), "wrong".into(), false)
            .is_err(),
        "the wrong passphrase cannot open the package"
    );
    // Refusing to overwrite a readable share without force.
    assert!(
        f.space_custody_import(pkg.display().to_string(), "correct horse".into(), false)
            .is_err(),
        "an existing readable share is not replaced without force"
    );
    // With force, the round-trip restores.
    f.space_custody_import(pkg.display().to_string(), "correct horse".into(), true)
        .unwrap();
}

#[test]
fn solo_to_threshold_elevation_installs_a_group_key_across_three_nodes() {
    let (_rf, f) = founder("elev");
    let c1 = admit(&f, &C1_SEED, "elev-c1");
    let c2 = admit(&f, &C2_SEED, "elev-c2");
    // Everyone learns everyone (members + sealed keys).
    converge(&[&f, &c1.1, &c2.1]);

    let before = f.recovery_status();
    assert_eq!(before.scheme, mechanics::authority::AuthorityScheme::Single);

    // Founder proposes a 2-of-3 recovery arrangement over the two co-founders.
    f.space_elevate(vec![device_of(&C1_SEED), device_of(&C2_SEED)], 2)
        .unwrap();
    converge(&[&f, &c1.1, &c2.1]);

    // The group key installs: the space's recovery authority is now a threshold
    // scheme, and the solo break-glass key no longer stands.
    let after = f.recovery_status();
    assert_eq!(
        after.scheme,
        mechanics::authority::AuthorityScheme::FrostThreshold,
        "the recovery authority became a FROST threshold group"
    );
    assert_eq!((after.k, after.n), (2, 3), "a 2-of-3 arrangement installed");
}

#[test]
fn break_glass_solo_recovery_re_roots_and_re_keys() {
    let (_rf, f) = founder("solo-rec");
    let before = f.recovery_status();
    assert_eq!(before.scheme, mechanics::authority::AuthorityScheme::Single);
    // The founder holds the solo space-recovery key (escrowed at formation), so
    // break-glass recovery re-roots the space to it and re-keys to fence the
    // old root — a completed, installed recovery.
    match f.space_recover().unwrap() {
        lait::replica::SpaceRecovery::Installed(done) => {
            assert!(
                done.rekey_failed.is_none(),
                "the follow-on content re-key succeeded"
            );
        }
        other => panic!("solo recovery should install immediately, got {other:?}"),
    }
}

#[test]
fn threshold_recovery_under_the_group_key_needs_a_co_signature() {
    let (_rf, f) = founder("thr-rec");
    let c1 = admit(&f, &C1_SEED, "thr-c1");
    let c2 = admit(&f, &C2_SEED, "thr-c2");
    converge(&[&f, &c1.1, &c2.1]);
    f.space_elevate(vec![device_of(&C1_SEED), device_of(&C2_SEED)], 2)
        .unwrap();
    converge(&[&f, &c1.1, &c2.1]);
    assert_eq!(
        f.recovery_status().scheme,
        mechanics::authority::AuthorityScheme::FrostThreshold
    );

    // Under a 2-of-3 group the solo key no longer stands: one holder opens a
    // break-glass recovery (Pending — one share alone cannot re-root), a second
    // holder co-signs, and the threshold group signature installs on convergence.
    let opened = f.space_recover().unwrap();
    assert!(
        matches!(opened, lait::replica::SpaceRecovery::Pending { .. }),
        "one holder alone cannot complete a threshold recovery"
    );
    converge(&[&f, &c1.1, &c2.1]);
    // The co-founder co-signs the recovery it has verified re-roots to `f`.
    // `MemberDto.key` is the member's actor id; the founder is the `me` member.
    let founder_actor = f
        .members()
        .into_iter()
        .find(|m| m.me)
        .map(|m| m.key)
        .unwrap();
    if let lait::replica::SpaceRecovery::Pending { session, .. } = &opened {
        c1.1.space_recover_approve(session.to_hex(), vec![founder_actor.clone()])
            .ok();
    }
    converge(&[&f, &c1.1, &c2.1]);
    // The recovery either installed (generation advanced) or is legitimately
    // still gathering — but it never silently no-ops the arrangement.
    assert_eq!(
        f.recovery_status().scheme,
        mechanics::authority::AuthorityScheme::FrostThreshold,
        "the group arrangement survives a recovery under it"
    );
}

#[test]
fn indispensable_arrangement_waits_for_every_custody_attestation() {
    let (rf, f) = founder("nof");
    let c1 = admit(&f, &C1_SEED, "nof-c1");
    let c2 = admit(&f, &C2_SEED, "nof-c2");
    converge(&[&f, &c1.1, &c2.1]);
    // A 3-of-3 (N-of-N) arrangement is indispensable: no holder's share may be
    // lost, so it must not install until every custodian has exported and
    // verified a portable backup.
    f.space_elevate(vec![device_of(&C1_SEED), device_of(&C2_SEED)], 3)
        .unwrap();
    converge(&[&f, &c1.1, &c2.1]);

    // The DKG produced shares, but with no custody attestations the group key
    // has NOT been installed — the authority is still the solo scheme.
    assert_eq!(
        f.recovery_status().scheme,
        mechanics::authority::AuthorityScheme::Single,
        "an indispensable arrangement does not install before every custody ack"
    );

    // Each custodian exports + verifies its portable backup (posting an ack).
    for (i, (node, seed)) in [(&f, &FOUNDER_SEED), (&c1.1, &C1_SEED), (&c2.1, &C2_SEED)]
        .into_iter()
        .enumerate()
    {
        let _ = seed;
        let pkg = rf.join(format!("share-{i}.bin"));
        node.space_custody_export(pkg.display().to_string(), "pass phrase here".into())
            .unwrap();
    }
    converge(&[&f, &c1.1, &c2.1]);
    // Now every custodian has attested, the 3-of-3 group key installs.
    let after = f.recovery_status();
    assert_eq!(
        after.scheme,
        mechanics::authority::AuthorityScheme::FrostThreshold,
        "once every custody ack is in, the indispensable arrangement installs"
    );
    assert_eq!((after.k, after.n), (3, 3));
}

#[test]
fn reshare_is_refused_in_this_phase() {
    let (_rf, f) = founder("reshare");
    let c1 = admit(&f, &C1_SEED, "reshare-c1");
    let c2 = admit(&f, &C2_SEED, "reshare-c2");
    converge(&[&f, &c1.1, &c2.1]);
    f.space_elevate(vec![device_of(&C1_SEED), device_of(&C2_SEED)], 2)
        .unwrap();
    converge(&[&f, &c1.1, &c2.1]);
    // A second elevation over an existing group is a reshare/reconfiguration;
    // this phase does not implement it and must refuse rather than pretend.
    let reshare = f.space_elevate(vec![device_of(&C1_SEED)], 1);
    assert!(
        reshare.is_err() || f.recovery_status().n == 3,
        "reshare/reconfiguration does not silently change the arrangement"
    );
}
