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
const C3_SEED: [u8; 32] = [15u8; 32];

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
        .mint_admission(
            &FOUNDER_SEED,
            3600,
            true,
            now_secs(),
            "contributor",
            [0u8; 32],
        )
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
        mechanics::ceremony::SpaceRecovery::Installed(done) => {
            assert!(
                done.rekey_failed.is_none(),
                "the follow-on content re-key succeeded"
            );
        }
        other => panic!("solo recovery should install immediately, got {other:?}"),
    }
}

#[test]
fn threshold_recovery_installs_the_exact_root_and_fences_the_old_epoch() {
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
    let (state, terminal_before) = f.space_root_state();
    assert_eq!(state.gen, 1, "the elevation's Rotate advanced to gen 1");
    assert_eq!(
        terminal_before, 1,
        "the elevation emitted exactly one terminal effect"
    );

    // Under a 2-of-3 group the solo key no longer stands: c1 opens a
    // break-glass recovery re-rooting the space to ITSELF (Pending — one
    // share alone cannot re-root), the founder co-signs, and the threshold
    // group signature installs on convergence.
    let opened = c1.1.space_recover().unwrap();
    let session = match &opened {
        mechanics::ceremony::SpaceRecovery::Pending { session, .. } => *session,
        other => panic!("one holder alone cannot complete a threshold recovery: {other:?}"),
    };
    converge(&[&f, &c1.1, &c2.1]);
    // The founder co-signs the recovery it has verified re-roots to c1.
    let c1_actor = c1.1.my_actor().unwrap();
    let approved = f
        .space_recover_approve(session.to_hex(), vec![c1_actor.as_str().to_string()])
        .expect("the co-signature must succeed");
    assert_eq!(
        approved.roots,
        vec![c1_actor.clone()],
        "consent bound to the exact root"
    );
    converge(&[&f, &c1.1, &c2.1]);

    // Terminal state, exactly: the recovery installed the EXACT root at the
    // EXACT next generation with exactly one more terminal effect, on every
    // node.
    for node in [&f, &c1.1, &c2.1] {
        let (state, terminal) = node.space_root_state();
        assert!(state.recovered, "the transcript completed and installed");
        assert_eq!(state.gen, 2, "exact generation advance");
        assert_eq!(
            state.root,
            vec![c1_actor.clone()],
            "the space re-rooted to exactly the approved actor"
        );
        assert_eq!(
            terminal, 2,
            "a successful transcript emits exactly ONE terminal SpaceAuthority effect"
        );
    }
    // The group arrangement survives a recovery under it.
    assert_eq!(
        c1.1.recovery_status().scheme,
        mechanics::authority::AuthorityScheme::FrostThreshold
    );
    // Re-key: the new root is the sole admin and holds a usable active epoch
    // (rotating from it succeeds); the OLD root is fenced — no longer a
    // member, cannot author authority.
    assert!(c1.1.am_i_admin(), "the recovered root holds admin standing");
    c1.1.key_rotate()
        .expect("the new root re-keyed (active epoch usable)");
    assert!(
        !f.am_i_member(),
        "the old root is fenced by the re-root: its ops no longer authorize"
    );
    // Old-epoch rejection post-install: the fenced founder cannot author.
    assert!(
        f.key_rotate().is_err(),
        "the fenced root cannot rotate the key"
    );

    // Durable restart result: reopen c1's store cold; the exact terminal
    // state — root, generation, effect count — survives.
    let space = c1.1.space();
    let reopened = OrbitalMechanics::open(&c1.0, &space, &C1_SEED).unwrap();
    let (state, terminal) = reopened.space_root_state();
    assert_eq!((state.gen, terminal), (2, 2));
    assert_eq!(state.root, vec![c1_actor]);
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
fn resharing_replaces_a_participant_without_changing_the_key() {
    let (_rf, f) = founder("reshare");
    let c1 = admit(&f, &C1_SEED, "reshare-c1");
    let c2 = admit(&f, &C2_SEED, "reshare-c2");
    let c3 = admit(&f, &C3_SEED, "reshare-c3");
    converge(&[&f, &c1.1, &c2.1, &c3.1]);
    f.space_elevate(vec![device_of(&C1_SEED), device_of(&C2_SEED)], 2)
        .unwrap();
    converge(&[&f, &c1.1, &c2.1, &c3.1]);
    let before = f.recovery_status();
    assert_eq!(
        (before.scheme, before.k, before.n),
        (mechanics::authority::AuthorityScheme::FrostThreshold, 2, 3)
    );
    let standing_key = before.authority.clone().expect("standing authority known");
    let (state_before, terminal_before) = f.space_root_state();

    // Same-key reshare: replace c2 with c3 in the holder set. The proposer's
    // grant needs the standing group's threshold, so c1 co-signs it.
    let reshare = f
        .space_reshare(
            vec![
                device_of(&FOUNDER_SEED),
                device_of(&C1_SEED),
                device_of(&C3_SEED),
            ],
            2,
        )
        .unwrap();
    converge(&[&f, &c1.1, &c2.1, &c3.1]);
    let grant_session = reshare
        .grant_request
        .expect("a group authority needs a grant");
    c1.1.space_elevate_approve(grant_session.to_hex(), reshare.proposal.to_hex())
        .expect("a holder co-signs the reshare authorization");
    converge(&[&f, &c1.1, &c2.1, &c3.1]);

    // Installed: the arrangement moved, the KEY did not.
    let after = f.recovery_status();
    assert_eq!(
        (after.scheme, after.k, after.n),
        (mechanics::authority::AuthorityScheme::FrostThreshold, 2, 3),
        "the reshared 2-of-3 arrangement installed"
    );
    assert_eq!(
        after.authority.as_deref(),
        Some(standing_key.as_str()),
        "a reshare NEVER changes the recovery key"
    );
    let (state_after, terminal_after) = f.space_root_state();
    assert_eq!(
        state_after.recovery_commit, state_before.recovery_commit,
        "the on-plane key commitment is unchanged"
    );
    assert_ne!(
        state_after.configuration, state_before.configuration,
        "the on-plane arrangement changed"
    );
    assert_eq!(
        state_after.gen,
        state_before.gen + 1,
        "exact generation advance"
    );
    assert_eq!(
        terminal_after,
        terminal_before + 1,
        "a successful reshare emits exactly ONE terminal SpaceAuthority effect"
    );

    // The REPLACEMENT holder is a working custodian under the same key: c3
    // co-signs a threshold recovery that installs.
    let opened = c1.1.space_recover().unwrap();
    let session = match &opened {
        mechanics::ceremony::SpaceRecovery::Pending { session, .. } => *session,
        other => panic!("threshold recovery still needs a co-signature: {other:?}"),
    };
    converge(&[&f, &c1.1, &c2.1, &c3.1]);
    let c1_actor = c1.1.my_actor().unwrap();
    c3.1.space_recover_approve(session.to_hex(), vec![c1_actor.as_str().to_string()])
        .expect("the replacement holder's share works under the reshared arrangement");
    converge(&[&f, &c1.1, &c2.1, &c3.1]);
    let (state, _) = c1.1.space_root_state();
    assert!(state.recovered, "the reshared group completed a recovery");
    assert_eq!(state.root, vec![c1_actor]);
}

#[test]
fn an_offline_participant_resumes_and_completes_an_elevation() {
    let (_rf, f) = founder("offline");
    let c1 = admit(&f, &C1_SEED, "offline-c1");
    let c2 = admit(&f, &C2_SEED, "offline-c2");
    converge(&[&f, &c1.1, &c2.1]);
    f.space_elevate(vec![device_of(&C1_SEED), device_of(&C2_SEED)], 2)
        .unwrap();
    // c2 is OFFLINE for the whole first phase: the DKG cannot complete
    // (round 1 needs all N), so nothing installs.
    converge(&[&f, &c1.1]);
    assert_eq!(
        f.recovery_status().scheme,
        mechanics::authority::AuthorityScheme::Single,
        "an elevation cannot install while a participant is offline"
    );
    // c2 comes back: the ceremony resumes from the durable board and installs.
    converge(&[&f, &c1.1, &c2.1]);
    assert_eq!(
        f.recovery_status().scheme,
        mechanics::authority::AuthorityScheme::FrostThreshold,
        "the offline participant resumed and the elevation completed"
    );
}

#[test]
fn a_cold_restart_mid_ceremony_resumes_without_regenerating_material() {
    let (rf, f) = founder("restart");
    let c1 = admit(&f, &C1_SEED, "restart-c1");
    let c2 = admit(&f, &C2_SEED, "restart-c2");
    converge(&[&f, &c1.1, &c2.1]);
    f.space_elevate(vec![device_of(&C1_SEED), device_of(&C2_SEED)], 2)
        .unwrap();
    // One partial exchange, then EVERY node cold-restarts (drop + reopen from
    // disk). The persisted phase state must resume — a regenerated round-1
    // package would break the DKG (other participants bound to the first).
    for a in [&f, &c1.1, &c2.1] {
        for b in [&f, &c1.1, &c2.1] {
            push(a, b);
        }
    }
    for n in [&f, &c1.1, &c2.1] {
        let _ = n.ceremony_advance();
    }
    let space = f.space();
    drop(f);
    let f = OrbitalMechanics::open(&rf, &space, &FOUNDER_SEED).unwrap();
    let c1m = {
        let (root, m) = c1;
        drop(m);
        OrbitalMechanics::open(&root, &space, &C1_SEED).unwrap()
    };
    let c2m = {
        let (root, m) = c2;
        drop(m);
        OrbitalMechanics::open(&root, &space, &C2_SEED).unwrap()
    };
    converge(&[&f, &c1m, &c2m]);
    let after = f.recovery_status();
    assert_eq!(
        after.scheme,
        mechanics::authority::AuthorityScheme::FrostThreshold,
        "the ceremony resumed across a cold restart of every node"
    );
    assert_eq!((after.k, after.n), (2, 3));
}
