//! FROST ↔ sigdag interop spike (W5 threshold-recovery gate).
//!
//! The threshold-recovery design rests on one premise: a FROST-Ed25519 group
//! signature verifies under the SAME `ed25519_dalek` verification our
//! `sigdag::SignedNode` uses, so a recovery authorized by a threshold of holders
//! is just a normal Ed25519-signed op with the group public key as its author —
//! no changes to signature verification, and the N holders/threshold never on the
//! wire (set privacy for free). These tests prove the premise for BOTH keygen
//! paths: trusted-dealer (a stand-in) and the real dealer-free DKG (the mechanism
//! we'll actually use), each ending in an `ed25519_dalek` verification.

use std::collections::BTreeMap;

use ed25519_dalek::Verifier;
use frost_ed25519 as frost;
use frost_ed25519::Identifier;

/// Threshold-sign `message` with the first `min` of the group's key packages and
/// return `(group_pubkey_bytes, signature_bytes)` — the raw 32/64-byte forms our
/// sigdag would consume. Runs FROST's two signing rounds.
fn group_sign(
    key_packages: &BTreeMap<Identifier, frost::keys::KeyPackage>,
    pubkey_package: &frost::keys::PublicKeyPackage,
    min: u16,
    message: &[u8],
) -> ([u8; 32], [u8; 64]) {
    let mut rng = rand_core::OsRng;
    let signers: Vec<Identifier> = key_packages.keys().copied().take(min as usize).collect();

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &signers {
        let (n, c) = frost::round1::commit(key_packages[id].signing_share(), &mut rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let signing_package = frost::SigningPackage::new(commitments, message);
    let mut sig_shares = BTreeMap::new();
    for id in &signers {
        let share = frost::round2::sign(&signing_package, &nonces[id], &key_packages[id])
            .expect("round2 sign");
        sig_shares.insert(*id, share);
    }
    let group_sig =
        frost::aggregate(&signing_package, &sig_shares, pubkey_package).expect("aggregate");

    // FROST's own verifier accepts it (sanity).
    assert!(pubkey_package
        .verifying_key()
        .verify(message, &group_sig)
        .is_ok());

    let pk: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .expect("serialize group key")
        .try_into()
        .expect("32-byte ed25519 public key");
    let sig: [u8; 64] = group_sig
        .serialize()
        .expect("serialize signature")
        .try_into()
        .expect("64-byte ed25519 signature");
    (pk, sig)
}

/// Verify a `(pubkey, sig)` over `message` through the exact path our sigdag uses
/// (`ed25519_dalek::Verifier::verify`), and confirm a different message fails.
fn assert_verifies_as_ed25519(pk: [u8; 32], sig: [u8; 64], message: &[u8]) {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).expect("dalek verifying key");
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    assert!(
        vk.verify(message, &sig).is_ok(),
        "FROST group signature must verify under ed25519_dalek::Verifier::verify (sigdag path)"
    );
    assert!(
        vk.verify(b"a different message", &sig).is_err(),
        "verification must be message-bound"
    );
    // Non-load-bearing (sigdag uses non-strict), but record the ZIP-215 result.
    println!(
        "verify_strict (ZIP-215): {}",
        vk.verify_strict(message, &sig).is_ok()
    );
}

#[test]
fn a_trusted_dealer_group_signature_verifies_as_ed25519() {
    let rng = rand_core::OsRng;
    let (shares, pubkey_package) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
            .expect("keygen");
    let key_packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, ss)| {
            (
                id,
                frost::keys::KeyPackage::try_from(ss).expect("key package"),
            )
        })
        .collect();

    let message = b"lait/space/1/event: Recover{new_root, gen}";
    let (pk, sig) = group_sign(&key_packages, &pubkey_package, 2, message);
    assert_verifies_as_ed25519(pk, sig, message);
}

#[test]
fn a_dkg_group_signature_verifies_as_ed25519() {
    // The real mechanism: dealer-free distributed key generation among 3 holders,
    // no party ever holding the group secret. Then a 2-of-3 threshold sign whose
    // aggregate verifies as a plain Ed25519 signature — exactly what a `Recover`
    // authored by the group key would be on our plane.
    let rng = rand_core::OsRng;
    let (max, min) = (3u16, 2u16);
    let ids: Vec<Identifier> = (1..=max)
        .map(|i| Identifier::try_from(i).expect("identifier"))
        .collect();

    // --- round 1: each participant broadcasts a round1 package ---
    let mut r1_secrets = BTreeMap::new();
    let mut r1_packages = BTreeMap::new();
    for id in &ids {
        let (secret, pkg) = frost::keys::dkg::part1(*id, max, min, rng).expect("dkg part1");
        r1_secrets.insert(*id, secret);
        r1_packages.insert(*id, pkg);
    }

    // --- round 2: each produces targeted round2 packages for the others ---
    let others_r1 = |me: &Identifier| -> BTreeMap<Identifier, frost::keys::dkg::round1::Package> {
        r1_packages
            .iter()
            .filter(|(k, _)| *k != me)
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    };
    let mut r2_secrets = BTreeMap::new();
    let mut r2_inbox: BTreeMap<
        Identifier,
        BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
    > = ids.iter().map(|id| (*id, BTreeMap::new())).collect();
    for id in &ids {
        let (secret2, outgoing) =
            frost::keys::dkg::part2(r1_secrets.remove(id).unwrap(), &others_r1(id))
                .expect("dkg part2");
        r2_secrets.insert(*id, secret2);
        for (recipient, pkg) in outgoing {
            r2_inbox.get_mut(&recipient).unwrap().insert(*id, pkg);
        }
    }

    // --- round 3: each computes its key package + the shared group public key ---
    let mut key_packages = BTreeMap::new();
    let mut group: Option<frost::keys::PublicKeyPackage> = None;
    for id in &ids {
        let (kp, pubkey_package) =
            frost::keys::dkg::part3(&r2_secrets[id], &others_r1(id), &r2_inbox[id])
                .expect("dkg part3");
        // Every participant must derive the identical group public key.
        if let Some(prev) = &group {
            assert_eq!(prev, &pubkey_package, "all holders agree on the group key");
        }
        group = Some(pubkey_package);
        key_packages.insert(*id, kp);
    }
    let pubkey_package = group.unwrap();

    let message = b"lait/space/1/event: Recover via DKG group key";
    let (pk, sig) = group_sign(&key_packages, &pubkey_package, min, message);
    assert_verifies_as_ed25519(pk, sig, message);
}
