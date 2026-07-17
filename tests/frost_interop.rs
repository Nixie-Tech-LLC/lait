//! FROST ↔ sigdag interop spike (W5 threshold-recovery gate).
//!
//! The whole threshold-recovery design rests on one premise: a FROST-Ed25519
//! group signature verifies under the SAME `ed25519_dalek` verification our
//! `sigdag::SignedNode` uses, so a recovery authorized by a threshold of holders
//! is just a normal Ed25519-signed op with the group public key as its author —
//! no changes to signature verification, and the N holders/threshold never on the
//! wire. This test proves (or refutes) that premise before anything is built on
//! it. It also characterises the strict-vs-non-strict caveat (RFC 8032 `verify`
//! vs ZIP-215 `verify_strict`).

use std::collections::BTreeMap;

use ed25519_dalek::Verifier;
use frost_ed25519 as frost;

#[test]
fn a_frost_group_signature_verifies_as_a_plain_ed25519_signature() {
    let mut rng = rand_core::OsRng;

    // --- dealer key-gen for a 2-of-3 group (a stand-in for DKG; same outputs) ---
    let (shares, pubkey_package) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
            .expect("keygen");
    let key_packages: BTreeMap<_, frost::keys::KeyPackage> = shares
        .into_iter()
        .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).expect("key package")))
        .collect();

    // The message is exactly the kind of bytes our sigdag signs over.
    let message = b"lait/space/1/event: Recover{new_root, gen} test payload";

    // --- pick 2 of the 3 signers and run the two FROST rounds ---
    let signers: Vec<_> = key_packages.keys().copied().take(2).collect();

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
        frost::aggregate(&signing_package, &sig_shares, &pubkey_package).expect("aggregate");

    // FROST's own verifier accepts it (sanity).
    assert!(pubkey_package
        .verifying_key()
        .verify(message, &group_sig)
        .is_ok());

    // --- the load-bearing check: verify with ed25519_dalek, our sigdag's path ---
    let pk_bytes: [u8; 32] = pubkey_package
        .verifying_key()
        .serialize()
        .expect("serialize group key")
        .try_into()
        .expect("32-byte ed25519 public key");
    let sig_bytes: [u8; 64] = group_sig
        .serialize()
        .expect("serialize signature")
        .try_into()
        .expect("64-byte ed25519 signature");

    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).expect("dalek verifying key");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

    // `verify` is RFC 8032 (what `SignedNode::verify_sig` calls). This MUST pass —
    // it is the entire premise of using a FROST group key as an op author.
    assert!(
        vk.verify(message, &sig).is_ok(),
        "FROST group signature must verify under ed25519_dalek::Verifier::verify (our sigdag path)"
    );

    // Characterise the strict path (ZIP-215) for the record — not load-bearing,
    // since our sigdag uses non-strict `verify`, but worth knowing.
    let strict = vk.verify_strict(message, &sig).is_ok();
    println!("FROST sig under ed25519_dalek::verify_strict (ZIP-215): {strict}");

    // A different message must NOT verify (guards against a trivial always-true).
    assert!(vk.verify(b"a different message", &sig).is_err());
}
