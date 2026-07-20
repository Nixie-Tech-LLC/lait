//! Agreement test at the **transport seam**: lait's identity model and iroh's
//! keypair must be the same ed25519 pair over the same 32-byte seed.
//!
//! This is the executable form of the claim `config`/`ids` rely on — a lait
//! `DeviceId` *is* the iroh `EndpointId`, so a box sealed to a member opens for the
//! device that holds the corresponding transport secret. It lives here, at the
//! seam (where iroh is named), not in the kernel: the kernel defines identity in
//! its own terms; this pins that iroh honors the same definition. If a future
//! iroh changes its key encoding, THIS test breaks — not the kernel.

use ed25519_dalek::SigningKey;
use lait::crypto::{device_from_seed, open_sealed, random_key, seal_to};
use lait::ids::DeviceId;

#[test]
fn iroh_keypair_is_the_same_ed25519_pair_as_a_lait_seed() {
    let seed = [5u8; 32];

    // iroh's SecretKey over the seed …
    let sk = iroh::SecretKey::from_bytes(&seed);
    // … its public key, as lait would read it off the wire …
    let from_iroh = DeviceId::from_key_string(sk.public().to_string());
    // … must equal both the raw ed25519 verifying key and lait's own derivation.
    let vk = SigningKey::from_bytes(&seed).verifying_key();
    assert_eq!(
        from_iroh.as_str(),
        data_encoding::HEXLOWER.encode(vk.as_bytes()),
        "iroh's pubkey must be a standard ed25519 verifying key"
    );
    assert_eq!(
        from_iroh,
        device_from_seed(&seed),
        "iroh's identity must equal lait's seed-derived DeviceId"
    );
    assert_eq!(sk.to_bytes(), seed, "iroh's secret bytes must be the seed");

    // And a box sealed to that DeviceId opens for the holder of the seed.
    let key = random_key();
    let sealed = seal_to(&from_iroh, &key).expect("seal to iroh-derived device");
    assert_eq!(
        open_sealed(&seed, &from_iroh, &sealed).as_deref(),
        Some(&key[..]),
        "an iroh-keyed member must open a box sealed to their DeviceId"
    );
}
