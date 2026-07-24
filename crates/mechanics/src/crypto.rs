//! End-to-end encryption primitives. All pure Rust (RustCrypto/dalek), no C toolchain,
//! no `aws-lc` — respecting the portability + supply-chain bans.
//!
//! - **AEAD**: ChaCha20-Poly1305 with the 32-byte space symmetric key. Sync
//!   payloads (catalog + issue-doc `export()` bytes) are sealed with this, so a
//!   blind relay or a non-member sees only ciphertext (the "encryption *is* the
//!   access control" posture).
//! - **Sealed box**: an anonymous X25519 + AEAD box that distributes the
//!   space key to a member addressed by their ed25519 `DeviceId`. The member's
//!   ed25519 identity is converted to X25519 (libsodium's `*_to_curve25519`).
//!
//! # Security status
//!
//! This composition has not received an independent cryptographic audit. Do not
//! treat it as suitable for high-sensitivity production data until that review
//! is complete.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

use crate::ids::DeviceId;

/// The space symmetric key length (ChaCha20-Poly1305).
pub const KEY_LEN: usize = 32;
/// A space symmetric key.
pub type SpaceKey = [u8; KEY_LEN];
const NONCE_LEN: usize = 12;

/// A fresh random 32-byte space key.
pub fn random_key() -> SpaceKey {
    let mut k = [0u8; KEY_LEN];
    getrandom::fill(&mut k).expect("getrandom");
    k
}

/// A fresh random 32-byte identity seed. A lait identity is just this seed; the
/// transport constructs its keypair from it (see [`device_from_seed`]).
pub fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("getrandom");
    s
}

/// The lait [`DeviceId`] (device key) of an identity seed: the ed25519 public key
/// of the 32-byte seed, hex-encoded. A `DeviceId` *is* this public key,
/// and it equals the transport's node id for the same seed (see [`crate::ids`]) —
/// so identity is defined here, in lait's own terms, with no transport type.
pub fn device_from_seed(seed: &[u8; 32]) -> DeviceId {
    let pk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key();
    DeviceId::from_key_string(data_encoding::HEXLOWER.encode(pk.as_bytes()))
}

/// The `did:key` form of an ed25519 public key (the raw bytes a [`DeviceId`]
/// *is*). A pure, offline, self-certifying function of the key — the interop
/// lingua franca the agent-identity standards converge on (draft-duda / AIP /
/// KERI, `docs/plans/09`): lait presents *any* member's identity outward as a
/// `did` with no registry and no network. The multicodec prefix `0xed01` marks
/// ed25519-pub; the body is multibase base58btc (`z`-prefixed), per the W3C
/// did:key spec, so every ed25519 did:key begins `z6Mk`.
pub fn did_key_from_pubkey(pubkey: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(34);
    bytes.extend_from_slice(&[0xed, 0x01]);
    bytes.extend_from_slice(pubkey);
    format!("did:key:z{}", base58btc_encode(&bytes))
}

/// The `did:key` of a [`DeviceId`] (which *is* a hex ed25519 public key).
/// `None` if the id is not a well-formed 32-byte key.
pub fn did_key_from_device(device: &DeviceId) -> Option<String> {
    ed_pubkey_bytes(device).map(|pk| did_key_from_pubkey(&pk))
}

/// Bitcoin-alphabet base58 encoding (no external crate: the kernel lists no
/// scaffold, and this is ~20 lines of well-defined arithmetic). Used only to
/// render a `did:key` multibase body.
fn base58btc_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut buf: Vec<u8> = Vec::new();
    for &byte in input {
        let mut carry = byte as u32;
        for b in buf.iter_mut() {
            carry += (*b as u32) << 8;
            *b = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            buf.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + buf.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &b in buf.iter().rev() {
        out.push(ALPHABET[b as usize] as char);
    }
    out
}

/// Sign an **already-built preimage** with an identity seed's Ed25519 key,
/// returning the detached 64-byte signature. Mechanics owns key operations; a
/// higher layer (e.g. runtime's World-action envelope) builds the canonical
/// length-framed preimage and hands it here, so no upper crate names a signature
/// primitive. Domain separation and framing are the caller's responsibility.
pub fn sign_detached(seed: &[u8; 32], preimage: &[u8]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    sk.sign(preimage).to_bytes()
}

/// Verify a detached Ed25519 signature over a preimage against a 32-byte public
/// key (the raw bytes a [`DeviceId`]/`StationId` *is*). Never panics on a
/// malformed key or signature — a bad input is a failed verification, not a
/// crash.
pub fn verify_detached(public_key: &[u8; 32], preimage: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    vk.verify(preimage, &sig).is_ok()
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    getrandom::fill(&mut n).expect("getrandom");
    n
}

/// AEAD-seal a payload with the space key. Output = `nonce(12) || ciphertext`.
pub fn aead_encrypt(key: &SpaceKey, plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = random_nonce();
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("aead encrypt");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// AEAD-open a payload; `None` if the key is wrong or the blob is malformed (the
/// blind-relay property: without the key you get nothing).
pub fn aead_decrypt(key: &SpaceKey, blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return None;
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

/// Parse a hex `DeviceId` into raw ed25519 public-key bytes.
fn ed_pubkey_bytes(device: &DeviceId) -> Option<[u8; 32]> {
    let s = device.as_str();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// ed25519 public → X25519 public (Edwards-Y → Montgomery-u).
fn ed_pk_to_x(ed_pub: &[u8; 32]) -> Option<XPublic> {
    let ed = CompressedEdwardsY(*ed_pub).decompress()?;
    Some(XPublic::from(ed.to_montgomery().to_bytes()))
}

/// ed25519 secret seed → X25519 static secret (libsodium `sk_to_curve25519`).
fn ed_seed_to_x(seed: &[u8; 32]) -> StaticSecret {
    let h = Sha512::digest(seed);
    let mut s = [0u8; 32];
    s.copy_from_slice(&h[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    StaticSecret::from(s)
}

/// Seal `msg` to a member addressed by their ed25519 `DeviceId` (an anonymous
/// sealed box). Output = `eph_x_pub(32) || nonce(12) || ciphertext`. Used to
/// distribute the space key. Returns `None` if the recipient key is invalid.
pub fn seal_to(recipient: &DeviceId, msg: &[u8]) -> Option<Vec<u8>> {
    let recip_ed = ed_pubkey_bytes(recipient)?;
    let recip_x = ed_pk_to_x(&recip_ed)?;
    let mut eph_seed = [0u8; 32];
    getrandom::fill(&mut eph_seed).expect("getrandom");
    let eph = StaticSecret::from(eph_seed);
    let eph_pub = XPublic::from(&eph);
    let shared = eph.diffie_hellman(&recip_x);
    let key = box_key(shared.as_bytes(), eph_pub.as_bytes(), recip_x.as_bytes());
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = random_nonce();
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), msg).ok()?;
    let mut out = Vec::with_capacity(32 + NONCE_LEN + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Open a sealed box addressed to us, given our ed25519 seed + `DeviceId`.
pub fn open_sealed(my_seed: &[u8; 32], me: &DeviceId, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < 32 + NONCE_LEN {
        return None;
    }
    let eph_pub = XPublic::from(<[u8; 32]>::try_from(&sealed[..32]).ok()?);
    let nonce = &sealed[32..32 + NONCE_LEN];
    let ct = &sealed[32 + NONCE_LEN..];
    let my_x = ed_seed_to_x(my_seed);
    let my_ed = ed_pubkey_bytes(me)?;
    let my_x_pub = ed_pk_to_x(&my_ed)?;
    let shared = my_x.diffie_hellman(&eph_pub);
    let key = box_key(shared.as_bytes(), eph_pub.as_bytes(), my_x_pub.as_bytes());
    let cipher = ChaCha20Poly1305::new((&key).into());
    cipher.decrypt(Nonce::from_slice(nonce), ct).ok()
}

/// Derive the box AEAD key from the DH shared secret + both public keys.
fn box_key(shared: &[u8], eph_pub: &[u8], recip_pub: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"lait/sealedbox/0");
    h.update(shared);
    h.update(eph_pub);
    h.update(recip_pub);
    *h.finalize().as_bytes()
}

/// The key-epoch id length prefixed to every protected Body envelope.
pub const BODY_EPOCH_ID_LEN: usize = 16;
/// The fixed protected-Body envelope overhead:
/// `epoch_id(16) || nonce(12) || tag(16)` beyond the plaintext length.
pub const BODY_ENVELOPE_OVERHEAD: usize = BODY_EPOCH_ID_LEN + NONCE_LEN + 16;

/// An **opaque, non-serializable** capability authorizing Body protection under
/// one approved key epoch: the authorized epoch id plus its current key
/// material. Mechanics-side policy (the composition root, reading the
/// authorized epoch set) mints it; Replica selects it under Space policy and
/// passes it only to Fabric seal/open. Fabric never decides epoch legitimacy —
/// holding this capability *is* the legitimacy decision, made upstream. The
/// key material has no accessor, no serialization, and no `Debug` leak.
#[derive(Clone)]
pub struct AuthorizedBodyKey {
    epoch: [u8; BODY_EPOCH_ID_LEN],
    key: SpaceKey,
}

impl std::fmt::Debug for AuthorizedBodyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedBodyKey")
            .field("epoch", &data_encoding::HEXLOWER.encode(&self.epoch))
            .finish_non_exhaustive()
    }
}

impl AuthorizedBodyKey {
    /// Mint the capability for an **authorized** epoch. The caller owes the
    /// authorization proof (a valid writer-signed epoch mint replayed from
    /// signed history); this constructor only packages the decision.
    pub fn for_authorized_epoch(epoch: [u8; BODY_EPOCH_ID_LEN], key: SpaceKey) -> Self {
        Self { epoch, key }
    }

    /// The authorized epoch id this capability speaks for.
    pub fn epoch_id(&self) -> &[u8; BODY_EPOCH_ID_LEN] {
        &self.epoch
    }
}

/// Seal a Body plaintext under an authorized key epoch. The persisted envelope
/// is exactly `epoch_id[16] || nonce[12] || ciphertext_and_tag` — the existing
/// construction; this completion pass introduces no new cryptography.
pub fn body_seal(key: &AuthorizedBodyKey, plaintext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BODY_EPOCH_ID_LEN + NONCE_LEN + plaintext.len() + 16);
    out.extend_from_slice(&key.epoch);
    out.extend_from_slice(&aead_encrypt(&key.key, plaintext));
    out
}

/// Open a protected Body envelope with the capability for **its** epoch.
/// `None` when the envelope names a different epoch, the key is wrong, or the
/// blob is malformed — without the right epoch key you learn nothing.
pub fn body_open(key: &AuthorizedBodyKey, envelope: &[u8]) -> Option<Vec<u8>> {
    let (epoch, blob) = envelope.split_at_checked(BODY_EPOCH_ID_LEN)?;
    if epoch != key.epoch {
        return None;
    }
    aead_decrypt(&key.key, blob)
}

/// The epoch id a protected Body envelope names (no key required — this is the
/// lookup tag, deliberately public).
pub fn body_epoch_id(envelope: &[u8]) -> Option<[u8; BODY_EPOCH_ID_LEN]> {
    envelope.get(..BODY_EPOCH_ID_LEN)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_roundtrip_and_wrong_key_fails() {
        let k = random_key();
        let blob = aead_encrypt(&k, b"opaque loro export");
        assert_eq!(
            aead_decrypt(&k, &blob).as_deref(),
            Some(&b"opaque loro export"[..])
        );
        // wrong key ⇒ None (a blind relay / non-member learns nothing).
        assert!(aead_decrypt(&[0u8; 32], &blob).is_none());
        assert!(aead_decrypt(&k, b"tooshort").is_none());
    }

    #[test]
    fn did_key_is_a_deterministic_ed25519_multibase() {
        let seed = [9u8; 32];
        let device = device_from_seed(&seed);
        let did = did_key_from_device(&device).expect("a seed device is a valid ed25519 key");
        // Every ed25519 did:key begins `did:key:z6Mk` — the multibase base58btc
        // encoding of the `0xed01` multicodec prefix. This pins both the prefix
        // and the base58 alphabet.
        assert!(
            did.starts_with("did:key:z6Mk"),
            "ed25519 did:key must be z6Mk-prefixed, got {did}"
        );
        // Pure function of the key: same device → same did, every time.
        assert_eq!(did, did_key_from_device(&device).unwrap());
        // And it is a function of the key material, not the id string form.
        let other = device_from_seed(&[10u8; 32]);
        assert_ne!(did, did_key_from_device(&other).unwrap());
    }

    #[test]
    fn base58btc_matches_known_vectors() {
        // Bitcoin base58 reference vectors (leading-zero handling included).
        assert_eq!(base58btc_encode(&[0x00, 0x00, 0x01]), "112");
        assert_eq!(base58btc_encode(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(base58btc_encode(&[]), "");
    }

    #[test]
    fn seals_to_a_seed_derived_device_and_opens() {
        // A member is addressed by their seed-derived DeviceId; the ed25519↔x25519
        // conversion must let a box sealed to it open with the seed. (The
        // agreement that the transport's key IS this ed25519 pair lives at the
        // net seam — see tests/identity_interop.rs.)
        let seed = [5u8; 32];
        let uid = device_from_seed(&seed);
        let key = random_key();
        let sealed = seal_to(&uid, &key).expect("seal to seed-derived key");
        assert_eq!(
            open_sealed(&seed, &uid, &sealed).as_deref(),
            Some(&key[..]),
            "seed-keyed sealed box must round-trip"
        );
    }

    #[test]
    fn sealed_box_only_opens_for_recipient() {
        let seed = [7u8; 32];
        let me = device_from_seed(&seed);
        let key = random_key();
        let sealed = seal_to(&me, &key).expect("seal");
        assert_eq!(open_sealed(&seed, &me, &sealed).as_deref(), Some(&key[..]));
        // a different member cannot open it.
        let other_seed = [9u8; 32];
        let other = device_from_seed(&other_seed);
        assert!(open_sealed(&other_seed, &other, &sealed).is_none());
    }
}
