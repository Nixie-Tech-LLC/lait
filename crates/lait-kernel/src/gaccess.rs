//! General-access Schnorr signing over a compiled access structure.
//!
//! The compiled access control is a monotone span program: a qualified leaf set
//! `S` has reconstruction coefficients `λ` with `x = Σ_{i∈S} λ_i s_i`, where
//! `s_i` is leaf `i`'s share of a secret scalar `x` and `Y = xG` is the public
//! key. This module produces **one** Schnorr signature under `Y` from a qualified
//! set — the same two-round nonce structure as FROST (RFC 9591), with the MSP
//! coefficient `λ_i` in place of the flat-threshold Lagrange coefficient.
//!
//! ```text
//! z = Σ_i z_i = Σ_i (d_i + ρ_i e_i + c·λ_i·s_i)
//!            = (Σ_i d_i + ρ_i e_i) + c·(Σ_i λ_i s_i)
//!            = k + c·x
//! R = k·G,   so   z·G = R + c·Y.
//! ```
//!
//! # Security status
//!
//! General-access signing is a new protocol, not "FROST with different
//! coefficients." Passing the functional vectors here does not establish
//! production readiness. The following protections are not yet implemented or
//! independently reviewed:
//!
//! - **Active-adversary security.** The tests exercise honest execution. Corrupt
//!   coordinators/signers, adaptive availability, transcript manipulation and
//!   identifiable aborts are not covered here.
//! - **Ed25519 wire compatibility.** This verifies under *this module's own*
//!   Schnorr equation, not a standard Ed25519 verifier. RFC-9591-exact challenge,
//!   cofactor and encoding — so the space plane's ed25519 verifier accepts the
//!   output — is deliberately not approximated here.
//! - **Dealer-free generation.** Shares here come from a **test dealer**
//!   ([`deal`]); [`crate::gdkg`] provides the isolated dealer-free prototype.
//! - **Nonce lifecycle.** Single-use nonce enforcement rides the existing
//!   [`crate::dkg::PendingNonce`] discipline at the ceremony layer; this module
//!   provides the algebra, and nonce reuse across messages is a caller error the
//!   plan-bound nonce record is responsible for preventing.
//!
//! Nothing here is wired into the replica or the space plane. It exists to
//! isolate and validate the signing/witness algebra. It is not production-ready.

use std::collections::BTreeMap;

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT as G;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use crate::authority::LeafId;
use crate::compile::{ReconstructionWitness, StructurallyValidatedCompiledPolicy};

const CHALLENGE_DOMAIN: &[u8] = b"lait/space/1/gaccess/1/challenge";
const BINDING_DOMAIN: &[u8] = b"lait/space/1/gaccess/1/binding";

/// A uniformly random scalar.
fn random_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    getrandom::fill(&mut wide).expect("getrandom");
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A test-only dealer's output: the secret, the public key, and each leaf's share
/// consistent with the compiled access structure. This prototype uses
/// dealer-generated shares by design; [`crate::gdkg`] is dealer-free.
#[derive(Debug, Clone)]
pub struct Dealing {
    secret: Scalar,
    public: EdwardsPoint,
    shares: BTreeMap<LeafId, Scalar>,
}

/// What signing needs from a key: the group public key and the caller's own
/// share of each leaf it operates. Deliberately does **not** expose the secret —
/// dealer-free generation produces a value with no secret to expose, and
/// signing must work identically whether the shares came from a test dealer or a
/// real DKG.
pub trait KeyShares {
    /// The group public key `Y = xG`, compressed.
    fn public_key(&self) -> [u8; 32];
    /// This holder's share for `leaf`, if it operates it.
    fn share(&self, leaf: &LeafId) -> Option<Scalar>;
}

impl Dealing {
    /// The dealt secret `x`. A real deployment never materializes this — it is
    /// the very thing dealer-free generation exists to avoid. Exposed here
    /// only so tests can check that qualified reconstruction recovers it.
    pub fn secret_for_test(&self) -> Scalar {
        self.secret
    }
}

impl KeyShares for Dealing {
    fn public_key(&self) -> [u8; 32] {
        self.public.compress().to_bytes()
    }
    fn share(&self, leaf: &LeafId) -> Option<Scalar> {
        self.shares.get(leaf).copied()
    }
}

/// Deal shares for `compiled`: sample a random distribution vector `ρ`, set the
/// secret `x = ρ₀`, and give leaf `i` the share `⟨A_i, ρ⟩`.
///
/// TEST DEALER ONLY. A trusted dealer holds `x`; dealer-free generation exists to
/// remove it. Used here to isolate signing correctness from DKG correctness.
pub fn deal(compiled: &StructurallyValidatedCompiledPolicy) -> Dealing {
    let cols = compiled.cols();
    let rho: Vec<Scalar> = (0..cols).map(|_| random_scalar()).collect();
    let secret = rho[0];
    let public = G * secret;
    let mut shares = BTreeMap::new();
    for (leaf, row) in compiled
        .leaves()
        .iter()
        .zip(compiled.inner().matrix.rows.iter())
    {
        // s_i = ⟨A_i, ρ⟩
        let s: Scalar = row
            .iter()
            .zip(&rho)
            .map(|(cell, r)| cell.as_scalar().expect("validated field element") * r)
            .sum();
        shares.insert(leaf.clone(), s);
    }
    Dealing {
        secret,
        public,
        shares,
    }
}

/// A signer's secret nonce pair (single-use).
#[derive(Debug, Clone)]
pub struct Nonce {
    d: Scalar,
    e: Scalar,
}

/// A signer's public nonce commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment {
    big_d: EdwardsPoint,
    big_e: EdwardsPoint,
}

/// Round 1: a signer draws a fresh nonce pair and publishes its commitment.
pub fn commit() -> (Nonce, Commitment) {
    let d = random_scalar();
    let e = random_scalar();
    (
        Nonce { d, e },
        Commitment {
            big_d: G * d,
            big_e: G * e,
        },
    )
}

/// The per-signer binding factor `ρ_i = H(domain, leaf, msg, all commitments)`.
fn binding_factor(leaf: &LeafId, msg: &[u8], commitments: &[(LeafId, Commitment)]) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(BINDING_DOMAIN);
    h.update(leaf.as_str().as_bytes());
    h.update(&(msg.len() as u64).to_le_bytes());
    h.update(msg);
    for (l, c) in commitments {
        h.update(l.as_str().as_bytes());
        h.update(&c.big_d.compress().to_bytes());
        h.update(&c.big_e.compress().to_bytes());
    }
    Scalar::from_bytes_mod_order_wide(&wide(h))
}

/// The group nonce `R = Σ (D_i + ρ_i E_i)` and each signer's binding factor.
fn group_nonce(
    msg: &[u8],
    commitments: &[(LeafId, Commitment)],
) -> (EdwardsPoint, BTreeMap<LeafId, Scalar>) {
    let mut r = EdwardsPoint::identity();
    let mut factors = BTreeMap::new();
    for (leaf, c) in commitments {
        let rho = binding_factor(leaf, msg, commitments);
        r += c.big_d + c.big_e * rho;
        factors.insert(leaf.clone(), rho);
    }
    (r, factors)
}

/// The Schnorr challenge `c = H(domain, R, Y, msg)`.
fn challenge(r: &EdwardsPoint, y: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = blake3::Hasher::new();
    h.update(CHALLENGE_DOMAIN);
    h.update(&r.compress().to_bytes());
    h.update(y);
    h.update(&(msg.len() as u64).to_le_bytes());
    h.update(msg);
    Scalar::from_bytes_mod_order_wide(&wide(h))
}

fn wide(h: blake3::Hasher) -> [u8; 64] {
    let mut out = [0u8; 64];
    h.finalize_xof().fill(&mut out);
    out
}

/// A finished general-access signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub z: [u8; 32],
}

/// One signer's contribution, given its nonce, its reconstruction coefficient
/// `λ_i`, its share `s_i`, and the round-1 commitments.
fn sign_share(
    leaf: &LeafId,
    nonce: &Nonce,
    coeff: Scalar,
    share: Scalar,
    msg: &[u8],
    commitments: &[(LeafId, Commitment)],
    y: &[u8; 32],
) -> Scalar {
    let (r, factors) = group_nonce(msg, commitments);
    let c = challenge(&r, y, msg);
    let rho = factors[leaf];
    // z_i = d_i + ρ_i e_i + c · λ_i · s_i
    nonce.d + rho * nonce.e + c * coeff * share
}

/// A whole honest signing session over a **qualified** set, for testing and to
/// exercise the algebra end to end. Returns the signature, or `None` if the
/// witness names a leaf not among the committed signers.
///
/// A real session distributes these rounds over the ceremony board with the
/// nonce lifecycle of [`crate::dkg::PendingNonce`]; this is the local algebra.
pub fn sign_qualified<K: KeyShares>(
    witness: &ReconstructionWitness,
    key: &K,
    nonces: &BTreeMap<LeafId, Nonce>,
    commitments: &[(LeafId, Commitment)],
    msg: &[u8],
) -> Option<Signature> {
    let y = key.public_key();
    let (r, _) = group_nonce(msg, commitments);
    let mut z = Scalar::ZERO;
    for (leaf, coeff) in witness.leaves.iter().zip(&witness.coefficients) {
        let nonce = nonces.get(leaf)?;
        let share = key.share(leaf)?;
        z += sign_share(
            leaf,
            nonce,
            coeff.as_scalar().expect("witness coefficient"),
            share,
            msg,
            commitments,
            &y,
        );
    }
    Some(Signature {
        r: r.compress().to_bytes(),
        z: z.to_bytes(),
    })
}

/// Verify a signature under the general-access Schnorr equation `z·G = R + c·Y`.
///
/// This is **this module's** verifier, not a standard Ed25519 verifier — see the
/// security limitations in the module documentation.
///
/// The public key `Y` and nonce `R` cross a trust boundary, so decompression
/// alone is not enough: both are checked to be non-identity points of the
/// prime-order subgroup (torsion-free), rejecting small-order and mixed-order
/// points a hostile peer could submit.
pub fn verify(public_key: &[u8; 32], msg: &[u8], sig: &Signature) -> bool {
    let Some(y) = decompress_prime_order(public_key) else {
        return false;
    };
    let Some(r) = decompress_prime_order(&sig.r) else {
        return false;
    };
    let Some(z) = Scalar::from_canonical_bytes(sig.z).into_option() else {
        return false;
    };
    let c = challenge(&r, public_key, msg);
    G * z == r + y * c
}

fn decompress(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    curve25519_dalek::edwards::CompressedEdwardsY(*bytes).decompress()
}

/// Decompress a point supplied by an untrusted party, accepting only a
/// non-identity element of the prime-order subgroup. Honest locally-generated
/// points always pass; this rejects the identity (a degenerate key/nonce) and
/// any point with a torsion component.
pub(crate) fn decompress_prime_order(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    let p = decompress(bytes)?;
    (p.is_torsion_free() && p != EdwardsPoint::identity()).then_some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::PrincipalId;
    use crate::compile::{compile, StructurallyValidatedCompiledPolicy};
    use crate::expand::{expand, PrincipalCustody, PrincipalDescriptor};
    use crate::policy::OwnershipPolicy;

    fn prin(n: u8) -> PrincipalId {
        PrincipalId::of_device(&crate::crypto::user_from_seed(&[n; 32]))
    }
    fn key(n: u8) -> OwnershipPolicy {
        OwnershipPolicy::Key(prin(n))
    }
    fn resolver() -> impl Fn(&PrincipalId) -> Option<PrincipalDescriptor> {
        |p: &PrincipalId| {
            Some(PrincipalDescriptor {
                id: p.clone(),
                custody: PrincipalCustody::Direct {
                    device: p.as_device()?,
                },
            })
        }
    }
    fn compiled(o: OwnershipPolicy) -> (StructurallyValidatedCompiledPolicy, Vec<LeafId>) {
        let canon = o.canonicalize().unwrap();
        let exp = expand(&canon, &resolver()).unwrap();
        let c = compile(&exp).unwrap();
        let leaves = c.leaves().to_vec();
        (c, leaves)
    }

    /// Run a full honest session for the given qualified subset and return
    /// whether the produced signature verifies.
    fn session(
        compiled: &StructurallyValidatedCompiledPolicy,
        dealing: &Dealing,
        signers: &[LeafId],
        msg: &[u8],
    ) -> Option<bool> {
        let witness = compiled.reconstruct(signers)?; // None ⇒ unqualified
        let mut nonces = BTreeMap::new();
        let mut commitments = Vec::new();
        for leaf in &witness.leaves {
            let (n, c) = commit();
            nonces.insert(leaf.clone(), n);
            commitments.push((leaf.clone(), c));
        }
        let sig = sign_qualified(&witness, dealing, &nonces, &commitments, msg).unwrap();
        Some(verify(&dealing.public_key(), msg, &sig))
    }

    #[test]
    fn a_qualified_set_produces_a_verifying_signature() {
        // 2-of-3.
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let dealing = deal(&c);
        // Any two of three qualify and verify.
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let signers = vec![leaves[pair[0]].clone(), leaves[pair[1]].clone()];
            assert_eq!(
                session(&c, &dealing, &signers, b"install candidate key"),
                Some(true),
                "qualified pair {pair:?} must sign and verify"
            );
        }
    }

    #[test]
    fn an_unqualified_set_cannot_even_form_a_witness() {
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let dealing = deal(&c);
        // One of three does not qualify for 2-of-3: no witness, no signature.
        assert_eq!(session(&c, &dealing, &leaves[0..1], b"m"), None);
    }

    #[test]
    fn a_compartmented_policy_signs_only_with_both_compartments() {
        // 1-of-{A1,A2} AND B.
        let (c, leaves) = compiled(OwnershipPolicy::AllOf(vec![
            OwnershipPolicy::AnyOf(vec![key(1), key(2)]),
            key(3),
        ]));
        let dealing = deal(&c);
        // Map leaves by principal.
        let exp_leaves = {
            let canon =
                OwnershipPolicy::AllOf(vec![OwnershipPolicy::AnyOf(vec![key(1), key(2)]), key(3)])
                    .canonicalize()
                    .unwrap();
            expand(&canon, &resolver()).unwrap()
        };
        let b_leaf = exp_leaves
            .leaves()
            .iter()
            .find(|d| d.principal == prin(3))
            .unwrap()
            .leaf
            .clone();
        let a_leaf = exp_leaves
            .leaves()
            .iter()
            .find(|d| d.principal == prin(1))
            .unwrap()
            .leaf
            .clone();
        let _ = &leaves;

        // A-only: unqualified (needs B too).
        assert_eq!(
            session(&c, &dealing, std::slice::from_ref(&a_leaf), b"m"),
            None
        );
        // A and B: qualified, verifies.
        assert_eq!(
            session(&c, &dealing, &[a_leaf, b_leaf], b"m"),
            Some(true),
            "both compartments sign and verify"
        );
    }

    #[test]
    fn a_tampered_signature_fails() {
        let (c, leaves) = compiled(OwnershipPolicy::AnyOf(vec![key(1), key(2)]));
        let dealing = deal(&c);
        let witness = c.reconstruct(&[leaves[0].clone()]).unwrap();
        let (n, com) = commit();
        let mut nonces = BTreeMap::new();
        nonces.insert(leaves[0].clone(), n);
        let commitments = vec![(leaves[0].clone(), com)];
        let mut sig = sign_qualified(&witness, &dealing, &nonces, &commitments, b"m").unwrap();
        assert!(verify(&dealing.public_key(), b"m", &sig));
        // Flip a bit in z.
        sig.z[0] ^= 1;
        assert!(!verify(&dealing.public_key(), b"m", &sig));
        // Or verify against the wrong message.
        let sig2 = sign_qualified(&witness, &dealing, &nonces, &commitments, b"m").unwrap();
        assert!(!verify(&dealing.public_key(), b"different", &sig2));
    }

    #[test]
    fn verify_rejects_degenerate_points() {
        let (c, leaves) = compiled(OwnershipPolicy::AnyOf(vec![key(1), key(2)]));
        let dealing = deal(&c);
        let witness = c.reconstruct(&[leaves[0].clone()]).unwrap();
        let (n, com) = commit();
        let mut nonces = BTreeMap::new();
        nonces.insert(leaves[0].clone(), n);
        let commitments = vec![(leaves[0].clone(), com)];
        let sig = sign_qualified(&witness, &dealing, &nonces, &commitments, b"m").unwrap();
        assert!(verify(&dealing.public_key(), b"m", &sig));

        let identity = EdwardsPoint::identity().compress().to_bytes();
        // An identity public key (zero-secret key) is refused.
        assert!(!verify(&identity, b"m", &sig));
        // An identity nonce R is refused.
        let mut bad_r = sig;
        bad_r.r = identity;
        assert!(!verify(&dealing.public_key(), b"m", &bad_r));
    }

    #[test]
    fn the_reconstructed_secret_matches_the_public_key() {
        // Sanity on the dealer: Σ λ_i s_i = x for a qualified set.
        let (c, leaves) = compiled(OwnershipPolicy::Threshold {
            k: 2,
            members: vec![key(1), key(2), key(3)],
        });
        let dealing = deal(&c);
        let witness = c
            .reconstruct(&[leaves[0].clone(), leaves[1].clone()])
            .unwrap();
        let mut recovered = Scalar::ZERO;
        for (leaf, coeff) in witness.leaves.iter().zip(&witness.coefficients) {
            recovered += coeff.as_scalar().unwrap() * dealing.share(leaf).unwrap();
        }
        assert_eq!(recovered, dealing.secret_for_test(), "Σ λ_i s_i = x");
        assert_eq!(G * recovered, dealing.public, "and xG = Y");
    }
}
