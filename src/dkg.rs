//! FROST distributed key generation & threshold signing — the ceremony that
//! produces the `lait/space/1` recovery **group key** and the group signatures
//! that authorize a `Recover`/`Rotate`.
//!
//! These are pure wrappers over `frost-ed25519` that move only **serialized
//! packages** and index participants by a 1-based `u16`, so the interactive
//! rounds can ride any transport — the membership-doc bulletin board (broadcast
//! round-1, sealed round-2), or copy-paste. Secret packages/shares are returned
//! as bytes for the caller to persist offline; nothing here touches the plane,
//! which only ever verifies one Ed25519 signature ([`crate::space`]).
//!
//! Round map (mirrors the frost API): DKG is `part1→part2→part3` (3 rounds,
//! round-2 packages are targeted secret shares); signing is `commit→sign→
//! aggregate` (2 rounds). See RFC 9591.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use frost_ed25519 as frost;
use serde::{Deserialize, Serialize};

use crate::ids::{UserId, WorkspaceId};
use crate::sigdag::{self, SignedNode};

/// Signing domain for FROST ceremony contributions (bulletin-board packages).
pub const CEREMONY_DOMAIN: &[u8] = b"lait/space/1/ceremony";

/// One participant's contribution to a FROST ceremony, posted to the shared
/// bulletin board and signed by the contributing **device** (the sigdag author).
/// A session is a DKG (produce a recovery group key) followed by one `Rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyOp {
    /// Open a DKG session: the ordered participant devices + threshold. Authored
    /// by the initiator, who must hold the current recovery key to install the
    /// result. `participants` are device `UserId` strings, sorted (index = pos+1).
    Propose {
        session: [u8; 16],
        n: u16,
        k: u16,
        participants: Vec<String>,
    },
    /// A broadcast DKG round-1 package.
    Round1 { session: [u8; 16], package: Vec<u8> },
    /// A DKG round-2 secret share, sealed to recipient device `to`.
    Round2 {
        session: [u8; 16],
        to: String,
        sealed: Vec<u8>,
    },
}

impl CeremonyOp {
    pub fn session(&self) -> [u8; 16] {
        match self {
            CeremonyOp::Propose { session, .. }
            | CeremonyOp::Round1 { session, .. }
            | CeremonyOp::Round2 { session, .. } => *session,
        }
    }
}

/// Sign a [`CeremonyOp`] with the contributing device's seed.
pub fn sign_ceremony(seed: &[u8; 32], op: &CeremonyOp, ws: &WorkspaceId) -> SignedNode {
    sigdag::sign_node(
        CEREMONY_DOMAIN,
        seed,
        postcard::to_stdvec(op).expect("encode ceremony op"),
        vec![],
        ws.as_str(),
    )
}

/// Signature-verified `(author_device, op)` pairs for one session.
pub fn parse_ceremony(
    events: &[SignedNode],
    ws: &WorkspaceId,
    session: &[u8; 16],
) -> Vec<(UserId, CeremonyOp)> {
    events
        .iter()
        .filter_map(|ev| {
            if !ev.verify_sig(CEREMONY_DOMAIN, ws.as_str()) {
                return None;
            }
            let op = postcard::from_bytes::<CeremonyOp>(&ev.op).ok()?;
            (op.session() == *session).then(|| (ev.author.clone(), op))
        })
        .collect()
}

/// Serialized packages keyed by 1-based participant index — how a round's
/// contributions travel on the transport.
pub type Packages = BTreeMap<u16, Vec<u8>>;

fn ident(index: u16) -> Result<frost::Identifier> {
    frost::Identifier::try_from(index).map_err(|e| anyhow!("dkg identifier {index}: {e}"))
}

fn ser<T, E: std::fmt::Display>(r: std::result::Result<T, E>, what: &str) -> Result<T> {
    r.map_err(|e| anyhow!("{what}: {e}"))
}

/// The group public key as a lait `UserId` (a plain Ed25519 key), from a DKG
/// public-key package. This is the recovery authority the plane commits to.
fn group_key_of(pkp: &frost::keys::PublicKeyPackage) -> Result<UserId> {
    let bytes = ser(pkp.verifying_key().serialize(), "serialize group key")?;
    Ok(UserId::from_key_string(
        data_encoding::HEXLOWER.encode(&bytes),
    ))
}

// ---- DKG (dealer-free key generation) ----

/// DKG round 1 for participant `index` of an `n`-party, `k`-threshold group.
/// Returns `(secret_state, broadcast_package)` — persist the secret locally, post
/// the package to every other participant.
pub fn dkg_round1(index: u16, n: u16, k: u16) -> Result<(Vec<u8>, Vec<u8>)> {
    let (secret, pkg) = ser(
        frost::keys::dkg::part1(ident(index)?, n, k, rand_core::OsRng),
        "dkg part1",
    )?;
    Ok((
        ser(secret.serialize(), "serialize round1 secret")?,
        ser(pkg.serialize(), "serialize round1 package")?,
    ))
}

/// DKG round 2: consume the round-1 secret + every OTHER participant's round-1
/// package; return `(secret_state, round2_packages_by_recipient_index)`. Each
/// round-2 package is a secret share for one recipient — seal it to them.
pub fn dkg_round2(secret1: &[u8], others_round1: &Packages) -> Result<(Vec<u8>, Packages)> {
    let secret = ser(
        frost::keys::dkg::round1::SecretPackage::deserialize(secret1),
        "deserialize round1 secret",
    )?;
    let mut r1 = BTreeMap::new();
    for (i, bytes) in others_round1 {
        r1.insert(
            ident(*i)?,
            ser(
                frost::keys::dkg::round1::Package::deserialize(bytes),
                "deserialize round1 package",
            )?,
        );
    }
    let (secret2, outgoing) = ser(frost::keys::dkg::part2(secret, &r1), "dkg part2")?;
    let mut by_index = BTreeMap::new();
    for i in others_round1.keys() {
        if let Some(pkg) = outgoing.get(&ident(*i)?) {
            by_index.insert(*i, ser(pkg.serialize(), "serialize round2 package")?);
        }
    }
    Ok((
        ser(secret2.serialize(), "serialize round2 secret")?,
        by_index,
    ))
}

/// DKG round 3: consume the round-2 secret, every other's round-1 package, and
/// the round-2 packages sent TO us (keyed by sender index). Returns
/// `(key_share, public_key_package, group_key)` — the key share is this holder's
/// secret (persist offline), the public-key package is public (needed to
/// aggregate signatures), and the group key is the recovery authority.
pub fn dkg_round3(
    secret2: &[u8],
    others_round1: &Packages,
    received_round2: &Packages,
) -> Result<(Vec<u8>, Vec<u8>, UserId)> {
    let secret = ser(
        frost::keys::dkg::round2::SecretPackage::deserialize(secret2),
        "deserialize round2 secret",
    )?;
    let mut r1 = BTreeMap::new();
    for (i, b) in others_round1 {
        r1.insert(
            ident(*i)?,
            ser(
                frost::keys::dkg::round1::Package::deserialize(b),
                "deserialize round1 package",
            )?,
        );
    }
    let mut r2 = BTreeMap::new();
    for (i, b) in received_round2 {
        r2.insert(
            ident(*i)?,
            ser(
                frost::keys::dkg::round2::Package::deserialize(b),
                "deserialize round2 package",
            )?,
        );
    }
    let (kp, pkp) = ser(frost::keys::dkg::part3(&secret, &r1, &r2), "dkg part3")?;
    let group = group_key_of(&pkp)?;
    Ok((
        ser(kp.serialize(), "serialize key package")?,
        ser(pkp.serialize(), "serialize public key package")?,
        group,
    ))
}

// ---- Threshold signing (produce one group signature over a message) ----

/// Signing round 1 (commit): from a key share, return `(nonces_state, broadcast
/// commitments)`. Persist the nonces locally (single-use), post the commitments.
pub fn sign_round1(key_share: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let kp = ser(
        frost::keys::KeyPackage::deserialize(key_share),
        "deserialize key package",
    )?;
    let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rand_core::OsRng);
    Ok((
        ser(nonces.serialize(), "serialize nonces")?,
        ser(commitments.serialize(), "serialize commitments")?,
    ))
}

fn signing_package(commitments: &Packages, message: &[u8]) -> Result<frost::SigningPackage> {
    let mut map = BTreeMap::new();
    for (i, b) in commitments {
        map.insert(
            ident(*i)?,
            ser(
                frost::round1::SigningCommitments::deserialize(b),
                "deserialize commitments",
            )?,
        );
    }
    Ok(frost::SigningPackage::new(map, message))
}

/// Signing round 2 (share): from the collected commitments (≥ threshold), the
/// message, this signer's nonces, and key share, return the signature share.
pub fn sign_round2(
    commitments: &Packages,
    message: &[u8],
    nonces: &[u8],
    key_share: &[u8],
) -> Result<Vec<u8>> {
    let sp = signing_package(commitments, message)?;
    let nonces = ser(
        frost::round1::SigningNonces::deserialize(nonces),
        "deserialize nonces",
    )?;
    let kp = ser(
        frost::keys::KeyPackage::deserialize(key_share),
        "deserialize key package",
    )?;
    let share = ser(frost::round2::sign(&sp, &nonces, &kp), "round2 sign")?;
    Ok(share.serialize()) // SignatureShare::serialize -> Vec<u8>
}

/// Aggregate ≥ threshold signature shares into one Ed25519 group signature over
/// `message` (64 bytes) — verifiable against the group key by any Ed25519
/// verifier (our sigdag). Needs the DKG public-key package.
pub fn aggregate(
    commitments: &Packages,
    message: &[u8],
    shares: &Packages,
    public_key_package: &[u8],
) -> Result<Vec<u8>> {
    let sp = signing_package(commitments, message)?;
    let pkp = ser(
        frost::keys::PublicKeyPackage::deserialize(public_key_package),
        "deserialize public key package",
    )?;
    let mut share_map = BTreeMap::new();
    for (i, b) in shares {
        share_map.insert(
            ident(*i)?,
            ser(
                frost::round2::SignatureShare::deserialize(b),
                "deserialize signature share",
            )?,
        );
    }
    let sig = ser(frost::aggregate(&sp, &share_map, &pkp), "aggregate")?;
    ser(sig.serialize(), "serialize signature")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-participant `(key_share, public_key_package)`, keyed by index.
    type Holders = BTreeMap<u16, (Vec<u8>, Vec<u8>)>;

    /// Run a full dealer-free `k`-of-`n` DKG through the byte API and return each
    /// participant's `(key_share, public_key_package)` plus the group key.
    fn run_dkg(n: u16, k: u16) -> (Holders, UserId) {
        let ids: Vec<u16> = (1..=n).collect();
        // round 1
        let mut secret1 = BTreeMap::new();
        let mut round1 = BTreeMap::new();
        for &i in &ids {
            let (s, p) = dkg_round1(i, n, k).unwrap();
            secret1.insert(i, s);
            round1.insert(i, p);
        }
        let others_r1 = |me: u16| -> Packages {
            round1
                .iter()
                .filter(|(k, _)| **k != me)
                .map(|(k, v)| (*k, v.clone()))
                .collect()
        };
        // round 2
        let mut secret2 = BTreeMap::new();
        let mut inbox: BTreeMap<u16, Packages> =
            ids.iter().map(|i| (*i, BTreeMap::new())).collect();
        for &i in &ids {
            let (s2, outgoing) = dkg_round2(&secret1[&i], &others_r1(i)).unwrap();
            secret2.insert(i, s2);
            for (recipient, pkg) in outgoing {
                inbox.get_mut(&recipient).unwrap().insert(i, pkg);
            }
        }
        // round 3
        let mut shares = BTreeMap::new();
        let mut group = None;
        for &i in &ids {
            let (kp, pkp, g) = dkg_round3(&secret2[&i], &others_r1(i), &inbox[&i]).unwrap();
            if let Some(prev) = &group {
                assert_eq!(prev, &g, "all holders derive the same group key");
            }
            group = Some(g);
            shares.insert(i, (kp, pkp));
        }
        (shares, group.unwrap())
    }

    #[test]
    fn dkg_then_threshold_sign_yields_an_ed25519_group_signature() {
        use ed25519_dalek::Verifier;

        let (holders, group_key) = run_dkg(3, 2);
        let message = b"lait/space/1/event: Recover{new_root, gen}";

        // Two of three holders sign.
        let signers: Vec<u16> = holders.keys().copied().take(2).collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for &i in &signers {
            let (n, c) = sign_round1(&holders[&i].0).unwrap();
            nonces.insert(i, n);
            commitments.insert(i, c);
        }
        let mut shares = BTreeMap::new();
        for &i in &signers {
            let sh = sign_round2(&commitments, message, &nonces[&i], &holders[&i].0).unwrap();
            shares.insert(i, sh);
        }
        // Any holder's public-key package works to aggregate.
        let pkp = &holders[&signers[0]].1;
        let sig = aggregate(&commitments, message, &shares, pkp).unwrap();

        // Verify as a plain Ed25519 signature against the group key (sigdag path).
        let pk: [u8; 32] = hex32(group_key.as_str()).unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig).unwrap();
        assert!(
            vk.verify(message, &sig).is_ok(),
            "the DKG group signature verifies as a plain Ed25519 signature"
        );
    }

    fn hex32(s: &str) -> Option<[u8; 32]> {
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .ok()?
            .as_slice()
            .try_into()
            .ok()
    }
}
