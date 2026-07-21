//! Portable custody for an authority share.
//!
//! # Why this exists
//!
//! A share protected only by DPAPI is bound to one Windows account on one
//! machine. For an N-of-N arrangement every share is indispensable, so losing a
//! profile does not degrade the group — it destroys the authority permanently.
//! That makes the operating-system profile an accidental founder, which nobody
//! chose and nobody can audit.
//!
//! So DPAPI is treated here as a **local convenience unlock**, never as the
//! durability boundary. The canonical artifact is an [`AuthoritySharePackage`]:
//! self-describing, portable, and openable by any of several independent
//! [`KeySlot`]s. Losing one slot costs convenience; it does not cost the share.
//!
//! # Shape
//!
//! One random data-encryption key encrypts the payload once. Each slot wraps
//! that DEK a different way, so adding an unlock path never re-encrypts the
//! secret and never requires having all paths present at once.
//!
//! The package binds itself to its context — space, authority, ceremony,
//! principal and leaf — so a restored share cannot be silently reopened against
//! the wrong space or mistaken for a different holder's. [`SharePayload`] is
//! an enum rather than raw bytes so the same envelope can carry a general-access
//! share without a format change.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::authority::{AuthorityId, AuthorityScheme, LeafId, PrincipalId};
use crate::crypto::{self, SpaceKey};
use crate::ids::{DeviceId, SpaceId};

/// Current package format version.
pub const PACKAGE_VERSION: u16 = 1;

/// Argon2id parameters for a passphrase slot.
///
/// Stored in the package rather than assumed, so a package written today still
/// opens after the defaults are raised — a share that survives a decade must not
/// depend on the reader agreeing with the writer about cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    /// RFC 9106's second recommended option (64 MiB, 3 passes), a reasonable
    /// interactive cost that still makes offline guessing expensive.
    fn default() -> Self {
        Argon2Params {
            m_cost_kib: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// One way to unwrap the package's data-encryption key.
///
/// Slots are independent by construction: each wraps the same DEK, so any one of
/// them opens the package and losing any one of them costs nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeySlot {
    /// Unwrapped by the OS user-bound facility. Convenience only — this slot is
    /// worthless on any other account or machine, which is exactly why it must
    /// never be the only slot on an indispensable share.
    WindowsDpapi { wrapped_dek: Vec<u8> },
    /// Unwrapped by an x25519 keypair the custodian controls — a recovery key
    /// held offline, or another device.
    RecoveryKey {
        recipient: DeviceId,
        wrapped_dek: Vec<u8>,
    },
    /// Unwrapped by a passphrase the custodian remembers.
    Passphrase {
        salt: [u8; 16],
        params: Argon2Params,
        wrapped_dek: Vec<u8>,
    },
}

impl KeySlot {
    /// A short, stable label for status output.
    pub fn kind(&self) -> &'static str {
        match self {
            KeySlot::WindowsDpapi { .. } => "windows-dpapi",
            KeySlot::RecoveryKey { .. } => "recovery-key",
            KeySlot::Passphrase { .. } => "passphrase",
        }
    }
    /// Whether this slot can open the package away from the machine that wrote
    /// it. A package with no portable slot is one profile loss from gone.
    pub fn is_portable(&self) -> bool {
        !matches!(self, KeySlot::WindowsDpapi { .. })
    }
}

/// The secret a package carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SharePayload {
    Frost(FrostSharePayload),
    /// Reserved for the general-access backend.
    GeneralAccess(Vec<u8>),
}

/// A flat-FROST holder's private material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostSharePayload {
    /// The serialized FROST key package.
    pub key_share: Vec<u8>,
    /// The public-key package, so a restored holder can derive the group key
    /// without needing anything else to have survived alongside it.
    pub public_package: Vec<u8>,
    /// This holder's 1-based participant index.
    pub index: u16,
}

/// A portable, self-describing custody envelope for one holder's share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritySharePackage {
    pub version: u16,
    pub space: SpaceId,
    pub authority: AuthorityId,
    pub ceremony: String,
    pub scheme: AuthorityScheme,
    pub principal: PrincipalId,
    pub leaf: LeafId,
    /// [`SharePayload`], AEAD-encrypted under the package DEK.
    pub encrypted_payload: Vec<u8>,
    pub key_slots: Vec<KeySlot>,
}

/// What a package must match to be accepted after a restore.
///
/// Verification is a *comparison against expectations*, never a report of what
/// the package says about itself: a package that names its own space proves
/// nothing, and accepting one because its fields are internally consistent is
/// how a share for the wrong space, or another holder's share, gets adopted.
#[derive(Debug, Clone)]
pub struct PackageExpectation<'a> {
    pub space: &'a SpaceId,
    pub authority: &'a AuthorityId,
    pub ceremony: &'a str,
    pub leaf: &'a LeafId,
    /// The group public key this holder expects to be part of.
    pub group_key: &'a DeviceId,
    /// The participant index this holder expects to occupy.
    pub index: u16,
}

impl AuthoritySharePackage {
    /// Build a package, encrypting `payload` under a fresh DEK wrapped by every
    /// slot in `slot_specs`.
    pub fn seal(
        space: &SpaceId,
        authority: &AuthorityId,
        ceremony: &str,
        principal: &PrincipalId,
        leaf: &LeafId,
        payload: &SharePayload,
        slot_specs: &[SlotSpec],
    ) -> Result<Self> {
        if slot_specs.is_empty() {
            return Err(anyhow!("a share package needs at least one unlock slot"));
        }
        let dek = crypto::random_key();
        let plaintext = postcard::to_stdvec(payload)?;
        let encrypted_payload = crypto::aead_encrypt(&dek, &plaintext);
        let key_slots = slot_specs
            .iter()
            .map(|spec| spec.wrap(&dek))
            .collect::<Result<Vec<_>>>()?;
        Ok(AuthoritySharePackage {
            version: PACKAGE_VERSION,
            space: space.clone(),
            authority: authority.clone(),
            ceremony: ceremony.to_string(),
            scheme: authority_scheme_of(payload),
            principal: principal.clone(),
            leaf: leaf.clone(),
            encrypted_payload,
            key_slots,
        })
    }

    /// Open the payload with one unlock method.
    pub fn open(&self, key: &UnlockKey) -> Result<SharePayload> {
        if self.version != PACKAGE_VERSION {
            return Err(anyhow!(
                "share package version {} is not supported by this build",
                self.version
            ));
        }
        let dek = self
            .key_slots
            .iter()
            .find_map(|slot| key.unwrap(slot))
            .ok_or_else(|| anyhow!("no slot in this package can be opened with that key"))?;
        let plaintext = crypto::aead_decrypt(&dek, &self.encrypted_payload)
            .ok_or_else(|| anyhow!("the package payload did not decrypt — wrong key or corrupt"))?;
        Ok(postcard::from_bytes(&plaintext)?)
    }

    /// Whether any slot survives leaving this machine.
    pub fn has_portable_slot(&self) -> bool {
        self.key_slots.iter().any(KeySlot::is_portable)
    }

    /// Open the package and confirm it is the one expected, returning the
    /// payload only if every binding matches.
    ///
    /// This is the check a custodian performs before an indispensable authority
    /// is installed. It deliberately verifies the *group key derived from the
    /// package's own public-key package* against the expected one, so a package
    /// cannot claim membership of a group it was not part of.
    pub fn verify_and_open(
        &self,
        key: &UnlockKey,
        expect: &PackageExpectation<'_>,
    ) -> Result<SharePayload> {
        if &self.space != expect.space {
            return Err(anyhow!("this package belongs to a different space"));
        }
        if &self.authority != expect.authority {
            return Err(anyhow!("this package belongs to a different authority"));
        }
        if self.ceremony != expect.ceremony {
            return Err(anyhow!("this package belongs to a different ceremony"));
        }
        if &self.leaf != expect.leaf {
            return Err(anyhow!("this package belongs to a different holder"));
        }
        let payload = self.open(key)?;
        match &payload {
            SharePayload::Frost(f) => {
                let derived = crate::dkg::group_key_of_package(&f.public_package)
                    .map_err(|e| anyhow!("the package's public-key package is unusable: {e}"))?;
                if &derived != expect.group_key {
                    return Err(anyhow!(
                        "the package's own public-key package derives a different group key"
                    ));
                }
                if f.index != expect.index {
                    return Err(anyhow!(
                        "this package is for participant {}, not {}",
                        f.index,
                        expect.index
                    ));
                }
                // The decisive check: the PRIVATE material must actually work.
                // Everything above validates the public half, which a corrupted
                // or substituted secret would pass unchanged.
                crate::dkg::validate_share(&f.key_share, &f.public_package, f.index)?;
            }
            SharePayload::GeneralAccess(_) => {
                return Err(anyhow!(
                    "general-access share payloads are not supported by this build"
                ))
            }
        }
        Ok(payload)
    }
}

fn authority_scheme_of(payload: &SharePayload) -> AuthorityScheme {
    match payload {
        SharePayload::Frost(_) => AuthorityScheme::FrostThreshold,
        SharePayload::GeneralAccess(_) => AuthorityScheme::GeneralAccess,
    }
}

/// How to create one slot.
#[derive(Debug, Clone)]
pub enum SlotSpec {
    /// The caller supplies already-DPAPI-wrapped bytes; this crate does not know
    /// about the OS facility.
    WindowsDpapi {
        wrapped_dek: Vec<u8>,
    },
    RecoveryKey {
        recipient: DeviceId,
    },
    Passphrase {
        passphrase: String,
        salt: [u8; 16],
        params: Argon2Params,
    },
}

impl SlotSpec {
    fn wrap(&self, dek: &SpaceKey) -> Result<KeySlot> {
        match self {
            SlotSpec::WindowsDpapi { wrapped_dek } => Ok(KeySlot::WindowsDpapi {
                wrapped_dek: wrapped_dek.clone(),
            }),
            SlotSpec::RecoveryKey { recipient } => {
                let wrapped_dek = crypto::seal_to(recipient, dek.as_slice())
                    .ok_or_else(|| anyhow!("cannot seal to {}", recipient.short()))?;
                Ok(KeySlot::RecoveryKey {
                    recipient: recipient.clone(),
                    wrapped_dek,
                })
            }
            SlotSpec::Passphrase {
                passphrase,
                salt,
                params,
            } => {
                let kek = derive_passphrase_key(passphrase, salt, params)?;
                Ok(KeySlot::Passphrase {
                    salt: *salt,
                    params: *params,
                    wrapped_dek: crypto::aead_encrypt(&kek, dek.as_slice()),
                })
            }
        }
    }
}

/// A key that may open one kind of slot.
#[derive(Debug, Clone)]
pub enum UnlockKey {
    /// The caller unwrapped a DPAPI slot itself and supplies the DEK.
    Dpapi {
        dek: Vec<u8>,
    },
    RecoveryKey {
        seed: [u8; 32],
        me: DeviceId,
    },
    Passphrase(String),
}

impl UnlockKey {
    fn unwrap(&self, slot: &KeySlot) -> Option<SpaceKey> {
        match (self, slot) {
            (UnlockKey::Dpapi { dek }, KeySlot::WindowsDpapi { .. }) => {
                SpaceKey::try_from(dek.as_slice()).ok()
            }
            (
                UnlockKey::RecoveryKey { seed, me },
                KeySlot::RecoveryKey {
                    recipient,
                    wrapped_dek,
                },
            ) if recipient == me => {
                let raw = crypto::open_sealed(seed, me, wrapped_dek)?;
                SpaceKey::try_from(raw.as_slice()).ok()
            }
            (
                UnlockKey::Passphrase(p),
                KeySlot::Passphrase {
                    salt,
                    params,
                    wrapped_dek,
                },
            ) => {
                let kek = derive_passphrase_key(p, salt, params).ok()?;
                let raw = crypto::aead_decrypt(&kek, wrapped_dek)?;
                SpaceKey::try_from(raw.as_slice()).ok()
            }
            _ => None,
        }
    }
}

/// Argon2id over the passphrase. Memory-hard on purpose: a share package is
/// meant to be carried and stored, so its passphrase slot must survive an
/// attacker who has the file and unlimited offline guesses.
fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8; 16],
    params: &Argon2Params,
) -> Result<SpaceKey> {
    let params = argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| anyhow!("argon2 parameters rejected: {e}"))?;
    let a2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("argon2 derivation failed: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{AuthorityConfiguration, FrostThresholdConfig};
    use crate::ids::SystemUlidSource;

    /// Cheap parameters so tests do not spend a second per derivation. Never use
    /// these for a real package.
    fn fast() -> Argon2Params {
        Argon2Params {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn fixture() -> (
        SpaceId,
        AuthorityId,
        PrincipalId,
        LeafId,
        SharePayload,
        DeviceId,
    ) {
        let ws = SpaceId::mint(&SystemUlidSource);
        let (holders, group_key) = crate::dkg::tests_support::run_dkg(3, 2);
        let (share, pkp) = holders[&1].clone();
        let device = crypto::device_from_seed(&[1u8; 32]);
        let principal = PrincipalId::of_device(&device);
        let leaf = LeafId::of_principal(&principal);
        let config = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 2,
            participants: vec![principal.clone()],
        });
        let authority = AuthorityId::new(group_key.clone(), &config);
        let payload = SharePayload::Frost(FrostSharePayload {
            key_share: share,
            public_package: pkp,
            index: 1,
        });
        (ws, authority, principal, leaf, payload, group_key)
    }

    #[test]
    fn a_passphrase_slot_opens_the_package_anywhere() {
        let (ws, authority, principal, leaf, payload, _) = fixture();
        let pkg = AuthoritySharePackage::seal(
            &ws,
            &authority,
            "ceremony-1",
            &principal,
            &leaf,
            &payload,
            &[SlotSpec::Passphrase {
                passphrase: "correct horse battery staple".into(),
                salt: [7u8; 16],
                params: fast(),
            }],
        )
        .unwrap();
        assert!(pkg.has_portable_slot());
        assert_eq!(
            pkg.open(&UnlockKey::Passphrase(
                "correct horse battery staple".into()
            ))
            .unwrap(),
            payload
        );
        assert!(pkg.open(&UnlockKey::Passphrase("wrong".into())).is_err());
    }

    /// Slots are independent: any one opens the package, so losing one costs
    /// convenience rather than the share. This is the property that stops a
    /// Windows profile from being an accidental founder.
    #[test]
    fn any_single_slot_opens_the_same_package() {
        let (ws, authority, principal, leaf, payload, _) = fixture();
        let device = crypto::device_from_seed(&[9u8; 32]);
        let pkg = AuthoritySharePackage::seal(
            &ws,
            &authority,
            "ceremony-1",
            &principal,
            &leaf,
            &payload,
            &[
                SlotSpec::WindowsDpapi {
                    wrapped_dek: vec![0u8; 4],
                },
                SlotSpec::RecoveryKey {
                    recipient: device.clone(),
                },
                SlotSpec::Passphrase {
                    passphrase: "pass".into(),
                    salt: [1u8; 16],
                    params: fast(),
                },
            ],
        )
        .unwrap();
        assert_eq!(pkg.key_slots.len(), 3);
        // The recovery-key slot alone.
        assert_eq!(
            pkg.open(&UnlockKey::RecoveryKey {
                seed: [9u8; 32],
                me: device,
            })
            .unwrap(),
            payload
        );
        // The passphrase slot alone.
        assert_eq!(
            pkg.open(&UnlockKey::Passphrase("pass".into())).unwrap(),
            payload
        );
    }

    /// A DPAPI-only package is exactly the failure this module exists to
    /// prevent: openable today, worthless on any other machine.
    #[test]
    fn a_dpapi_only_package_is_not_portable() {
        let (ws, authority, principal, leaf, payload, _) = fixture();
        let pkg = AuthoritySharePackage::seal(
            &ws,
            &authority,
            "ceremony-1",
            &principal,
            &leaf,
            &payload,
            &[SlotSpec::WindowsDpapi {
                wrapped_dek: vec![0u8; 4],
            }],
        )
        .unwrap();
        assert!(
            !pkg.has_portable_slot(),
            "a DPAPI-only share is one profile loss from gone"
        );
    }

    #[test]
    fn a_package_needs_at_least_one_slot() {
        let (ws, authority, principal, leaf, payload, _) = fixture();
        assert!(AuthoritySharePackage::seal(
            &ws,
            &authority,
            "ceremony-1",
            &principal,
            &leaf,
            &payload,
            &[]
        )
        .is_err());
    }

    /// Verification compares against expectations rather than reading the
    /// package's claims about itself.
    #[test]
    fn verification_rejects_a_package_from_the_wrong_context() {
        let (ws, authority, principal, leaf, payload, group_key) = fixture();
        let pkg = AuthoritySharePackage::seal(
            &ws,
            &authority,
            "ceremony-1",
            &principal,
            &leaf,
            &payload,
            &[SlotSpec::Passphrase {
                passphrase: "pass".into(),
                salt: [1u8; 16],
                params: fast(),
            }],
        )
        .unwrap();
        let key = UnlockKey::Passphrase("pass".into());
        let good = PackageExpectation {
            space: &ws,
            authority: &authority,
            ceremony: "ceremony-1",
            leaf: &leaf,
            group_key: &group_key,
            index: 1,
        };
        assert!(pkg.verify_and_open(&key, &good).is_ok());

        let other_ws = SpaceId::mint(&SystemUlidSource);
        assert!(pkg
            .verify_and_open(
                &key,
                &PackageExpectation {
                    space: &other_ws,
                    ..good.clone()
                }
            )
            .is_err());
        assert!(pkg
            .verify_and_open(
                &key,
                &PackageExpectation {
                    ceremony: "ceremony-2",
                    ..good.clone()
                }
            )
            .is_err());
        let other_leaf = LeafId::of_principal(&PrincipalId::of_device(&crypto::device_from_seed(
            &[42u8; 32],
        )));
        assert!(pkg
            .verify_and_open(
                &key,
                &PackageExpectation {
                    leaf: &other_leaf,
                    ..good.clone()
                }
            )
            .is_err());
        // And the group key is checked by DERIVING it from the package's own
        // public-key package, not by trusting a field.
        let other_key = crypto::device_from_seed(&[99u8; 32]);
        assert!(pkg
            .verify_and_open(
                &key,
                &PackageExpectation {
                    group_key: &other_key,
                    ..good
                }
            )
            .is_err());
    }

    /// A package whose private material does not work is refused, even though
    /// every public-half check passes and the envelope opens cleanly.
    ///
    /// This is the shape that would otherwise produce an honest custody
    /// attestation for a dead share — and, for an N-of-N arrangement, install an
    /// authority on it.
    #[test]
    fn a_package_with_unusable_private_material_is_refused() {
        let ws = SpaceId::mint(&SystemUlidSource);
        let (forged, pkp, group_key) = crate::dkg::tests_support::share_with_foreign_secret();
        let device = crypto::device_from_seed(&[1u8; 32]);
        let principal = PrincipalId::of_device(&device);
        let leaf = LeafId::of_principal(&principal);
        let config = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 2,
            participants: vec![principal.clone()],
        });
        let authority = AuthorityId::new(group_key.clone(), &config);
        let broken = SharePayload::Frost(FrostSharePayload {
            key_share: forged,
            public_package: pkp.clone(),
            index: 1,
        });
        let pkg = AuthoritySharePackage::seal(
            &ws,
            &authority,
            "ceremony-1",
            &principal,
            &leaf,
            &broken,
            &[SlotSpec::Passphrase {
                passphrase: "pass".into(),
                salt: [1u8; 16],
                params: fast(),
            }],
        )
        .unwrap();
        let key = UnlockKey::Passphrase("pass".into());
        // The public half is impeccable and the envelope opens.
        assert_eq!(crate::dkg::group_key_of_package(&pkp).unwrap(), group_key);
        assert!(pkg.open(&key).is_ok());
        // Verification refuses it anyway.
        let err = pkg
            .verify_and_open(
                &key,
                &PackageExpectation {
                    space: &ws,
                    authority: &authority,
                    ceremony: "ceremony-1",
                    leaf: &leaf,
                    group_key: &group_key,
                    index: 1,
                },
            )
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("does not correspond to its public half"),
            "must reject unusable private material: {err}"
        );
    }

    #[test]
    fn a_package_round_trips_through_its_wire_form() {
        let (ws, authority, principal, leaf, payload, _) = fixture();
        let pkg = AuthoritySharePackage::seal(
            &ws,
            &authority,
            "ceremony-1",
            &principal,
            &leaf,
            &payload,
            &[SlotSpec::Passphrase {
                passphrase: "pass".into(),
                salt: [1u8; 16],
                params: fast(),
            }],
        )
        .unwrap();
        let bytes = postcard::to_stdvec(&pkg).unwrap();
        let back: AuthoritySharePackage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(pkg, back);
        assert_eq!(
            back.open(&UnlockKey::Passphrase("pass".into())).unwrap(),
            payload
        );
    }
}
