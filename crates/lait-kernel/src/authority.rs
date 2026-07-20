//! Scheme-neutral vocabulary for the recovery-authority lifecycle.
//!
//! The space plane understands exactly one thing: a public key that verifies one
//! ordinary signature over a [`crate::space::SpaceOp`]. Everything about *how*
//! that key is operated — one holder, a flat threshold, or eventually a
//! compiled ownership policy — lives above the plane and is described here.
//!
//! These types exist so the lifecycle (propose → authorize → generate → install)
//! can be written once and survive a second signing backend. They deliberately
//! carry **no** policy semantics: no trees, no access matrices, no
//! reconstruction vectors. A scheme's specifics ride in an opaque
//! [`AuthorityConfiguration::payload`], so adding a backend does not reshape the
//! lifecycle around it.
//!
//! # The distinction that matters most
//!
//! **Rotation** replaces public key `Y1` with a different `Y2`. **Resharing**
//! redistributes the *same* private scalar under a new arrangement, keeping `Y`.
//! They are different operations with different authorization stories, and
//! conflating them is how a system ends up unable to say whether a policy change
//! invalidated existing signatures. [`AuthorityTransition`] keeps them apart from
//! the start; only `RotateKey` is implemented today.

use serde::{Deserialize, Serialize};

use crate::ids::UserId;

/// Domain separating configuration-id hashing from every other hash in the
/// system, so a configuration id can never collide with a transcript id or an
/// op hash by construction.
const CONFIG_ID_DOMAIN: &[u8] = b"lait/space/1/authority/config-id";

/// How an authority's private half is operated.
///
/// The scheme is what tells a participant which decoder to apply to
/// [`AuthorityConfiguration::payload`]. An unrecognized scheme must be rejected
/// rather than guessed at — a node that cannot understand a configuration cannot
/// safely take part in a ceremony that uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AuthorityScheme {
    /// One holder with the whole secret. The bootstrap state.
    Single,
    /// Flat K-of-N FROST over a participant list (RFC 9591).
    FrostThreshold,
    /// A compiled ownership policy over a general access structure. Reserved
    /// until the general-access backend is production-ready.
    GeneralAccess,
}

/// A scheme plus its opaque configuration bytes.
///
/// The payload is not interpreted here. That is the point: the lifecycle moves
/// configurations around without understanding them, and only the backend that
/// declares a scheme decodes its payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityConfiguration {
    pub version: u16,
    pub scheme: AuthorityScheme,
    pub payload: Vec<u8>,
}

impl AuthorityConfiguration {
    /// A configuration for the bootstrap single-holder authority. The key itself
    /// identifies it, so the payload is empty.
    pub fn single() -> Self {
        AuthorityConfiguration {
            version: 1,
            scheme: AuthorityScheme::Single,
            payload: Vec::new(),
        }
    }

    /// A flat K-of-N FROST configuration.
    pub fn frost_threshold(config: &FrostThresholdConfig) -> Self {
        AuthorityConfiguration {
            version: 1,
            scheme: AuthorityScheme::FrostThreshold,
            payload: postcard::to_stdvec(config).expect("encode frost config"),
        }
    }

    /// Decode this configuration as flat FROST, or `None` if it is not one.
    pub fn as_frost_threshold(&self) -> Option<FrostThresholdConfig> {
        (self.scheme == AuthorityScheme::FrostThreshold)
            .then(|| postcard::from_bytes(&self.payload).ok())
            .flatten()
    }

    /// A general-access configuration over a compiled ownership policy.
    pub fn general_access(config: &GeneralAccessConfig) -> Self {
        AuthorityConfiguration {
            version: 1,
            scheme: AuthorityScheme::GeneralAccess,
            payload: postcard::to_stdvec(config).expect("encode general-access config"),
        }
    }

    /// Decode this configuration as general-access, or `None`.
    pub fn as_general_access(&self) -> Option<GeneralAccessConfig> {
        (self.scheme == AuthorityScheme::GeneralAccess)
            .then(|| postcard::from_bytes(&self.payload).ok())
            .flatten()
    }

    /// The content-address of this configuration.
    pub fn id(&self) -> AuthorityConfigurationId {
        let mut h = blake3::Hasher::new();
        h.update(CONFIG_ID_DOMAIN);
        h.update(&postcard::to_stdvec(self).expect("encode authority configuration"));
        AuthorityConfigurationId(*h.finalize().as_bytes())
    }

    /// Whether this configuration is well formed *for its declared scheme*.
    ///
    /// Checked by every acceptor rather than trusted from the proposer: the
    /// proposing node sorts and validates, but a hostile one does not, and a
    /// duplicated participant would corrupt the index-to-participant mapping the
    /// whole ceremony depends on.
    pub fn is_well_formed(&self) -> bool {
        match self.scheme {
            AuthorityScheme::Single => self.payload.is_empty(),
            AuthorityScheme::FrostThreshold => self
                .as_frost_threshold()
                .is_some_and(|c| c.is_well_formed()),
            // Structural well-formedness only: the payload decodes and its leaf
            // set is nonempty and distinct. Whether the committed access
            // structure actually implements the named policy is a *semantic*
            // check that needs the policy tree — `compile::verify_compilation`
            // during transition acceptance — not something derivable from the
            // config alone.
            AuthorityScheme::GeneralAccess => self
                .as_general_access()
                .is_some_and(|c| c.is_structurally_well_formed()),
        }
    }
}

/// The content-address of an [`AuthorityConfiguration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthorityConfigurationId([u8; 32]);

impl AuthorityConfigurationId {
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }
    /// The configuration id of the bootstrap single-holder authority.
    ///
    /// Every workspace is born `Single` (the founder mints one solo recovery
    /// key), so this is the standing configuration at genesis and the value an
    /// old key-only `Rotate` — which never named a configuration — replays to.
    /// Content-addressed like any other, just from a fixed input.
    pub fn single() -> Self {
        AuthorityConfiguration::single().id()
    }
}

/// Flat K-of-N FROST over a fixed participant list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrostThresholdConfig {
    pub k: u16,
    /// Participants, sorted and deduped. Position + 1 is the FROST index.
    pub participants: Vec<PrincipalId>,
}

impl FrostThresholdConfig {
    /// Sorted, deduped, at least two participants, `1 <= k <= n`.
    ///
    /// `k >= 1` is checked here, but note RFC 9591 itself requires `k >= 2`;
    /// a 1-of-N "threshold" is a single holder wearing a threshold's clothes and
    /// the FROST implementation rejects it. Callers building a configuration
    /// should use [`AuthorityScheme::Single`] for that case.
    pub fn is_well_formed(&self) -> bool {
        let n = self.participants.len();
        let mut sorted = self.participants.clone();
        sorted.sort();
        sorted.dedup();
        n >= 2
            && sorted.len() == n
            && sorted == self.participants
            && self.k >= 1
            && self.k as usize <= n
    }

    /// This principal's 1-based FROST index, if it is a participant.
    pub fn index_of(&self, who: &PrincipalId) -> Option<u16> {
        self.participants
            .iter()
            .position(|p| p == who)
            .map(|i| i as u16 + 1)
    }
}

/// A general-access authority: the ownership policy, the exact compiler
/// output that realizes it, and the immutable leaf snapshot.
///
/// The three identities are all here, distinct: `policy` (the human rule),
/// `access_structure` (the compiler output), and — via this whole config's id —
/// the deployed arrangement. An acceptor recomputes the expansion from `policy`
/// and `leaves`, recompiles, and requires the result to equal `access_structure`
/// (`compile::verify_compilation`); only then is the arrangement trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralAccessConfig {
    pub policy: crate::policy::PolicyId,
    pub access_structure: crate::compile::AccessStructureCommitment,
    /// The committed leaf snapshot, in the compiler's row order.
    pub leaves: Vec<crate::expand::LeafDescriptor>,
}

impl GeneralAccessConfig {
    /// Structural well-formedness: a nonempty, distinct leaf set. This is *not*
    /// proof the access structure implements the policy — that is a semantic
    /// check requiring recompilation of the policy tree.
    pub fn is_structurally_well_formed(&self) -> bool {
        if self.leaves.is_empty() {
            return false;
        }
        let distinct: std::collections::BTreeSet<&LeafId> =
            self.leaves.iter().map(|l| &l.leaf).collect();
        distinct.len() == self.leaves.len()
    }
}

/// An ownership identity in a configuration.
///
/// For flat FROST a principal is one device key, so principal and leaf coincide.
/// They are separate types because a principal can expand into a whole
/// policy branch — a federated founder — at which point one principal owns
/// several leaves and collapsing them would lose the distinction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PrincipalId(String);

impl PrincipalId {
    pub fn of_device(user: &UserId) -> Self {
        PrincipalId(user.as_str().to_string())
    }
    /// The device this principal is, when it is a direct device principal.
    pub fn as_device(&self) -> Option<UserId> {
        UserId::parse(&self.0)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A cryptographic participant in the compiled access structure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeafId(String);

impl LeafId {
    /// The leaf of a flat-FROST principal, where principal and leaf coincide.
    /// Principal-to-leaf expansion instead mints per-occurrence leaf ids.
    pub fn of_principal(p: &PrincipalId) -> Self {
        LeafId(p.0.clone())
    }
    /// A leaf id from an opaque string (a content-addressed hex id minted during
    /// principal-to-leaf expansion). Not validated; the caller owns the derivation.
    pub fn from_string(s: String) -> Self {
        LeafId(s)
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A public key together with the arrangement operating it.
///
/// Carrying the configuration id alongside the key is what lets a proposal name
/// the authority it replaces unambiguously. Without it, "the current authority"
/// would mean only "the current key", and a proposal authorized before a
/// configuration change could be replayed after one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityId {
    pub public_key: UserId,
    pub configuration: AuthorityConfigurationId,
}

impl AuthorityId {
    pub fn new(public_key: UserId, configuration: &AuthorityConfiguration) -> Self {
        AuthorityId {
            public_key,
            configuration: configuration.id(),
        }
    }
    /// The bootstrap authority for a solo recovery key.
    pub fn single(public_key: UserId) -> Self {
        Self::new(public_key, &AuthorityConfiguration::single())
    }
}

/// A change to the authority.
///
/// The two variants are NOT interchangeable and must stay distinct in code, docs
/// and UI. `RotateKey` produces a different public key, so anything pinned to
/// the old key must be re-pinned. `Reshare` keeps the key and changes only who
/// can operate it, so nothing downstream needs to know it happened. Phase B
/// implements rotation only; resharing needs a reviewed same-key protocol that
/// does not reconstruct the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityTransition {
    RotateKey {
        from: AuthorityId,
        next_configuration: AuthorityConfigurationId,
        next_public_key: UserId,
    },
    /// Reserved until proactive same-key resharing is implemented.
    Reshare {
        authority: AuthorityId,
        next_configuration: AuthorityConfigurationId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principals(seeds: &[u8]) -> Vec<PrincipalId> {
        let mut v: Vec<PrincipalId> = seeds
            .iter()
            .map(|n| PrincipalId::of_device(&crate::crypto::user_from_seed(&[*n; 32])))
            .collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn a_configuration_id_is_stable_and_content_addressed() {
        let a = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 2,
            participants: principals(&[1, 2, 3]),
        });
        let same = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 2,
            participants: principals(&[1, 2, 3]),
        });
        assert_eq!(a.id(), same.id(), "same content, same id");

        // Every field is covered.
        let other_k = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 3,
            participants: principals(&[1, 2, 3]),
        });
        assert_ne!(a.id(), other_k.id(), "threshold is committed");
        let other_set = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 2,
            participants: principals(&[1, 2, 4]),
        });
        assert_ne!(a.id(), other_set.id(), "participants are committed");
        assert_ne!(
            a.id(),
            AuthorityConfiguration::single().id(),
            "scheme is committed"
        );
    }

    #[test]
    fn well_formedness_is_checked_per_scheme() {
        assert!(AuthorityConfiguration::single().is_well_formed());
        // Single carries no payload; anything else is malformed.
        let bogus = AuthorityConfiguration {
            version: 1,
            scheme: AuthorityScheme::Single,
            payload: vec![1],
        };
        assert!(!bogus.is_well_formed());

        let good = FrostThresholdConfig {
            k: 2,
            participants: principals(&[1, 2, 3]),
        };
        assert!(AuthorityConfiguration::frost_threshold(&good).is_well_formed());

        // A duplicated participant would corrupt the index mapping.
        let mut dup = good.clone();
        dup.participants.push(dup.participants[0].clone());
        assert!(!dup.is_well_formed());

        // Unsorted: the index mapping must be canonical, not proposer-chosen.
        let mut unsorted = good.clone();
        unsorted.participants.reverse();
        assert!(!unsorted.is_well_formed());

        // k out of range, and a one-participant "group".
        assert!(!FrostThresholdConfig {
            k: 4,
            participants: principals(&[1, 2, 3])
        }
        .is_well_formed());
        assert!(!FrostThresholdConfig {
            k: 0,
            participants: principals(&[1, 2])
        }
        .is_well_formed());
        assert!(!FrostThresholdConfig {
            k: 1,
            participants: principals(&[1])
        }
        .is_well_formed());
    }

    /// A scheme this build does not implement must be refused, not treated as
    /// acceptable-because-undecodable.
    #[test]
    fn an_unimplemented_scheme_is_not_well_formed() {
        let reserved = AuthorityConfiguration {
            version: 1,
            scheme: AuthorityScheme::GeneralAccess,
            payload: vec![],
        };
        assert!(!reserved.is_well_formed());
        assert!(reserved.as_frost_threshold().is_none());
    }

    #[test]
    fn the_frost_index_is_position_plus_one() {
        let ps = principals(&[1, 2, 3]);
        let c = FrostThresholdConfig {
            k: 2,
            participants: ps.clone(),
        };
        assert_eq!(c.index_of(&ps[0]), Some(1));
        assert_eq!(c.index_of(&ps[2]), Some(3));
        assert_eq!(
            c.index_of(&PrincipalId::of_device(&crate::crypto::user_from_seed(
                &[9u8; 32]
            ))),
            None
        );
    }

    #[test]
    fn an_authority_id_distinguishes_key_from_arrangement() {
        let key = crate::crypto::user_from_seed(&[1u8; 32]);
        let two_of_three = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 2,
            participants: principals(&[1, 2, 3]),
        });
        let three_of_three = AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k: 3,
            participants: principals(&[1, 2, 3]),
        });
        // Same key, different arrangement ⇒ different authority. This is what
        // stops a proposal authorized under one configuration being replayed
        // after the configuration changed.
        assert_ne!(
            AuthorityId::new(key.clone(), &two_of_three),
            AuthorityId::new(key, &three_of_three)
        );
    }
}
