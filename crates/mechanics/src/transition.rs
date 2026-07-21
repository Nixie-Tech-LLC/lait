//! Authority transitions: candidate evidence, generation-bound custody, and the
//! transition lifecycle as a deterministic projection.
//!
//! A transition moves the recovery authority from one configuration to another.
//! Its lifecycle is **not** a mutable state field — it is a pure projection over
//! grow-only events, every one bound to a [`TransitionId`], so every replica
//! computes the same state and a liveness failure never leaves two plausible
//! standing configurations.
//!
//! # Trust model
//!
//! Activation evidence is **generation-bound participant attestations plus a
//! candidate-key possession signature** — not an unproven publicly-verifiable
//! DKG proof. Be precise about what that proves:
//!
//! > Participant attestations prove that the named operators *claim* to have
//! > validated and backed up their shares. They are accountable, signed
//! > statements — not a zero-knowledge or publicly-verifiable proof of correct
//! > DKG execution.
//!
//! The possession signature proves the candidate key is *operational under at
//! least one qualified set*: it is a group signature under the new key, carrying
//! the [`crate::dkg::SigningPlan`] and reconstruction witness that produced it.
//! [`CandidateEvidence`] keeps format space for a future reviewed transcript
//! proof to be added without a redesign.

use serde::{Deserialize, Serialize};

use crate::authority::{AuthorityConfigurationId, LeafId};
use crate::dkg::{SigningPlan, TranscriptId};
use crate::ids::DeviceId;
use crate::sigdag::SignedNode;

/// A transition's identity: the content-address of the signed node that **opens**
/// it. Distinct from the proposal's transcript id, so refresh/repair/reshare
/// against an unchanged configuration get distinct transition ids and never
/// collide with one another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransitionId([u8; 32]);

impl TransitionId {
    pub fn of(node: &SignedNode) -> Option<Self> {
        Self::parse_hex(&node.hash())
    }
    pub fn parse_hex(s: &str) -> Option<Self> {
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        data_encoding::HEXLOWER
            .decode(s.as_bytes())
            .ok()?
            .as_slice()
            .try_into()
            .ok()
            .map(Self)
    }
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }
}

/// A proof that a candidate authority exists and is operational — the thing an
/// old authority verifies before signing the rotation that installs it.
///
/// The possession signature is a group signature under `public_key` over a
/// canonical message binding this transition; `signing_plan` is the plan and
/// reconstruction witness that produced it, so an old holder can confirm a
/// *qualified* set operated the key rather than trusting a bare claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateAuthority {
    pub transition: TransitionId,
    /// The DKG that produced the candidate.
    pub proposal: TranscriptId,
    pub configuration: AuthorityConfigurationId,
    pub public_key: DeviceId,
    /// Commitment to the ceremony transcript the candidate came from.
    pub transcript_commitment: [u8; 32],
    /// A group signature under `public_key` proving possession/operability.
    pub possession_signature: Vec<u8>,
    /// The plan (and witness) that produced the possession signature.
    pub signing_plan: SigningPlan,
}

/// A custodian's generation-bound attestation that it holds and has backed up a
/// usable share for one leaf.
///
/// Bound to the exact output generation — a ceremony-and-device marker is
/// insufficient once refresh/repair/resharing can issue successive shares to the
/// same leaf. `public_share_commitment` ties it to the verification material the
/// custodian validated its private share against; `package_commitment` ties it to
/// the exact portable package it exported and reopened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyAck {
    pub transition: TransitionId,
    pub configuration: AuthorityConfigurationId,
    pub share_generation: u64,
    pub leaf: LeafId,
    pub public_share_commitment: [u8; 32],
    pub package_commitment: [u8; 32],
}

/// The evidence that authorizes activating a candidate authority. Versioned and
/// extensible so a future reviewed transcript proof slots in without a redesign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateEvidence {
    /// Version 1 evidence: possession plus per-leaf custody attestations.
    ParticipantAttestationsV1 {
        candidate: CandidateAuthority,
        custody: Vec<CustodyAck>,
    },
    /// Reserved: a publicly-verifiable DKG transcript proof, once one exists that
    /// is demonstrably compatible with Ed25519 and the access structure.
    PublicTranscriptProofV1 { proof: Vec<u8> },
    /// Both, when a reviewed transcript proof augments the attestations.
    CombinedV1 {
        candidate: CandidateAuthority,
        custody: Vec<CustodyAck>,
        proof: Vec<u8>,
    },
}

/// One grow-only event in a transition's history, each bound to its transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionEvent {
    /// The transition was proposed (a new configuration named).
    Proposed {
        transition: TransitionId,
        configuration: AuthorityConfigurationId,
    },
    /// The current authority authorized generating the candidate.
    Authorized { transition: TransitionId },
    /// The candidate is proven to exist and be operational.
    CandidateComplete {
        transition: TransitionId,
        candidate: Box<CandidateAuthority>,
    },
    /// A custodian attested its share for a leaf.
    Custody(CustodyAck),
    /// The rotation installing the candidate was applied on the space plane.
    Activated { transition: TransitionId },
    /// The transition was abandoned (e.g. authorization withdrawn, ceremony died).
    Abandoned { transition: TransitionId },
    /// Another candidate won; this transition is superseded.
    Superseded { transition: TransitionId },
}

impl TransitionEvent {
    pub fn transition(&self) -> TransitionId {
        match self {
            TransitionEvent::Proposed { transition, .. }
            | TransitionEvent::Authorized { transition }
            | TransitionEvent::CandidateComplete { transition, .. }
            | TransitionEvent::Activated { transition }
            | TransitionEvent::Abandoned { transition }
            | TransitionEvent::Superseded { transition } => *transition,
            TransitionEvent::Custody(ack) => ack.transition,
        }
    }
}

/// The lifecycle state a transition projects to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionState {
    /// Proposed, not yet authorized.
    Proposed,
    /// Authorized; the candidate DKG is generating, no candidate yet.
    Generating,
    /// The candidate exists and is operational, but custody is incomplete.
    CustodyPending,
    /// Custody is complete for every required leaf; ready to activate.
    Ready,
    /// The rotation was applied.
    Activated,
    /// Abandoned before activation.
    Abandoned,
    /// Superseded by another candidate.
    Superseded,
}

/// Project a transition's grow-only events to its current state — a pure,
/// deterministic function, so every replica agrees.
///
/// `required_leaves` is the set of leaves whose custody must be attested before
/// `Ready`. **Initial authority creation requires every configured leaf**, so an
/// authority is never activated while naming owners who never received usable
/// shares. Later refresh or repair may pass a narrower set.
///
/// Only custody acks matching the transition, its configuration, and
/// `share_generation` count — a stale ack for an earlier generation does not.
pub fn project(
    events: &[TransitionEvent],
    transition: TransitionId,
    configuration: AuthorityConfigurationId,
    share_generation: u64,
    required_leaves: &[LeafId],
) -> Option<TransitionState> {
    let mine: Vec<&TransitionEvent> = events
        .iter()
        .filter(|e| e.transition() == transition)
        .collect();
    if mine.is_empty() {
        return None;
    }
    let has = |f: &dyn Fn(&TransitionEvent) -> bool| mine.iter().any(|e| f(e));

    // Terminal states first. Activation is the successful end; a superseded or
    // abandoned transition that never activated is a failed end.
    if has(&|e| matches!(e, TransitionEvent::Activated { .. })) {
        return Some(TransitionState::Activated);
    }
    if has(&|e| matches!(e, TransitionEvent::Superseded { .. })) {
        return Some(TransitionState::Superseded);
    }
    if has(&|e| matches!(e, TransitionEvent::Abandoned { .. })) {
        return Some(TransitionState::Abandoned);
    }

    if has(&|e| matches!(e, TransitionEvent::CandidateComplete { .. })) {
        // Custody: every required leaf must have a matching, generation-bound ack.
        let acked: std::collections::BTreeSet<&LeafId> = mine
            .iter()
            .filter_map(|e| match e {
                TransitionEvent::Custody(a)
                    if a.configuration == configuration
                        && a.share_generation == share_generation =>
                {
                    Some(&a.leaf)
                }
                _ => None,
            })
            .collect();
        let all = required_leaves.iter().all(|l| acked.contains(l));
        return Some(if all {
            TransitionState::Ready
        } else {
            TransitionState::CustodyPending
        });
    }
    if has(&|e| matches!(e, TransitionEvent::Authorized { .. })) {
        return Some(TransitionState::Generating);
    }
    Some(TransitionState::Proposed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(n: u8) -> TransitionId {
        TransitionId([n; 32])
    }
    fn cfg(n: u8) -> AuthorityConfigurationId {
        // Reuse the Single id as a stand-in distinct value via the public helper.
        let _ = n;
        AuthorityConfigurationId::single()
    }
    fn leaf(n: u8) -> LeafId {
        LeafId::from_string(format!("{n:064x}"))
    }
    fn ack(t: TransitionId, c: AuthorityConfigurationId, gen: u64, l: LeafId) -> TransitionEvent {
        TransitionEvent::Custody(CustodyAck {
            transition: t,
            configuration: c,
            share_generation: gen,
            leaf: l,
            public_share_commitment: [0u8; 32],
            package_commitment: [0u8; 32],
        })
    }

    #[test]
    fn the_lifecycle_advances_through_its_states() {
        let t = tid(1);
        let c = cfg(1);
        let req = vec![leaf(1), leaf(2)];
        let mut ev = vec![TransitionEvent::Proposed {
            transition: t,
            configuration: c,
        }];
        assert_eq!(project(&ev, t, c, 0, &req), Some(TransitionState::Proposed));

        ev.push(TransitionEvent::Authorized { transition: t });
        assert_eq!(
            project(&ev, t, c, 0, &req),
            Some(TransitionState::Generating)
        );

        // A candidate exists but no custody yet.
        ev.push(TransitionEvent::CandidateComplete {
            transition: t,
            candidate: Box::new(dummy_candidate(t, c)),
        });
        assert_eq!(
            project(&ev, t, c, 0, &req),
            Some(TransitionState::CustodyPending)
        );

        // One of two leaves acked → still pending.
        ev.push(ack(t, c, 0, leaf(1)));
        assert_eq!(
            project(&ev, t, c, 0, &req),
            Some(TransitionState::CustodyPending)
        );

        // Both acked → Ready.
        ev.push(ack(t, c, 0, leaf(2)));
        assert_eq!(project(&ev, t, c, 0, &req), Some(TransitionState::Ready));

        // Activated is terminal.
        ev.push(TransitionEvent::Activated { transition: t });
        assert_eq!(
            project(&ev, t, c, 0, &req),
            Some(TransitionState::Activated)
        );
    }

    #[test]
    fn a_stale_generation_ack_does_not_count() {
        let t = tid(1);
        let c = cfg(1);
        let req = vec![leaf(1)];
        let ev = vec![
            TransitionEvent::CandidateComplete {
                transition: t,
                candidate: Box::new(dummy_candidate(t, c)),
            },
            ack(t, c, 7, leaf(1)), // generation 7, but we require generation 8
        ];
        assert_eq!(
            project(&ev, t, c, 8, &req),
            Some(TransitionState::CustodyPending),
            "an ack for the wrong generation does not satisfy custody"
        );
    }

    #[test]
    fn abandoned_and_superseded_are_terminal() {
        let t = tid(1);
        let c = cfg(1);
        let ev = vec![
            TransitionEvent::Authorized { transition: t },
            TransitionEvent::Abandoned { transition: t },
        ];
        assert_eq!(project(&ev, t, c, 0, &[]), Some(TransitionState::Abandoned));

        let ev = vec![
            TransitionEvent::Authorized { transition: t },
            TransitionEvent::Superseded { transition: t },
        ];
        assert_eq!(
            project(&ev, t, c, 0, &[]),
            Some(TransitionState::Superseded)
        );
    }

    #[test]
    fn events_for_other_transitions_are_ignored() {
        let t = tid(1);
        let other = tid(2);
        let c = cfg(1);
        let ev = vec![
            TransitionEvent::Proposed {
                transition: t,
                configuration: c,
            },
            TransitionEvent::Activated { transition: other },
        ];
        assert_eq!(
            project(&ev, t, c, 0, &[]),
            Some(TransitionState::Proposed),
            "another transition's activation does not affect this one"
        );
        assert_eq!(project(&ev, tid(9), c, 0, &[]), None, "unknown transition");
    }

    fn dummy_candidate(t: TransitionId, c: AuthorityConfigurationId) -> CandidateAuthority {
        CandidateAuthority {
            transition: t,
            proposal: TranscriptId::parse_hex(&"a".repeat(64)).unwrap(),
            configuration: c,
            public_key: crate::crypto::device_from_seed(&[1u8; 32]),
            transcript_commitment: [0u8; 32],
            possession_signature: vec![],
            signing_plan: dummy_plan(),
        }
    }

    fn dummy_plan() -> SigningPlan {
        SigningPlan {
            signing: TranscriptId::parse_hex(&"b".repeat(64)).unwrap(),
            authority: crate::authority::AuthorityId::single(crate::crypto::device_from_seed(
                &[2u8; 32],
            )),
            message_commitment: [0u8; 32],
            signers: vec![],
            commitments: std::collections::BTreeMap::new(),
            witness: crate::dkg::AccessWitness::FrostThreshold {
                k: 1,
                participant_indices: vec![],
            },
        }
    }
}
