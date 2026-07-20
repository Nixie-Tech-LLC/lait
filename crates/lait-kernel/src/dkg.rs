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

use crate::authority::{
    AuthorityConfiguration, AuthorityId, AuthorityScheme, FrostThresholdConfig, PrincipalId,
};
use crate::ids::{UserId, WorkspaceId};
use crate::sigdag::{self, SignedNode};

/// Signing domain for FROST ceremony contributions (bulletin-board packages).
///
/// `/2` is the transcript-identity format. v1 keyed every op by a random
/// `session: [u8; 16]` that nothing bound to the proposal defining it, so a
/// signature-valid proposal from any device could supply the configuration for
/// a session it did not open. Bumping the domain means v1 events fail
/// [`SignedNode::verify_sig`] and are ignored rather than mis-parsed — the safe
/// failure. Any in-flight v1 ceremony must be restarted.
pub const CEREMONY_DOMAIN: &[u8] = b"lait/space/1/ceremony/2";

/// The content-address of the signed node that **opened** a transcript: a DKG's
/// `DkgPropose`, or a signing session's `SignRequest`.
///
/// Two properties of [`SignedNode::hash`] shape this type:
///
/// - it covers `op ‖ author ‖ sorted(parents)` and **excludes the signature**,
///   which is what we want — Ed25519 signature bytes are not a canonical
///   function of the message across implementations, so hashing the envelope
///   could yield two ids for one proposal;
/// - it is deliberately **not** domain- or workspace-bound (see its docs), so a
///   `TranscriptId` is only meaningful within the plane that produced it. Never
///   use one as a key in anything shared across planes, and keep the explicit
///   `nonce` on both openers: Ed25519 signing is deterministic (RFC 8032), so
///   without it a device re-opening an identical transcript would collide.
///
/// Only [`TranscriptId::to_hex`] ever becomes a filename, and [`Self::parse_hex`]
/// is strict — permissive hex would let two spellings name one id, and an
/// unvalidated remote string could carry path separators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TranscriptId([u8; 32]);

impl TranscriptId {
    /// The id of the transcript this node opens.
    pub fn of(node: &SignedNode) -> Option<Self> {
        Self::parse_hex(&node.hash())
    }
    /// Strict canonical lowercase hex, exactly 64 chars. Rejects everything
    /// else, including uppercase, path separators and `..`.
    pub fn parse_hex(s: &str) -> Option<Self> {
        if s.len() != 64
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let raw = data_encoding::HEXLOWER.decode(s.as_bytes()).ok()?;
        raw.as_slice().try_into().ok().map(Self)
    }
    /// The canonical form — the only one that may become a path component.
    pub fn to_hex(&self) -> String {
        data_encoding::HEXLOWER.encode(&self.0)
    }
}

/// What a threshold signature is *for*. Carried on the request so the signing
/// message is domain-separated and the finished signature is installed on the
/// matching plane.
///
/// This exists because a group must be able to threshold-sign a ceremony
/// proposal (group→group reconfiguration), and the signing path would otherwise
/// build every message under [`crate::space::SPACE_EVENT_DOMAIN`] and hand the
/// result to the space plane. Postcard is not self-describing and
/// `CeremonyOp::DkgPropose` shares variant tag 0 with `SpaceOp::Recover`, so a
/// cross-target signature is not merely misfiled — it is a type-confusion
/// primitive that could reinterpret attacker-chosen bytes as a re-root op
/// carrying a genuine group signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignTarget {
    /// A [`crate::space::SpaceOp`] — `Recover` or `Rotate`.
    SpaceOp,
    /// An [`AuthorityGrant`] authorizing a new key ceremony (group→group
    /// reconfiguration).
    AuthorityGrant,
}

/// One participant's contribution to a FROST ceremony, posted to the shared
/// bulletin board and signed by the contributing **device** (the sigdag author).
///
/// Openers (`DkgPropose`, `SignRequest`) carry no transcript field — they
/// *define* one, as the hash of the node carrying them, which the op alone
/// cannot know. Callers must take the id from the enclosing [`SignedNode`];
/// [`CeremonyOp::dkg`] and [`CeremonyOp::signing`] return `None` for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CeremonyOp {
    /// Open a key-ceremony transcript. Authorization is *not* the device
    /// signature on this node — see [`AuthorityGrant`].
    DkgPropose(KeyCeremonyProposal),
    /// The recovery authority's authorization for a `DkgPropose`, as an ordinary
    /// signed node under [`AUTHORITY_GRANT_DOMAIN`].
    ///
    /// Two signatures, two jobs: the **outer** ceremony signature authenticates
    /// the device that posted this to the board, and the **inner** grant
    /// signature is the authorization proper. Carried as its own object because
    /// what it signs is the proposal's *hash*, which cannot be a field of the
    /// proposal.
    DkgAuthorize(SignedAuthorityGrant),
    /// A broadcast DKG round-1 package.
    DkgRound1 { dkg: TranscriptId, package: Vec<u8> },
    /// A DKG round-2 secret share, sealed to recipient device `to`.
    DkgRound2 {
        dkg: TranscriptId,
        to: UserId,
        sealed: Vec<u8>,
    },
    /// Open a threshold-signing transcript over `op`.
    SignRequest {
        nonce: [u8; 16],
        /// The DKG transcript whose group key is being asked to sign. Binds the
        /// request to one authority rather than "whichever group is current".
        authority: TranscriptId,
        target: SignTarget,
        /// The device permitted to publish this transcript's [`SigningPlan`].
        ///
        /// Must be a participant of the named authority: retention drops rounds
        /// from non-participants, so a plan from an outsider is discarded before
        /// anyone could act on it. Coordination is a holder's job.
        ///
        /// Any-K needs *someone* to choose which K holders sign, and that choice
        /// must be a single canonical object every signer binds to. Naming the
        /// chooser in the request means the role cannot be seized later: a plan
        /// from anyone else is not a plan. If the coordinator goes away, the
        /// answer is a new transcript with fresh nonces — never a second
        /// coordinator over the same commitments.
        coordinator: UserId,
        op: Vec<u8>,
    },
    /// The coordinator's chosen signing plan for a transcript.
    SignPlan {
        signing: TranscriptId,
        plan: Vec<u8>,
    },
    /// A custodian's attestation that it has exported its share package for
    /// `dkg` and reopened it through a **portable** slot.
    ///
    /// Required before an indispensable arrangement (every holder needed) may be
    /// installed. Without it, an N-of-N authority can be created in a state where
    /// one holder's share exists only behind a Windows profile — and the
    /// workspace discovers this on the day it needs to recover, which is the day
    /// it is too late. The attestation is a signed board event rather than local
    /// state so that no *other* node can install the rotation before every
    /// custodian has actually made the check.
    CustodyAck { dkg: TranscriptId },
    /// A broadcast signing round-1 commitment.
    SignRound1 {
        signing: TranscriptId,
        commitments: Vec<u8>,
    },
    /// A broadcast signing round-2 signature share (not secret).
    SignRound2 {
        signing: TranscriptId,
        share: Vec<u8>,
    },
}

impl CeremonyOp {
    /// The DKG transcript this op belongs to, where the op alone determines it.
    /// `None` for openers — their id is the hash of the enclosing node.
    pub fn dkg(&self) -> Option<TranscriptId> {
        match self {
            CeremonyOp::DkgRound1 { dkg, .. } | CeremonyOp::DkgRound2 { dkg, .. } => Some(*dkg),
            _ => None,
        }
    }
    /// The signing transcript this op belongs to, where the op alone determines
    /// it. `None` for openers.
    pub fn signing(&self) -> Option<TranscriptId> {
        match self {
            CeremonyOp::SignRound1 { signing, .. } | CeremonyOp::SignRound2 { signing, .. } => {
                Some(*signing)
            }
            _ => None,
        }
    }
}

/// A proposed key ceremony: what arrangement to create, and what it replaces.
///
/// Scheme-neutral on purpose. The lifecycle — propose, authorize, generate,
/// install — is identical whether the outcome is a flat threshold or, later, a
/// compiled policy, so the proposal carries an opaque
/// [`AuthorityConfiguration`] rather than threshold fields. Adding a backend
/// must not reshape the ceremony around it.
///
/// The proposal's signed-node hash is its transcript identity, and that hash
/// therefore commits to everything above: scheme, configuration payload,
/// transition kind, the authority being replaced, the nonce, and the
/// workspace-scoped envelope. An [`AuthorityGrant`] needs only the id because
/// the id already covers the whole decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCeremonyProposal {
    /// Uniqueness. Ed25519 signing is deterministic (RFC 8032), so without it a
    /// device re-proposing an identical ceremony would collide on hash.
    pub nonce: [u8; 16],
    pub configuration: AuthorityConfiguration,
    pub transition: ProposedTransition,
}

/// What kind of change a proposal asks for.
///
/// Naming the *current* authority — key and arrangement both — is what stops a
/// proposal authorized under one authority being replayed against another. A
/// grant says "this ceremony may run"; it must not silently become "this
/// ceremony may run against whatever authority happens to be standing later".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposedTransition {
    /// Create a new key under a new arrangement, replacing `current`.
    RotateKey { current: AuthorityId },
    /// Redistribute the same key under a new arrangement. Reserved until the
    /// proactive resharing protocol is production-ready:
    /// same-key resharing needs a reviewed protocol that never reconstructs the
    /// secret, so accepting one here would promise something unimplemented.
    Reshare { authority: AuthorityId },
}

impl KeyCeremonyProposal {
    /// The flat-FROST configuration this proposal creates, if it is one and it
    /// is well formed for a transition this phase implements.
    ///
    /// Returns `None` for a `Reshare` — the variant exists so the format does
    /// not need changing when resharing is enabled, not so it can be honored now.
    pub fn frost_config(&self) -> Option<FrostThresholdConfig> {
        if !matches!(self.transition, ProposedTransition::RotateKey { .. }) {
            return None;
        }
        if self.configuration.scheme != AuthorityScheme::FrostThreshold
            || !self.configuration.is_well_formed()
        {
            return None;
        }
        self.configuration.as_frost_threshold()
    }

    /// The authority this proposal replaces or reshares.
    pub fn current_authority(&self) -> &AuthorityId {
        match &self.transition {
            ProposedTransition::RotateKey { current } => current,
            ProposedTransition::Reshare { authority } => authority,
        }
    }

    /// Participant devices, in canonical index order, for a flat-FROST proposal.
    pub fn frost_devices(&self) -> Option<Vec<UserId>> {
        self.frost_config()?
            .participants
            .iter()
            .map(|p| p.as_device())
            .collect()
    }
}

/// Domain for an authority grant. Distinct from [`CEREMONY_DOMAIN`] and from
/// [`crate::space::SPACE_EVENT_DOMAIN`], so a grant can never verify as a
/// ceremony contribution or a space operation, nor either as a grant.
pub const AUTHORITY_GRANT_DOMAIN: &[u8] = b"lait/space/1/ceremony/2/authority-grant";

/// The recovery authority's statement that one exact key ceremony may run.
///
/// The proposal's hash already commits to the whole configuration — scheme,
/// threshold, participants, transition, nonce, workspace envelope — so naming it
/// is the entire content of the decision. A struct rather than bare bytes so a
/// later field (a policy commitment, say) can ride the same object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityGrant {
    pub proposal: TranscriptId,
}

/// A grant carried as an ordinary signed node, authored by the recovery
/// authority itself.
///
/// This is the point of the shape: a **solo** authority signs it with
/// [`sigdag::sign_node`], and a **group** authority produces the byte-identical
/// object by FROST-signing [`sigdag::payload_to_sign`] and assembling with
/// [`sigdag::assemble_signed`]. One object, one verifier, no second
/// representation of the same decision to keep in sync — and no detached-message
/// mode inside threshold signing, which is where signature-confusion bugs live.
pub type SignedAuthorityGrant = SignedNode;

/// Build a flat-FROST rotation proposal replacing `current`.
pub fn frost_rotation_proposal(
    nonce: [u8; 16],
    k: u16,
    participants: Vec<PrincipalId>,
    current: AuthorityId,
) -> KeyCeremonyProposal {
    KeyCeremonyProposal {
        nonce,
        configuration: AuthorityConfiguration::frost_threshold(&FrostThresholdConfig {
            k,
            participants,
        }),
        transition: ProposedTransition::RotateKey { current },
    }
}

/// Author an authority grant with a solo recovery secret.
pub fn sign_authority_grant(
    recovery_seed: &[u8; 32],
    ws: &WorkspaceId,
    proposal: &TranscriptId,
) -> SignedAuthorityGrant {
    let grant = AuthorityGrant {
        proposal: *proposal,
    };
    sigdag::sign_node(
        AUTHORITY_GRANT_DOMAIN,
        recovery_seed,
        postcard::to_stdvec(&grant).expect("encode authority grant"),
        vec![],
        ws.as_str(),
    )
}

/// The bytes a group must FROST-sign to produce a grant for `proposal` under
/// `group_key`. The aggregated signature assembles into a node identical in
/// shape to [`sign_authority_grant`]'s output.
pub fn authority_grant_payload(
    ws: &WorkspaceId,
    group_key: &UserId,
    proposal: &TranscriptId,
) -> (Vec<u8>, [u8; 32]) {
    let grant = AuthorityGrant {
        proposal: *proposal,
    };
    let op = postcard::to_stdvec(&grant).expect("encode authority grant");
    let payload = sigdag::payload_to_sign(AUTHORITY_GRANT_DOMAIN, &op, group_key, &[], ws.as_str());
    (op, payload)
}

/// The proposal a grant authorizes, if it is a well-formed grant for this
/// workspace. `None` otherwise.
///
/// Checks, in order: the signature verifies under the grant domain for this
/// workspace; the payload decodes as an [`AuthorityGrant`]; and the node has no
/// parents. Parents are rejected because a grant is a standalone statement — an
/// unconstrained parent list is signed-over data with no defined meaning, and
/// leaving it free would let two grants for one decision differ in their hash
/// and stop converging.
///
/// Says nothing about *whose* key signed it: the caller must still check the
/// author against the standing recovery authority.
pub fn authority_grant_of(node: &SignedAuthorityGrant, ws: &WorkspaceId) -> Option<AuthorityGrant> {
    if !node.verify_sig(AUTHORITY_GRANT_DOMAIN, ws.as_str()) || !node.parents.is_empty() {
        return None;
    }
    postcard::from_bytes::<AuthorityGrant>(&node.op).ok()
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

/// A signature-verified board entry: who posted it, the id of the node (which
/// *is* the transcript id when the op is an opener), and the op.
#[derive(Debug, Clone)]
pub struct Verified {
    pub author: UserId,
    pub id: TranscriptId,
    pub op: CeremonyOp,
}

/// One DKG transcript's verified contributions.
#[derive(Debug, Clone, Default)]
pub struct DkgTranscript {
    /// The opening proposal, if it has been seen.
    pub proposal: Option<Verified>,
    /// **Every** distinct signature-valid authorization, keyed by signing key.
    ///
    /// A map rather than a single slot because a signature-valid authorization
    /// from the *wrong* key must not be able to displace the right one. With one
    /// slot, whichever landed later won, so anyone able to post to the board
    /// could suppress a proposal by spamming authorizations — a denial of
    /// service on recovery, decided by CRDT iteration order rather than by
    /// authority. Keying by signer also makes re-posts of one decision converge.
    ///
    /// Signatures are checked here; whether a signer is the *standing* authority
    /// is the caller's rule, since it needs the space plane.
    pub auths: BTreeMap<UserId, SignedAuthorityGrant>,
    /// Round packages referencing this transcript (openers excluded).
    pub rounds: Vec<Verified>,
}

/// One signing transcript's verified contributions.
#[derive(Debug, Clone, Default)]
pub struct SignTranscript {
    pub request: Option<Verified>,
    pub rounds: Vec<Verified>,
}

impl DkgTranscript {
    /// Devices that have attested portable custody of their share.
    pub fn custody_acks(&self) -> Vec<UserId> {
        self.rounds
            .iter()
            .filter(|v| matches!(v.op, CeremonyOp::CustodyAck { .. }))
            .map(|v| v.author.clone())
            .collect()
    }
}

impl SignTranscript {
    /// The plan for this transcript, if the **named coordinator** published one.
    ///
    /// A plan from any other author is not a plan: the coordinator role is fixed
    /// by the request precisely so it cannot be seized by whoever posts first.
    pub fn plan(&self) -> Option<SigningPlan> {
        let coordinator = match self.request.as_ref().map(|r| &r.op) {
            Some(CeremonyOp::SignRequest { coordinator, .. }) => coordinator.clone(),
            _ => return None,
        };
        self.rounds.iter().find_map(|v| match &v.op {
            CeremonyOp::SignPlan { plan, .. } if v.author == coordinator => {
                postcard::from_bytes::<SigningPlan>(plan).ok()
            }
            _ => None,
        })
    }
}

/// Every verified ceremony contribution, indexed by transcript.
#[derive(Debug, Clone, Default)]
pub struct CeremonyBoard {
    pub dkg: BTreeMap<TranscriptId, DkgTranscript>,
    pub signing: BTreeMap<TranscriptId, SignTranscript>,
}

#[cfg(test)]
thread_local! {
    /// Signature verifications performed by [`parse_board`], so tests can assert
    /// the scan is linear in board size rather than `transcripts × board`.
    pub static VERIFY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Verify and index the whole board in **one pass**.
///
/// Events must be verified before they can identify a session; otherwise unsigned
/// input could manufacture transcripts and amplify work to
/// `transcripts × board`, with both dimensions attacker-controlled. Every event
/// is verified exactly once and failures are dropped before they can name anything.
///
/// Note this establishes *authenticity*, not *authorization*: a validly signed
/// proposal from any device still lands here. Accepting it is
/// the caller's proposal-authorization check, applied before acting on the board.
pub fn parse_board(events: &[SignedNode], ws: &WorkspaceId) -> CeremonyBoard {
    let mut board = CeremonyBoard::default();
    for ev in events {
        #[cfg(test)]
        VERIFY_COUNT.with(|c| c.set(c.get() + 1));
        if !ev.verify_sig(CEREMONY_DOMAIN, ws.as_str()) {
            continue;
        }
        let Ok(op) = postcard::from_bytes::<CeremonyOp>(&ev.op) else {
            continue;
        };
        let Some(id) = TranscriptId::of(ev) else {
            continue;
        };
        let entry = Verified {
            author: ev.author.clone(),
            id,
            op,
        };
        match &entry.op {
            // Openers are keyed by their OWN id — they define the transcript.
            CeremonyOp::DkgPropose { .. } => {
                board.dkg.entry(id).or_default().proposal = Some(entry);
            }
            CeremonyOp::SignRequest { .. } => {
                board.signing.entry(id).or_default().request = Some(entry);
            }
            // Authorizations are filed against the proposal they name, and only
            // if the detached signature actually covers it — an unverifiable one
            // must never occupy the slot a real authorization would fill.
            // The outer signature is already verified above; the inner grant is
            // verified separately, so an invalid outer and an invalid inner are
            // independently rejected and neither can carry the other.
            CeremonyOp::DkgAuthorize(grant) => {
                if let Some(inner) = authority_grant_of(grant, ws) {
                    board
                        .dkg
                        .entry(inner.proposal)
                        .or_default()
                        .auths
                        .insert(grant.author.clone(), grant.clone());
                }
            }
            // Rounds are keyed by the transcript they name.
            CeremonyOp::DkgRound1 { dkg, .. }
            | CeremonyOp::DkgRound2 { dkg, .. }
            | CeremonyOp::CustodyAck { dkg } => {
                let dkg = *dkg;
                board.dkg.entry(dkg).or_default().rounds.push(entry);
            }
            CeremonyOp::SignRound1 { signing, .. }
            | CeremonyOp::SignRound2 { signing, .. }
            | CeremonyOp::SignPlan { signing, .. } => {
                let signing = *signing;
                board.signing.entry(signing).or_default().rounds.push(entry);
            }
        }
    }
    retain(&mut board);
    board
}

/// The dedup key for a round contribution: which round it is, plus whatever
/// else legitimately distinguishes two posts by one author.
///
/// Round 2 of a DKG is the reason this is not simply "which round". Each
/// participant sends a *targeted* secret share to every other participant, so it
/// posts `n - 1` round-2 events, and capping at one per author silently breaks
/// every DKG with more than two participants. It happens to work at n = 2 —
/// which is exactly how such a bug survives a test suite whose ceremonies are
/// all 2-of-2. The recipient therefore belongs in the key: one contribution per
/// author **per recipient**, which still bounds flooding at `n - 1`.
fn round_key(op: &CeremonyOp) -> Option<(u8, &str)> {
    match op {
        CeremonyOp::DkgRound1 { .. } => Some((1, "")),
        CeremonyOp::DkgRound2 { to, .. } => Some((2, to.as_str())),
        CeremonyOp::SignRound1 { .. } => Some((3, "")),
        CeremonyOp::SignRound2 { .. } => Some((4, "")),
        // One plan per author is retained. A coordinator that publishes two is
        // equivocating; keeping the first means every replica honours the same
        // one (board order converges), and a holder already bound to it refuses
        // the other. Retaining both would not help — it would only move the
        // decision to whoever looks second.
        CeremonyOp::SignPlan { .. } => Some((5, "")),
        CeremonyOp::CustodyAck { .. } => Some((6, "")),
        _ => None,
    }
}

/// Drop what can never contribute, so a grow-only board cannot be padded into
/// unbounded retained state.
///
/// Three rules, all structural — authorization is the caller's, since it needs
/// the space plane that this layer cannot see:
///
/// - a transcript with **no opener** is dropped entirely: rounds naming an id
///   nobody opened can never be acted on, and anyone can mint ids;
/// - a DKG round whose author is **not a participant** of that transcript's
///   proposal is dropped (a `SignRequest` names no participants of its own, so
///   signing rounds are filtered against their authority at point of use);
/// - at most **one round of each kind per author per transcript** is kept. Later
///   duplicates were already ignored — `entry().or_insert` takes the first — but
///   they were still retained, so a legitimate participant could flood a
///   transcript they belong to.
///
/// Per-author caps are a backstop, not the mechanism: an attacker can mint
/// arbitrary keys and stay under any per-author limit, which is why the opener
/// and participant rules do the real work.
///
/// **This bounds the materialized projection, not storage.** Dropping entries
/// here stops replay work; it does not reclaim raw Loro oplog history, which
/// still holds every event ever synced. Actual reclamation needs a separately
/// designed mechanism — ceremony-document rotation, an authenticated checkpoint,
/// or snapshot compaction with retained terminal proofs — and none of that is
/// what this function does. Do not describe it as garbage collection.
fn retain(board: &mut CeremonyBoard) {
    board.dkg.retain(|_, t| t.proposal.is_some());
    board.signing.retain(|_, t| t.request.is_some());
    for t in board.dkg.values_mut() {
        let participants: Vec<UserId> = match t.proposal.as_ref().map(|p| &p.op) {
            Some(CeremonyOp::DkgPropose(p)) => p.frost_devices().unwrap_or_default(),
            _ => Vec::new(),
        };
        let mut seen: BTreeMap<(UserId, u8, String), ()> = BTreeMap::new();
        t.rounds.retain(|v| {
            let Some((kind, extra)) = round_key(&v.op) else {
                return false;
            };
            participants.contains(&v.author)
                && seen
                    .insert((v.author.clone(), kind, extra.to_string()), ())
                    .is_none()
        });
    }
}

impl CeremonyBoard {
    /// The participant set of a DKG transcript's proposal, if the board holds it.
    fn dkg_participants(&self, id: &TranscriptId) -> Option<Vec<UserId>> {
        match self.dkg.get(id)?.proposal.as_ref().map(|p| &p.op) {
            Some(CeremonyOp::DkgPropose(p)) => p.frost_devices(),
            _ => None,
        }
    }

    /// Restrict signing rounds to the participants of the DKG authority each
    /// request names, dropping everything else.
    ///
    /// **Required for retention to bound anything on the signing side.** DKG
    /// rounds are filtered against their proposal's participants, but a
    /// `SignRequest` names no participants of its own, so one-contribution-
    /// per-author is not a bound: an attacker mints as many keys as they like
    /// and stays under any per-author limit forever.
    ///
    /// Participants are resolved through the request's `authority` — the DKG
    /// that produced the group — and **never** from the request itself, which is
    /// attacker-supplied. `fallback` covers an authority whose proposal is not in
    /// this projection (pruned or not yet synced); callers should back it with an
    /// authenticated local record. An authority resolvable by neither retains no
    /// rounds, since nothing can establish who may contribute.
    pub fn restrict_signing_rounds(
        &mut self,
        fallback: impl Fn(&TranscriptId) -> Option<Vec<UserId>>,
    ) {
        let resolved: BTreeMap<TranscriptId, Option<Vec<UserId>>> = self
            .signing
            .iter()
            .map(|(id, t)| {
                let authority = match t.request.as_ref().map(|r| &r.op) {
                    Some(CeremonyOp::SignRequest { authority, .. }) => *authority,
                    // No resolvable authority ⇒ no permitted authors.
                    _ => return (*id, None),
                };
                (
                    *id,
                    self.dkg_participants(&authority)
                        .or_else(|| fallback(&authority)),
                )
            })
            .collect();
        for (id, t) in self.signing.iter_mut() {
            let participants = resolved.get(id).and_then(|p| p.clone());
            let mut seen: BTreeMap<(UserId, u8, String), ()> = BTreeMap::new();
            t.rounds.retain(|v| {
                let Some((kind, extra)) = round_key(&v.op) else {
                    return false;
                };
                participants.as_ref().is_some_and(|p| p.contains(&v.author))
                    && seen
                        .insert((v.author.clone(), kind, extra.to_string()), ())
                        .is_none()
            });
        }
    }
}

/// Serialized packages keyed by 1-based participant index — how a round's
/// contributions travel on the transport.
pub type Packages = BTreeMap<u16, Vec<u8>>;

/// A local record that this device accepted a specific proposal, written the
/// first time it acts on one.
///
/// Acceptance is checked against the recovery authority **current at proposal
/// time**, and "proposal time" cannot be re-derived later: the elevation this
/// authorizes ends by rotating the authority, so re-checking against the
/// standing key would un-accept every transcript the moment it succeeds —
/// orphaning holders who had not finished their rounds.
///
/// It is not a second authorization path. It is only consulted for a proposal
/// whose configuration still matches the board byte-for-byte, and it is written
/// only after a genuine acceptance. Comparing local files against the board's
/// signed proposal is a real check; checking that a local file agrees with
/// itself would be circular.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkgManifest {
    pub proposal: TranscriptId,
    pub proposal_author: UserId,
    /// The recovery authority whose authorization we accepted. Recorded so a
    /// later rotation does not un-accept the transcript, while still requiring
    /// that *that* authorization is still on the board — the record pins which
    /// decision was accepted, it does not stand in for one.
    pub authorized_by: UserId,
    /// The arrangement this ceremony creates.
    ///
    /// Stored whole rather than as decoded threshold fields, so the record works
    /// for any scheme, and so resolving "what governs the standing key" does not
    /// have to re-derive acceptance — which is what made that resolution
    /// mutually recursive with acceptance itself.
    pub configuration: AuthorityConfiguration,
}

/// The canonical description of one signing attempt: who signs, over what, with
/// which commitments, and by what right.
///
/// This is the object every signature share is bound to. It exists as one
/// structure rather than as loose parameters because the nonce binding must
/// cover *everything* that affects a share's meaning — change any field and a
/// nonce bound to the old plan must refuse the new one. Splitting it into
/// separate comparisons is how one of them eventually gets dropped in a
/// refactor, and the field most likely to go is the signer set: exactly what
/// any-K selection mutates.
///
/// Scheme-neutral by construction. Flat FROST and, later, general-access
/// signing differ only in [`AccessWitness`]; the nonce lifecycle above and the
/// aggregation below are shared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningPlan {
    pub signing: TranscriptId,
    pub authority: crate::authority::AuthorityId,
    /// `blake3` of the exact message. The message itself is re-derived locally
    /// by every signer, so the plan commits to it without being trusted for it.
    pub message_commitment: [u8; 32],
    pub signers: Vec<crate::authority::LeafId>,
    /// The frozen commitment map, keyed by participant index.
    pub commitments: Packages,
    pub witness: AccessWitness,
}

/// Why the chosen signer set is entitled to operate the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessWitness {
    /// Flat threshold: any `k` of the participants qualify, so the witness is
    /// just which indices were chosen.
    FrostThreshold {
        k: u16,
        participant_indices: Vec<u16>,
    },
    /// A qualified set under a compiled access structure, with the
    /// reconstruction coefficients it implies. Reserved for general-access signing.
    LinearReconstruction {
        policy: [u8; 32],
        leaves: Vec<crate::authority::LeafId>,
        coefficient_commitment: [u8; 32],
    },
}

impl SigningPlan {
    /// The canonical bytes this plan hashes to.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode signing plan")
    }
}

/// One signing transcript's single-use nonce state.
///
/// FROST nonces are one-use cryptographic material. Producing shares for two
/// different signing packages under one nonce is textbook reuse — two equations,
/// one unknown — and yields the holder's signing share. The record therefore
/// carries the [`nonce_binding`] of the package it was committed for, and the
/// signer refuses if the package it is about to sign does not match.
///
/// The **comparison** is what enforces the invariant, not deletion: a crash
/// between publishing a share and deleting the record always leaves the record
/// behind, so the check has to stand alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingNonce {
    pub signing: TranscriptId,
    /// [`nonce_binding`] of the package these nonces may sign. All-zero until
    /// the full commitment set is known, then fixed for the record's life.
    pub binding: [u8; 32],
    pub nonces: Vec<u8>,
}

/// The binding a [`PendingNonce`] is pinned to: a domain-separated hash over the
/// signing transcript, the exact message, and the canonical [`SigningPlan`] —
/// which carries the signer set, the frozen commitments, the authority and the
/// access witness.
///
/// One composite hash rather than several separate comparisons: a single value
/// cannot be partially checked. Now that any-K selection genuinely varies the
/// signer set, this is the difference between "the plan changed under me" being
/// detected and a share being produced for a package the holder never agreed
/// to — which, with a reused nonce, leaks the share.
pub fn nonce_binding(signing: &TranscriptId, message: &[u8], plan: &SigningPlan) -> [u8; 32] {
    let encoded = plan.encode();
    let mut h = blake3::Hasher::new();
    h.update(b"lait/space/1/ceremony/2/nonce-binding");
    h.update(&signing.0);
    h.update(&(message.len() as u64).to_le_bytes());
    h.update(message);
    h.update(&(encoded.len() as u64).to_le_bytes());
    h.update(&encoded);
    *h.finalize().as_bytes()
}

fn ident(index: u16) -> Result<frost::Identifier> {
    frost::Identifier::try_from(index).map_err(|e| anyhow!("dkg identifier {index}: {e}"))
}

fn ser<T, E: std::fmt::Display>(r: std::result::Result<T, E>, what: &str) -> Result<T> {
    r.map_err(|e| anyhow!("{what}: {e}"))
}

/// The group public key as a lait `UserId` (a plain Ed25519 key), from a DKG
/// public-key package. This is the recovery authority the plane commits to.
/// Check that a private key share is genuinely usable for `index` in the group
/// described by `public_package`.
///
/// Deriving the group key from the public package proves the *public* half is
/// intact and says nothing about the private half — a corrupted or substituted
/// `key_share` paired with the correct package would sail through. For an
/// indispensable arrangement that is the whole ballgame: the backup looks fine,
/// the attestation is honest, and the share turns out unusable on the one day it
/// is needed.
///
/// Four checks, of which the last is the one that matters:
///
/// 1. the share's identifier is the expected participant index;
/// 2. it names the same group verifying key as the package;
/// 3. its verifying share matches the one the package publishes for it;
/// 4. **the verifying share re-derives from the private signing scalar.**
///
/// A `KeyPackage` stores the signing share and the verifying share side by side,
/// so (3) alone would accept a package whose public half is pristine and whose
/// secret has been swapped. (4) recomputes `s·G` and is what actually binds the
/// secret to the group.
pub fn validate_share(key_share: &[u8], public_package: &[u8], index: u16) -> Result<()> {
    let kp = ser(
        frost::keys::KeyPackage::deserialize(key_share),
        "deserialize key package",
    )?;
    let pkp = ser(
        frost::keys::PublicKeyPackage::deserialize(public_package),
        "deserialize public key package",
    )?;
    let expected = ident(index)?;
    if *kp.identifier() != expected {
        return Err(anyhow!(
            "this share is for participant {:?}, not index {index}",
            kp.identifier()
        ));
    }
    if kp.verifying_key() != pkp.verifying_key() {
        return Err(anyhow!("this share belongs to a different group"));
    }
    let published = pkp
        .verifying_shares()
        .get(kp.identifier())
        .ok_or_else(|| anyhow!("the group does not publish a share for this participant"))?;
    if published != kp.verifying_share() {
        return Err(anyhow!(
            "this share's public half does not match what the group publishes for it"
        ));
    }
    if frost::keys::VerifyingShare::from(*kp.signing_share()) != *kp.verifying_share() {
        return Err(anyhow!(
            "this share's secret does not correspond to its public half — the private material is corrupt or substituted"
        ));
    }
    Ok(())
}

/// The group key **derived** from a serialized public-key package.
///
/// The authority a `Rotate` installs must come from here, never from a stored
/// plaintext `-group` artifact: the derivation is cheap and the file is a swap
/// target that would let a local attacker redirect the rotation.
pub fn group_key_of_package(pkp: &[u8]) -> Result<UserId> {
    let pkp = ser(
        frost::keys::PublicKeyPackage::deserialize(pkp),
        "deserialize public key package",
    )?;
    group_key_of(&pkp)
}

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

/// DKG fixtures shared by other modules' tests.
///
/// Exposed so custody tests can seal a REAL share rather than random bytes: a
/// package that round-trips arbitrary bytes proves nothing about whether the
/// group key derives from what it carries.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// Per-participant `(key_share, public_key_package)`, keyed by index.
    pub type Holders = BTreeMap<u16, (Vec<u8>, Vec<u8>)>;

    /// A key package for participant 1 whose identifier, verifying share and
    /// group key are all correct, but whose **secret** belongs to participant 2.
    ///
    /// This is the adversarial shape that every public-half check passes: the
    /// only thing distinguishing it from a good share is that `s·G` no longer
    /// equals the published verifying share. Returns the forged share, the
    /// matching public package, and the group key.
    pub fn share_with_foreign_secret() -> (Vec<u8>, Vec<u8>, UserId) {
        let (holders, group) = run_dkg(3, 2);
        let mine = frost::keys::KeyPackage::deserialize(&holders[&1].0).unwrap();
        let theirs = frost::keys::KeyPackage::deserialize(&holders[&2].0).unwrap();
        let forged = frost::keys::KeyPackage::new(
            *mine.identifier(),
            *theirs.signing_share(),
            *mine.verifying_share(),
            *mine.verifying_key(),
            *mine.min_signers(),
        );
        (forged.serialize().unwrap(), holders[&1].1.clone(), group)
    }

    /// Run a full dealer-free `k`-of-`n` DKG through the byte API.
    pub fn run_dkg(n: u16, k: u16) -> (Holders, UserId) {
        let ids: Vec<u16> = (1..=n).collect();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::tests_support::run_dkg;

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

    /// A flat-FROST rotation proposal for tests. `n` is now derived from the
    /// participant list rather than stated separately, so it cannot disagree
    /// with it.
    fn test_proposal(nonce: [u8; 16], k: u16, participants: Vec<UserId>) -> KeyCeremonyProposal {
        let mut principals: Vec<PrincipalId> =
            participants.iter().map(PrincipalId::of_device).collect();
        principals.sort();
        principals.dedup();
        frost_rotation_proposal(
            nonce,
            k,
            principals,
            crate::authority::AuthorityId::single(crate::crypto::user_from_seed(&[200u8; 32])),
        )
    }

    fn hex32(s: &str) -> Option<[u8; 32]> {
        data_encoding::HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .ok()?
            .as_slice()
            .try_into()
            .ok()
    }

    /// The check that actually binds a secret to its group. A `KeyPackage`
    /// stores the signing share and verifying share side by side, so comparing
    /// the verifying share against the published one accepts a package whose
    /// public half is pristine and whose secret has been swapped. Only
    /// re-deriving `s·G` catches that.
    #[test]
    fn a_share_whose_secret_does_not_match_its_public_half_is_rejected() {
        let (holders, _) = tests_support::run_dkg(3, 2);
        assert!(validate_share(&holders[&1].0, &holders[&1].1, 1).is_ok());

        let (forged, pkp, _) = tests_support::share_with_foreign_secret();
        let err = validate_share(&forged, &pkp, 1).unwrap_err().to_string();
        assert!(
            err.contains("does not correspond to its public half"),
            "must catch the swapped secret specifically: {err}"
        );
    }

    /// A genuine share presented under the wrong index is refused.
    #[test]
    fn a_share_validated_against_the_wrong_index_is_rejected() {
        let (holders, _) = tests_support::run_dkg(3, 2);
        assert!(validate_share(&holders[&2].0, &holders[&2].1, 2).is_ok());
        assert!(validate_share(&holders[&2].0, &holders[&2].1, 1).is_err());
    }

    // ---- transcript identity ----

    fn ws() -> WorkspaceId {
        WorkspaceId::mint(&crate::ids::SystemUlidSource)
    }

    /// A transcript id only ever reaches the filesystem as `to_hex`, so the
    /// parser must reject anything that is not canonical — a permissive decode
    /// would let two spellings name one artifact, and a remote-supplied string
    /// could carry path components.
    #[test]
    fn transcript_ids_parse_only_canonical_hex() {
        let good = "a".repeat(64);
        assert!(TranscriptId::parse_hex(&good).is_some());
        for bad in [
            "",
            "a",
            &"a".repeat(63),
            &"a".repeat(65),
            &"A".repeat(64),                  // uppercase
            &format!("{}/", "a".repeat(63)),  // path separator
            &format!("{}\\", "a".repeat(63)), // windows separator
            &format!("..{}", "a".repeat(62)), // traversal
            &format!("{}\0", "a".repeat(63)), // NUL
            &format!("{} ", "a".repeat(63)),  // trailing space
            &"g".repeat(64),                  // non-hex
        ] {
            assert!(
                TranscriptId::parse_hex(bad).is_none(),
                "must reject {bad:?}"
            );
        }
        // Round-trip is canonical and stable.
        let id = TranscriptId::parse_hex(&good).unwrap();
        assert_eq!(id.to_hex(), good);
    }

    /// A transcript's id is the hash of the node that opened it.
    #[test]
    fn a_transcript_id_is_the_opening_nodes_hash() {
        let w = ws();
        let op = CeremonyOp::DkgPropose(test_proposal([1u8; 16], 2, vec![]));
        let ev = sign_ceremony(&[7u8; 32], &op, &w);
        assert_eq!(TranscriptId::of(&ev).unwrap().to_hex(), ev.hash());
    }

    /// Openers cannot report their own transcript — the id is the hash of the
    /// enclosing node, which the op alone cannot know. Callers must take it from
    /// the `SignedNode`, and this pins that asymmetry.
    #[test]
    fn openers_report_no_transcript_of_their_own() {
        let opener = CeremonyOp::DkgPropose(test_proposal([1u8; 16], 2, vec![]));
        assert!(opener.dkg().is_none() && opener.signing().is_none());
        let id = TranscriptId::parse_hex(&"b".repeat(64)).unwrap();
        let round = CeremonyOp::DkgRound1 {
            dkg: id,
            package: vec![],
        };
        assert_eq!(round.dkg(), Some(id));
        assert!(round.signing().is_none());
    }

    // ---- board scan ----

    /// A forged event cannot name anything: `parse_board` drops it before it
    /// reaches an index, so it can neither supply configuration nor manufacture
    /// a transcript for the caller to spend work on.
    #[test]
    fn the_board_drops_events_whose_signature_does_not_verify() {
        let w = ws();
        let op = CeremonyOp::DkgPropose(test_proposal([1u8; 16], 2, vec![]));
        let mut ev = sign_ceremony(&[7u8; 32], &op, &w);
        assert_eq!(parse_board(std::slice::from_ref(&ev), &w).dkg.len(), 1);
        ev.sig = vec![0u8; 64];
        assert!(parse_board(&[ev.clone()], &w).dkg.is_empty());
        // Nor can it be lifted into a different workspace.
        assert!(parse_board(std::slice::from_ref(&ev), &ws()).dkg.is_empty());
    }

    /// The scan verifies each event exactly once, however many transcripts the
    /// board holds. The old per-session parse re-verified the whole board once
    /// per discovered session — `transcripts × board`, both attacker-controlled.
    #[test]
    fn board_scan_cost_is_linear_in_events_not_transcripts() {
        let w = ws();
        let events: Vec<SignedNode> = (0..24u8)
            .map(|i| {
                sign_ceremony(
                    &[9u8; 32],
                    &CeremonyOp::DkgPropose(test_proposal([i; 16], 2, vec![])),
                    &w,
                )
            })
            .collect();
        VERIFY_COUNT.with(|c| c.set(0));
        let board = parse_board(&events, &w);
        let verifies = VERIFY_COUNT.with(|c| c.get());
        assert_eq!(board.dkg.len(), 24, "24 distinct transcripts");
        assert_eq!(
            verifies,
            events.len(),
            "one verification per event, not per (transcript, event) pair"
        );
    }

    // ---- proposal authorization ----

    /// A grant is bound to one proposal in one workspace: it cannot be replayed
    /// against a different proposal, nor lifted to another workspace.
    #[test]
    fn a_grant_binds_to_its_proposal_and_workspace() {
        let w = ws();
        let seed = [3u8; 32];
        let a = TranscriptId::parse_hex(&"a".repeat(64)).unwrap();

        let grant = sign_authority_grant(&seed, &w, &a);
        assert_eq!(authority_grant_of(&grant, &w).unwrap().proposal, a);
        // Same signature, different workspace.
        assert!(authority_grant_of(&grant, &ws()).is_none());
        // Tampered payload: the signature no longer covers it.
        let mut swapped = grant.clone();
        swapped.op = postcard::to_stdvec(&AuthorityGrant {
            proposal: TranscriptId::parse_hex(&"b".repeat(64)).unwrap(),
        })
        .unwrap();
        assert!(authority_grant_of(&swapped, &w).is_none());
        // Tampered signature.
        let mut bad = grant.clone();
        bad.sig[0] ^= 0xff;
        assert!(authority_grant_of(&bad, &w).is_none());
    }

    /// Solo and group producers must yield the SAME object, verified by the same
    /// rule — that is the entire point of the signed-node shape. Here the group
    /// signature is stood in for by a plain key signing the group payload; what
    /// matters is that the assembled node is byte-identical to the solo one and
    /// passes one verifier.
    #[test]
    fn solo_and_assembled_grants_satisfy_one_verifier() {
        let w = ws();
        let seed = [3u8; 32];
        let author = crate::crypto::user_from_seed(&seed);
        let a = TranscriptId::parse_hex(&"a".repeat(64)).unwrap();

        let solo = sign_authority_grant(&seed, &w, &a);
        // The group path: derive the payload, sign it, assemble.
        let (op, payload) = authority_grant_payload(&w, &author, &a);
        let sig = {
            use ed25519_dalek::Signer;
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .sign(&payload)
                .to_bytes()
        };
        let assembled = sigdag::assemble_signed(op, author, sig.to_vec(), vec![]);

        assert_eq!(solo, assembled, "one object, however it was produced");
        assert!(authority_grant_of(&assembled, &w).is_some());
        assert_eq!(
            solo.hash(),
            assembled.hash(),
            "identical decisions converge to one board entry"
        );
    }

    /// A grant must not be a ceremony contribution or a space operation, and
    /// neither may masquerade as a grant. Domains are the only thing separating
    /// them, since postcard carries no type information.
    #[test]
    fn grants_do_not_cross_domains() {
        let w = ws();
        let seed = [3u8; 32];
        let a = TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
        let grant = sign_authority_grant(&seed, &w, &a);

        assert!(
            !grant.verify_sig(CEREMONY_DOMAIN, w.as_str()),
            "a grant is not a ceremony contribution"
        );
        assert!(
            !grant.verify_sig(crate::space::SPACE_EVENT_DOMAIN, w.as_str()),
            "a grant is not a space operation"
        );

        // And the reverse: a ceremony node over the same bytes is not a grant.
        let ceremony =
            sigdag::sign_node(CEREMONY_DOMAIN, &seed, grant.op.clone(), vec![], w.as_str());
        assert!(authority_grant_of(&ceremony, &w).is_none());
        let space = sigdag::sign_node(
            crate::space::SPACE_EVENT_DOMAIN,
            &seed,
            grant.op.clone(),
            vec![],
            w.as_str(),
        );
        assert!(authority_grant_of(&space, &w).is_none());
    }

    /// A grant is a standalone statement. Parents are signed-over data with no
    /// defined meaning here, and leaving them free would let two grants for one
    /// decision differ in hash and stop converging.
    #[test]
    fn a_grant_with_parents_is_rejected() {
        let w = ws();
        let a = TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
        let op = postcard::to_stdvec(&AuthorityGrant { proposal: a }).unwrap();
        let parented = sigdag::sign_node(
            AUTHORITY_GRANT_DOMAIN,
            &[3u8; 32],
            op,
            vec!["f".repeat(64)],
            w.as_str(),
        );
        assert!(
            parented.verify_sig(AUTHORITY_GRANT_DOMAIN, w.as_str()),
            "the signature itself is valid — only the shape is wrong"
        );
        assert!(authority_grant_of(&parented, &w).is_none());
    }

    /// An unverifiable authorization must not occupy the slot a real one would
    /// fill — otherwise it could mask a genuine authorization arriving later.
    #[test]
    fn the_board_files_only_verifiable_authorizations() {
        let w = ws();
        let propose = CeremonyOp::DkgPropose(test_proposal([1u8; 16], 2, vec![]));
        let pev = sign_ceremony(&[7u8; 32], &propose, &w);
        let id = TranscriptId::of(&pev).unwrap();

        let mut grant = sign_authority_grant(&[3u8; 32], &w, &id);
        grant.sig[0] ^= 0xff;
        let aev = sign_ceremony(&[7u8; 32], &CeremonyOp::DkgAuthorize(grant), &w);
        let board = parse_board(&[pev.clone(), aev], &w);
        assert!(
            board.dkg[&id].auths.is_empty(),
            "a broken grant is not filed"
        );

        let good = sign_authority_grant(&[3u8; 32], &w, &id);
        let aev = sign_ceremony(&[7u8; 32], &CeremonyOp::DkgAuthorize(good), &w);
        let board = parse_board(&[pev, aev], &w);
        assert!(board.dkg[&id].auths.len() == 1);
    }

    // ---- signing plans and retention ----
    fn request_with_coordinator(
        w: &WorkspaceId,
        coordinator: UserId,
    ) -> (TranscriptId, SignedNode) {
        let authority = TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
        let req = CeremonyOp::SignRequest {
            nonce: [3u8; 16],
            authority,
            target: SignTarget::SpaceOp,
            coordinator,
            op: vec![1, 2, 3],
        };
        let ev = sign_ceremony(&[7u8; 32], &req, w);
        (TranscriptId::of(&ev).unwrap(), ev)
    }

    /// The coordinator role is fixed by the request. A plan from anyone else is
    /// not a plan — otherwise any holder could seize the choice of who signs
    /// simply by publishing first.
    #[test]
    fn a_plan_from_a_non_coordinator_is_ignored() {
        let w = ws();
        let coordinator = crate::crypto::user_from_seed(&[50u8; 32]);
        let (signing, rev) = request_with_coordinator(&w, coordinator.clone());
        let plan = test_plan(signing, [(1u16, vec![1])].into_iter().collect());

        let impostor = sign_ceremony(
            &[51u8; 32],
            &CeremonyOp::SignPlan {
                signing,
                plan: plan.encode(),
            },
            &w,
        );
        let mut board = parse_board(&[rev.clone(), impostor], &w);
        board.restrict_signing_rounds(|_| Some(vec![coordinator.clone()]));
        assert!(
            board.signing[&signing].plan().is_none(),
            "only the named coordinator publishes a plan"
        );

        let good = sign_ceremony(
            &[50u8; 32],
            &CeremonyOp::SignPlan {
                signing,
                plan: plan.encode(),
            },
            &w,
        );
        let mut board = parse_board(&[rev, good], &w);
        board.restrict_signing_rounds(|_| Some(vec![coordinator.clone()]));
        assert_eq!(board.signing[&signing].plan(), Some(plan));
    }

    /// A coordinator publishing two plans is equivocating. Every replica honours
    /// the same one (board order converges) and a holder already bound to it
    /// refuses the other, so the second is inert rather than ambiguous.
    #[test]
    fn only_one_plan_per_coordinator_is_honoured() {
        let w = ws();
        let coordinator = crate::crypto::user_from_seed(&[50u8; 32]);
        let (signing, rev) = request_with_coordinator(&w, coordinator.clone());
        let first = test_plan(signing, [(1u16, vec![1])].into_iter().collect());
        let second = test_plan(signing, [(2u16, vec![2])].into_iter().collect());
        let evs = vec![
            rev,
            sign_ceremony(
                &[50u8; 32],
                &CeremonyOp::SignPlan {
                    signing,
                    plan: first.encode(),
                },
                &w,
            ),
            sign_ceremony(
                &[50u8; 32],
                &CeremonyOp::SignPlan {
                    signing,
                    plan: second.encode(),
                },
                &w,
            ),
        ];
        let mut board = parse_board(&evs, &w);
        board.restrict_signing_rounds(|_| Some(vec![coordinator.clone()]));
        assert_eq!(board.signing[&signing].rounds.len(), 1, "one plan retained");
        assert_eq!(board.signing[&signing].plan(), Some(first));
    }

    // ---- nonce binding ----

    fn test_plan(signing: TranscriptId, commitments: Packages) -> SigningPlan {
        let indices: Vec<u16> = commitments.keys().copied().collect();
        SigningPlan {
            signing,
            authority: crate::authority::AuthorityId::single(crate::crypto::user_from_seed(
                &[201u8; 32],
            )),
            message_commitment: [0u8; 32],
            signers: indices
                .iter()
                .map(|i| {
                    crate::authority::LeafId::of_principal(
                        &crate::authority::PrincipalId::of_device(&crate::crypto::user_from_seed(
                            &[*i as u8; 32],
                        )),
                    )
                })
                .collect(),
            commitments,
            witness: AccessWitness::FrostThreshold {
                k: indices.len() as u16,
                participant_indices: indices,
            },
        }
    }

    /// The binding covers the transcript, the message AND the whole plan — which
    /// carries the signer set, the frozen commitments, the authority and the
    /// access witness. Any of them moving is a different binding, so a stored
    /// nonce cannot sign two distinct plans.
    #[test]
    fn the_nonce_binding_covers_transcript_message_and_plan() {
        let a = TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
        let b = TranscriptId::parse_hex(&"b".repeat(64)).unwrap();
        let commitments: Packages = [(1u16, vec![1, 2, 3]), (2u16, vec![4, 5, 6])]
            .into_iter()
            .collect();
        let plan = test_plan(a, commitments.clone());
        let base = nonce_binding(&a, b"msg", &plan);

        assert_ne!(base, nonce_binding(&b, b"msg", &plan), "transcript");
        assert_ne!(base, nonce_binding(&a, b"other", &plan), "message");

        // A different signer set at the same size — what any-K selection varies.
        let moved: Packages = [(1u16, vec![1, 2, 3]), (3u16, vec![4, 5, 6])]
            .into_iter()
            .collect();
        assert_ne!(
            base,
            nonce_binding(&a, b"msg", &test_plan(a, moved)),
            "signer set"
        );

        // A changed commitment for the same signer.
        let tweaked: Packages = [(1u16, vec![1, 2, 3]), (2u16, vec![4, 5, 7])]
            .into_iter()
            .collect();
        assert_ne!(
            base,
            nonce_binding(&a, b"msg", &test_plan(a, tweaked)),
            "commitment bytes"
        );

        // A different authority over the same commitments.
        let mut other_authority = test_plan(a, commitments.clone());
        other_authority.authority =
            crate::authority::AuthorityId::single(crate::crypto::user_from_seed(&[202u8; 32]));
        assert_ne!(
            base,
            nonce_binding(&a, b"msg", &other_authority),
            "authority"
        );

        // Stable for identical input.
        assert_eq!(base, nonce_binding(&a, b"msg", &plan));
    }

    /// The group key must be derivable from the public-key package, since that
    /// derivation is what replaces trusting a stored plaintext `-group` file.
    #[test]
    fn the_group_key_derives_from_the_public_key_package() {
        let (holders, group_key) = run_dkg(3, 2);
        for (_, pkp) in holders.values() {
            assert_eq!(group_key_of_package(pkp).unwrap(), group_key);
        }
        assert!(group_key_of_package(b"not a package").is_err());
    }
}
