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
    /// A `DkgPropose` authorizing a new DKG (group→group reconfiguration).
    CeremonyProposal,
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
    /// Open a DKG transcript: the ordered participant devices + threshold.
    /// Authorization is *not* the device signature on this node — see
    /// [`ProposalAuth`].
    DkgPropose {
        nonce: [u8; 16],
        n: u16,
        k: u16,
        /// Participant devices, sorted + deduped (index = position + 1).
        participants: Vec<UserId>,
    },
    /// The recovery authority's authorization for a `DkgPropose`. Carried as its
    /// own board entry because what it signs is the proposal's *hash*, which
    /// cannot be a field of the proposal.
    DkgAuthorize(ProposalAuth),
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
        op: Vec<u8>,
    },
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

/// Authorization for a `DkgPropose`, detached from the proposal node.
///
/// A ceremony signature proves only control of the declared **device** key. It
/// says nothing about authority to configure an elevation, so acceptance rests
/// on this instead: a signature by the recovery authority current at proposal
/// time, over the proposal's own id.
///
/// Detached rather than a field on `DkgPropose`, because the thing being
/// authorized is the proposal's *hash*, which cannot be a field of the proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalAuth {
    /// The proposal being authorized.
    pub proposal: TranscriptId,
    /// The key that authorized it — checked against the standing recovery
    /// commitment by the acceptance rule, not trusted from here.
    pub by: UserId,
    /// Detached signature over the proposal id (see [`sign_proposal_auth`]).
    pub sig: Vec<u8>,
}

/// Domain for the detached proposal authorization. Distinct from
/// [`CEREMONY_DOMAIN`] so an authorization can never verify as a ceremony
/// contribution, or vice versa.
pub const PROPOSAL_AUTH_DOMAIN: &[u8] = b"lait/space/1/ceremony/2/proposal-auth";

/// Authorize `proposal` with the current recovery secret. Rides
/// [`sigdag::sign_message`], so it is domain-separated and workspace-bound: an
/// authorization cannot be lifted to another workspace, replayed against a
/// different proposal, or reused as any other kind of signature.
pub fn sign_proposal_auth(
    recovery_seed: &[u8; 32],
    ws: &WorkspaceId,
    proposal: &TranscriptId,
) -> ProposalAuth {
    let (by, sig) = sigdag::sign_message(
        PROPOSAL_AUTH_DOMAIN,
        ws.as_str(),
        recovery_seed,
        &proposal.0,
    );
    ProposalAuth {
        proposal: *proposal,
        by,
        sig: sig.to_vec(),
    }
}

/// Whether `auth` is a well-formed authorization for its named proposal. Says
/// nothing about *whose* key signed it — the caller must still check
/// `auth.by` against the standing recovery commitment.
pub fn verify_proposal_auth(auth: &ProposalAuth, ws: &WorkspaceId) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(auth.sig.as_slice()) else {
        return false;
    };
    sigdag::verify_message(
        PROPOSAL_AUTH_DOMAIN,
        ws.as_str(),
        &auth.by,
        &auth.proposal.0,
        &sig,
    )
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
    pub auths: BTreeMap<UserId, ProposalAuth>,
    /// Round packages referencing this transcript (openers excluded).
    pub rounds: Vec<Verified>,
}

/// One signing transcript's verified contributions.
#[derive(Debug, Clone, Default)]
pub struct SignTranscript {
    pub request: Option<Verified>,
    pub rounds: Vec<Verified>,
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
/// Replaces the per-session parse this used to do: callers previously decoded
/// events *unverified* to discover sessions, then re-verified the entire board
/// once per discovered session. That let unsigned events manufacture transcripts
/// and made the work `transcripts × board` — both attacker-controlled. Here every
/// event is verified exactly once and an event that fails is dropped before it
/// can name anything.
///
/// Note this establishes *authenticity*, not *authorization*: a validly signed
/// proposal from any device still lands here. Accepting it is
/// [`ProposalAuth`]'s job, applied by the caller.
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
            CeremonyOp::DkgAuthorize(auth) => {
                if verify_proposal_auth(auth, ws) {
                    let (proposal, auth) = (auth.proposal, auth.clone());
                    board
                        .dkg
                        .entry(proposal)
                        .or_default()
                        .auths
                        .insert(auth.by.clone(), auth);
                }
            }
            // Rounds are keyed by the transcript they name.
            CeremonyOp::DkgRound1 { dkg, .. } | CeremonyOp::DkgRound2 { dkg, .. } => {
                let dkg = *dkg;
                board.dkg.entry(dkg).or_default().rounds.push(entry);
            }
            CeremonyOp::SignRound1 { signing, .. } | CeremonyOp::SignRound2 { signing, .. } => {
                let signing = *signing;
                board.signing.entry(signing).or_default().rounds.push(entry);
            }
        }
    }
    retain(&mut board);
    board
}

/// Which round an entry is, for the one-per-author-per-round cap.
fn round_kind(op: &CeremonyOp) -> Option<u8> {
    match op {
        CeremonyOp::DkgRound1 { .. } => Some(1),
        CeremonyOp::DkgRound2 { .. } => Some(2),
        CeremonyOp::SignRound1 { .. } => Some(3),
        CeremonyOp::SignRound2 { .. } => Some(4),
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
            Some(CeremonyOp::DkgPropose { participants, .. }) => participants.clone(),
            _ => Vec::new(),
        };
        let mut seen: BTreeMap<(UserId, u8), ()> = BTreeMap::new();
        t.rounds.retain(|v| {
            let Some(kind) = round_kind(&v.op) else {
                return false;
            };
            participants.contains(&v.author) && seen.insert((v.author.clone(), kind), ()).is_none()
        });
    }
}

impl CeremonyBoard {
    /// The participant set of a DKG transcript's proposal, if the board holds it.
    fn dkg_participants(&self, id: &TranscriptId) -> Option<Vec<UserId>> {
        match self.dkg.get(id)?.proposal.as_ref().map(|p| &p.op) {
            Some(CeremonyOp::DkgPropose { participants, .. }) => Some(participants.clone()),
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
            let mut seen: BTreeMap<(UserId, u8), ()> = BTreeMap::new();
            t.rounds.retain(|v| {
                let Some(kind) = round_kind(&v.op) else {
                    return false;
                };
                participants.as_ref().is_some_and(|p| p.contains(&v.author))
                    && seen.insert((v.author.clone(), kind), ()).is_none()
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
    pub n: u16,
    pub k: u16,
    pub participants: Vec<UserId>,
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
/// signing transcript, the exact message, and the complete frozen commitment map
/// (which encodes the signer set — the indices are its keys).
///
/// One composite hash rather than several separate comparisons: a single value
/// cannot be partially checked, and the field most likely to be dropped in a
/// later refactor is the signer set — exactly what any-K selection would start
/// mutating.
pub fn nonce_binding(signing: &TranscriptId, message: &[u8], commitments: &Packages) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"lait/space/1/ceremony/2/nonce-binding");
    h.update(&signing.0);
    h.update(&(message.len() as u64).to_le_bytes());
    h.update(message);
    h.update(&(commitments.len() as u64).to_le_bytes());
    for (i, c) in commitments {
        h.update(&i.to_le_bytes());
        h.update(&(c.len() as u64).to_le_bytes());
        h.update(c);
    }
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
        let op = CeremonyOp::DkgPropose {
            nonce: [1u8; 16],
            n: 2,
            k: 2,
            participants: vec![],
        };
        let ev = sign_ceremony(&[7u8; 32], &op, &w);
        assert_eq!(TranscriptId::of(&ev).unwrap().to_hex(), ev.hash());
    }

    /// Openers cannot report their own transcript — the id is the hash of the
    /// enclosing node, which the op alone cannot know. Callers must take it from
    /// the `SignedNode`, and this pins that asymmetry.
    #[test]
    fn openers_report_no_transcript_of_their_own() {
        let opener = CeremonyOp::DkgPropose {
            nonce: [1u8; 16],
            n: 2,
            k: 2,
            participants: vec![],
        };
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
        let op = CeremonyOp::DkgPropose {
            nonce: [1u8; 16],
            n: 2,
            k: 2,
            participants: vec![],
        };
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
                    &CeremonyOp::DkgPropose {
                        nonce: [i; 16],
                        n: 2,
                        k: 2,
                        participants: vec![],
                    },
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

    /// An authorization is bound to one proposal in one workspace: it cannot be
    /// replayed against a different proposal, nor lifted to another workspace.
    #[test]
    fn a_proposal_authorization_binds_to_its_proposal_and_workspace() {
        let w = ws();
        let seed = [3u8; 32];
        let a = TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
        let b = TranscriptId::parse_hex(&"b".repeat(64)).unwrap();

        let auth = sign_proposal_auth(&seed, &w, &a);
        assert!(verify_proposal_auth(&auth, &w));
        // Same signature, different proposal.
        let swapped = ProposalAuth {
            proposal: b,
            ..auth.clone()
        };
        assert!(!verify_proposal_auth(&swapped, &w));
        // Same signature, different workspace.
        assert!(!verify_proposal_auth(&auth, &ws()));
        // Tampered signature.
        let mut bad = auth.clone();
        bad.sig[0] ^= 0xff;
        assert!(!verify_proposal_auth(&bad, &w));
    }

    /// An unverifiable authorization must not occupy the slot a real one would
    /// fill — otherwise it could mask a genuine authorization arriving later.
    #[test]
    fn the_board_files_only_verifiable_authorizations() {
        let w = ws();
        let propose = CeremonyOp::DkgPropose {
            nonce: [1u8; 16],
            n: 2,
            k: 2,
            participants: vec![],
        };
        let pev = sign_ceremony(&[7u8; 32], &propose, &w);
        let id = TranscriptId::of(&pev).unwrap();

        let mut auth = sign_proposal_auth(&[3u8; 32], &w, &id);
        auth.sig[0] ^= 0xff;
        let aev = sign_ceremony(&[7u8; 32], &CeremonyOp::DkgAuthorize(auth), &w);
        let board = parse_board(&[pev.clone(), aev], &w);
        assert!(
            board.dkg[&id].auths.is_empty(),
            "a broken authorization is not filed"
        );

        let good = sign_proposal_auth(&[3u8; 32], &w, &id);
        let aev = sign_ceremony(&[7u8; 32], &CeremonyOp::DkgAuthorize(good), &w);
        let board = parse_board(&[pev, aev], &w);
        assert!(board.dkg[&id].auths.len() == 1);
    }

    // ---- nonce binding ----

    /// The binding covers the transcript, the message AND the complete
    /// commitment map (whose keys are the signer set). Any of them moving is a
    /// different binding, so a stored nonce cannot sign two distinct packages.
    #[test]
    fn the_nonce_binding_covers_transcript_message_and_signer_set() {
        let a = TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
        let b = TranscriptId::parse_hex(&"b".repeat(64)).unwrap();
        let commitments: Packages = [(1u16, vec![1, 2, 3]), (2u16, vec![4, 5, 6])]
            .into_iter()
            .collect();
        let base = nonce_binding(&a, b"msg", &commitments);

        assert_ne!(base, nonce_binding(&b, b"msg", &commitments), "transcript");
        assert_ne!(base, nonce_binding(&a, b"other", &commitments), "message");

        // A different signer set at the same size.
        let moved: Packages = [(1u16, vec![1, 2, 3]), (3u16, vec![4, 5, 6])]
            .into_iter()
            .collect();
        assert_ne!(base, nonce_binding(&a, b"msg", &moved), "signer set");

        // A changed commitment for the same signer.
        let tweaked: Packages = [(1u16, vec![1, 2, 3]), (2u16, vec![4, 5, 7])]
            .into_iter()
            .collect();
        assert_ne!(
            base,
            nonce_binding(&a, b"msg", &tweaked),
            "commitment bytes"
        );

        // Stable for identical input.
        assert_eq!(base, nonce_binding(&a, b"msg", &commitments));
    }

    // ---- domain separation ----

    /// §2.3 regression. A group must be able to threshold-sign a ceremony
    /// proposal, so the signing path takes the domain from `SignTarget`. If it
    /// did not, a signature over ceremony bytes would be produced under the
    /// space domain and handed to the space plane — and because postcard is not
    /// self-describing and `DkgPropose` shares variant tag 0 with
    /// `SpaceOp::Recover`, that is type confusion, not a filing error.
    #[test]
    fn a_ceremony_signature_cannot_pass_as_a_space_event() {
        let w = ws();
        let seed = [4u8; 32];
        // Bytes that are a structurally valid DkgPropose...
        let op_bytes = postcard::to_stdvec(&CeremonyOp::DkgPropose {
            nonce: [0u8; 16],
            n: 2,
            k: 2,
            participants: vec![],
        })
        .unwrap();
        // ...and which postcard will also happily read as a SpaceOp, since the
        // encoding carries no type information. This is the hazard itself.
        assert!(
            postcard::from_bytes::<crate::space::SpaceOp>(&op_bytes).is_ok(),
            "ceremony bytes decode as a space op — nothing but the domain separates them"
        );

        // The two targets produce different signing messages...
        let author = crate::crypto::user_from_seed(&seed);
        let as_space = sigdag::payload_to_sign(
            crate::space::SPACE_EVENT_DOMAIN,
            &op_bytes,
            &author,
            &[],
            w.as_str(),
        );
        let as_ceremony =
            sigdag::payload_to_sign(CEREMONY_DOMAIN, &op_bytes, &author, &[], w.as_str());
        assert_ne!(as_space, as_ceremony, "the domain must change the message");

        // ...so a node signed for the ceremony plane cannot be installed on the
        // space plane, even though the bytes parse there.
        let node = sigdag::sign_node(CEREMONY_DOMAIN, &seed, op_bytes, vec![], w.as_str());
        assert!(node.verify_sig(CEREMONY_DOMAIN, w.as_str()));
        assert!(
            !node.verify_sig(crate::space::SPACE_EVENT_DOMAIN, w.as_str()),
            "a ceremony-plane signature must never verify as a space event"
        );
    }

    // ---- multi-authorization retention (§3) ----

    /// Build a proposal and `count` authorizations from distinct keys.
    fn proposal_with_auths(w: &WorkspaceId, seeds: &[[u8; 32]]) -> (TranscriptId, Vec<SignedNode>) {
        let propose = CeremonyOp::DkgPropose {
            nonce: [1u8; 16],
            n: 2,
            k: 2,
            participants: vec![],
        };
        let pev = sign_ceremony(&[7u8; 32], &propose, w);
        let id = TranscriptId::of(&pev).unwrap();
        let mut evs = vec![pev];
        for seed in seeds {
            let auth = sign_proposal_auth(seed, w, &id);
            evs.push(sign_ceremony(
                &[7u8; 32],
                &CeremonyOp::DkgAuthorize(auth),
                w,
            ));
        }
        (id, evs)
    }

    /// A signature-valid authorization from the WRONG key must not displace the
    /// right one. With a single slot, whichever landed later won — so anyone able
    /// to post could suppress a proposal, making recovery a denial-of-service
    /// target decided by board order rather than by authority.
    #[test]
    fn a_wrong_key_authorization_cannot_displace_the_right_one() {
        let w = ws();
        let right = [3u8; 32];
        let wrong = [4u8; 32];
        let right_key = crate::crypto::user_from_seed(&right);

        // Both orders must give the same answer.
        for seeds in [[right, wrong], [wrong, right]] {
            let (id, evs) = proposal_with_auths(&w, &seeds);
            let board = parse_board(&evs, &w);
            let auths = &board.dkg[&id].auths;
            assert_eq!(auths.len(), 2, "both are retained");
            assert!(
                auths.contains_key(&right_key),
                "the correct authorization survives regardless of order"
            );
        }
    }

    /// Many wrong-key authorizations cannot crowd out a correct one: they are
    /// keyed by signer, so the correct signer always has its own entry.
    #[test]
    fn many_wrong_authorizations_cannot_suppress_a_correct_one() {
        let w = ws();
        let right = [3u8; 32];
        let right_key = crate::crypto::user_from_seed(&right);
        // Correct authorization FIRST: a last-wins single slot would lose it,
        // so this fails against the behaviour being replaced.
        let mut seeds: Vec<[u8; 32]> = vec![right];
        seeds.extend((10..60u8).map(|i| [i; 32]));
        let (id, evs) = proposal_with_auths(&w, &seeds);
        let board = parse_board(&evs, &w);
        assert!(board.dkg[&id].auths.contains_key(&right_key));
    }

    /// Two postings of the SAME authority decision converge to one entry, so a
    /// participant cannot inflate retained state by re-posting.
    #[test]
    fn repeated_postings_of_one_authority_decision_converge() {
        let w = ws();
        let (id, mut evs) = proposal_with_auths(&w, &[[3u8; 32]]);
        // Post the same decision again, under a different carrier signature.
        let auth = sign_proposal_auth(&[3u8; 32], &w, &id);
        evs.push(sign_ceremony(
            &[8u8; 32],
            &CeremonyOp::DkgAuthorize(auth),
            &w,
        ));
        let board = parse_board(&evs, &w);
        assert_eq!(
            board.dkg[&id].auths.len(),
            1,
            "one authority, one retained decision"
        );
    }

    // ---- signing-round participant filtering (§4) ----

    /// Build a DKG whose proposal names `participants`, plus a signing request
    /// against it.
    fn dkg_and_request(
        w: &WorkspaceId,
        participants: Vec<UserId>,
    ) -> (TranscriptId, TranscriptId, Vec<SignedNode>) {
        let propose = CeremonyOp::DkgPropose {
            nonce: [1u8; 16],
            n: participants.len() as u16,
            k: 2,
            participants,
        };
        let pev = sign_ceremony(&[7u8; 32], &propose, w);
        let authority = TranscriptId::of(&pev).unwrap();
        let req = CeremonyOp::SignRequest {
            nonce: [2u8; 16],
            authority,
            target: SignTarget::SpaceOp,
            op: vec![1, 2, 3],
        };
        let rev = sign_ceremony(&[7u8; 32], &req, w);
        let signing = TranscriptId::of(&rev).unwrap();
        (authority, signing, vec![pev, rev])
    }

    /// One-contribution-per-author is not a bound on the signing side: an
    /// attacker mints as many keys as they like. Participants must be resolved
    /// through the request's named authority.
    #[test]
    fn signing_rounds_from_nonparticipant_keys_retain_nothing() {
        let w = ws();
        let insider = crate::crypto::user_from_seed(&[11u8; 32]);
        let (_authority, signing, mut evs) = dkg_and_request(&w, vec![insider.clone()]);
        // 500 distinct attacker keys, one round each — under any per-author cap.
        for i in 0..500u32 {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            seed[8] = 1; // keep clear of the insider seed
            evs.push(sign_ceremony(
                &seed,
                &CeremonyOp::SignRound1 {
                    signing,
                    commitments: vec![0u8; 8],
                },
                &w,
            ));
        }
        let mut board = parse_board(&evs, &w);
        board.restrict_signing_rounds(|_| None);
        assert_eq!(
            board.signing[&signing].rounds.len(),
            0,
            "no attacker key is a participant of the named authority"
        );

        // The insider's round is retained, and is not displaced by the flood.
        evs.push(sign_ceremony(
            &[11u8; 32],
            &CeremonyOp::SignRound1 {
                signing,
                commitments: vec![9u8; 8],
            },
            &w,
        ));
        let mut board = parse_board(&evs, &w);
        board.restrict_signing_rounds(|_| None);
        assert_eq!(board.signing[&signing].rounds.len(), 1);
        assert_eq!(board.signing[&signing].rounds[0].author, insider);
    }

    /// An authority the projection cannot resolve, and for which the caller has
    /// no authenticated local record, retains no actionable rounds — nothing can
    /// establish who is permitted to contribute.
    #[test]
    fn a_request_naming_an_unknown_authority_retains_no_rounds() {
        let w = ws();
        let unknown = TranscriptId::parse_hex(&"e".repeat(64)).unwrap();
        let req = CeremonyOp::SignRequest {
            nonce: [2u8; 16],
            authority: unknown,
            target: SignTarget::SpaceOp,
            op: vec![1],
        };
        let rev = sign_ceremony(&[11u8; 32], &req, &w);
        let signing = TranscriptId::of(&rev).unwrap();
        let round = sign_ceremony(
            &[11u8; 32],
            &CeremonyOp::SignRound1 {
                signing,
                commitments: vec![1],
            },
            &w,
        );
        let mut board = parse_board(&[rev, round], &w);
        board.restrict_signing_rounds(|_| None);
        assert_eq!(board.signing[&signing].rounds.len(), 0);
    }

    /// The fallback resolves an authority missing from the projection, so a
    /// pruned or not-yet-synced proposal does not strand a live group.
    #[test]
    fn an_authenticated_fallback_resolves_a_missing_authority() {
        let w = ws();
        let holder = crate::crypto::user_from_seed(&[11u8; 32]);
        let missing = TranscriptId::parse_hex(&"e".repeat(64)).unwrap();
        let req = CeremonyOp::SignRequest {
            nonce: [2u8; 16],
            authority: missing,
            target: SignTarget::SpaceOp,
            op: vec![1],
        };
        let rev = sign_ceremony(&[11u8; 32], &req, &w);
        let signing = TranscriptId::of(&rev).unwrap();
        let round = sign_ceremony(
            &[11u8; 32],
            &CeremonyOp::SignRound1 {
                signing,
                commitments: vec![1],
            },
            &w,
        );
        let mut board = parse_board(&[rev, round], &w);
        board.restrict_signing_rounds(|id| (*id == missing).then(|| vec![holder.clone()]));
        assert_eq!(board.signing[&signing].rounds.len(), 1);
    }

    /// A signing request cannot smuggle in its own participant set: the filter
    /// reads the authority's proposal, never the request. Here the request names
    /// authority A while the attacker holds a slot only in an unrelated DKG B.
    #[test]
    fn a_signing_request_cannot_borrow_another_dkgs_participants() {
        let w = ws();
        let outsider = crate::crypto::user_from_seed(&[42u8; 32]);
        let insider = crate::crypto::user_from_seed(&[11u8; 32]);

        // Authority A names only the insider.
        let (_a_id, signing, mut evs) = dkg_and_request(&w, vec![insider]);
        // An unrelated DKG B names the outsider — irrelevant to this request.
        let other = CeremonyOp::DkgPropose {
            nonce: [9u8; 16],
            n: 1,
            k: 1,
            participants: vec![outsider],
        };
        evs.push(sign_ceremony(&[7u8; 32], &other, &w));
        evs.push(sign_ceremony(
            &[42u8; 32],
            &CeremonyOp::SignRound1 {
                signing,
                commitments: vec![1],
            },
            &w,
        ));
        let mut board = parse_board(&evs, &w);
        board.restrict_signing_rounds(|_| None);
        assert_eq!(
            board.signing[&signing].rounds.len(),
            0,
            "membership of another DKG grants nothing here"
        );
    }

    // ---- retention ----

    /// Rounds naming a transcript nobody opened can never be acted on, and
    /// anyone can mint ids — so they must not accumulate as retained state.
    #[test]
    fn rounds_for_an_unopened_transcript_are_dropped() {
        let w = ws();
        let orphan = TranscriptId::parse_hex(&"d".repeat(64)).unwrap();
        let ev = sign_ceremony(
            &[5u8; 32],
            &CeremonyOp::DkgRound1 {
                dkg: orphan,
                package: vec![1, 2, 3],
            },
            &w,
        );
        let board = parse_board(&[ev], &w);
        assert!(board.dkg.is_empty(), "no opener, no transcript");
    }

    /// A round from a device the proposal never named cannot contribute, so it
    /// is dropped rather than carried.
    #[test]
    fn rounds_from_non_participants_are_dropped() {
        let w = ws();
        let insider = crate::crypto::user_from_seed(&[11u8; 32]);
        let propose = CeremonyOp::DkgPropose {
            nonce: [1u8; 16],
            n: 2,
            k: 2,
            participants: vec![insider.clone()],
        };
        let pev = sign_ceremony(&[11u8; 32], &propose, &w);
        let id = TranscriptId::of(&pev).unwrap();
        let good = sign_ceremony(
            &[11u8; 32],
            &CeremonyOp::DkgRound1 {
                dkg: id,
                package: vec![1],
            },
            &w,
        );
        let outsider = sign_ceremony(
            &[99u8; 32],
            &CeremonyOp::DkgRound1 {
                dkg: id,
                package: vec![2],
            },
            &w,
        );
        let board = parse_board(&[pev, good, outsider], &w);
        assert_eq!(board.dkg[&id].rounds.len(), 1);
        assert_eq!(board.dkg[&id].rounds[0].author, insider);
    }

    /// Duplicates past the first were already ignored by `entry().or_insert`,
    /// but they were retained — so a legitimate participant could flood a
    /// transcript they belong to.
    #[test]
    fn one_round_per_author_per_kind_is_retained() {
        let w = ws();
        let me = crate::crypto::user_from_seed(&[11u8; 32]);
        let propose = CeremonyOp::DkgPropose {
            nonce: [1u8; 16],
            n: 2,
            k: 2,
            participants: vec![me.clone()],
        };
        let pev = sign_ceremony(&[11u8; 32], &propose, &w);
        let id = TranscriptId::of(&pev).unwrap();
        let mut events = vec![pev];
        for i in 0..50u8 {
            events.push(sign_ceremony(
                &[11u8; 32],
                &CeremonyOp::DkgRound1 {
                    dkg: id,
                    package: vec![i],
                },
                &w,
            ));
        }
        let board = parse_board(&events, &w);
        assert_eq!(
            board.dkg[&id].rounds.len(),
            1,
            "50 round-1 posts from one author retain one"
        );
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
