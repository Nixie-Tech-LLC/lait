//! Why a replica operation failed, as structured values.
//!
//! The replica is the domain: it decides what is legitimate, not how to say so.
//! An error here names *what went wrong* and carries the data that made it go
//! wrong; turning that into a sentence a person reads — and into a wire
//! `Response` — belongs to the control adapter in [`super::dispatch`], which is
//! the single door between this crate's domain and the client protocol.
//!
//! Two consequences worth stating, because they are the reason the type exists:
//! a caller can distinguish "no such ref" from "you may not do that" without
//! matching on prose, and the domain no longer depends on the control plane, so
//! it can be lifted out from under the daemon without dragging it along.
//!
//! **On `Display`.** These render exactly the sentences the CLI, web, and MCP
//! surfaces already show. That is deliberate: this refactor changes where a
//! message is produced, never what a person sees. Wording changes are their own
//! commits, with their own reasons.

use crate::dto::StatusCategory;
use std::fmt;

/// A replica operation's failure.
#[derive(Debug)]
pub enum ReplicaError {
    /// A reference did not resolve to exactly one issue.
    ///
    /// Not every member of this family is really a failure: an ambiguous ref, or
    /// a typo with near misses, is answered with the candidate list rather than
    /// a refusal, because the useful reply is "did you mean one of these". The
    /// domain reports what it found and the adapter decides how to say it, which
    /// is exactly the split this type exists to make.
    Ref(RefError),
    /// A request needing one project could not settle on one.
    ProjectChoice(ProjectChoice),
    /// Nothing here answers to that name. The only family the control plane
    /// reports as `NotFound` (exit code 2), so a script can tell "absent" from
    /// "refused" without reading the message.
    NotFound(NotFound),
    /// The caller may not do this — membership standing, admin gates, or a
    /// self-protection rule.
    Denied(Denied),
    /// The request itself is malformed: empty where a value is required, or not
    /// the shape an id/key/blob must take.
    Invalid(Invalid),
    /// Well-formed and permitted, but it contradicts state that already exists.
    Conflict(Conflict),
    /// A multi-step ceremony (recovery, elevation, custody) refused a step.
    /// Boxed: this is the widest variant by far and every `Result` in the
    /// replica would otherwise pay for its size.
    Ceremony(Box<Ceremony>),
    /// A failure from beneath the domain — persistence, encoding, crypto —
    /// carried verbatim. Formatted with the anyhow chain, as it always was.
    Internal(anyhow::Error),
}

/// How a reference failed to name exactly one issue.
#[derive(Debug)]
pub enum RefError {
    /// Nothing matched, and nothing was close enough to suggest.
    NoMatch { reff: String },
    /// Either the ref matched several issues, or it matched none but some
    /// handles are near enough to be worth offering. `near_miss_for` carries the
    /// original ref in the second case, and is absent in the first — that is the
    /// difference between "which of these did you mean" and "did you mean one of
    /// these", and clients render them differently.
    Candidates {
        candidates: Vec<crate::dto::Candidate>,
        near_miss_for: Option<String>,
    },
}

/// Something was named that does not exist here.
#[derive(Debug)]
pub enum NotFound {
    Project {
        named: String,
    },
    Label {
        named: String,
    },
    /// No member of this space answers to that handle. Distinct from an unknown
    /// *actor*: this asks the membership roll, not the directory.
    Member {
        named: String,
    },
    /// The edge named by (source, kind, target) is not in the graph. Boxed: it
    /// is the widest failure in this family, and every `Result` in the replica
    /// would otherwise carry its three strings by value.
    Link(Box<LinkRef>),
    /// No share package at that path.
    CustodyPackage {
        path: String,
    },
    /// No actor answers to that `<who>`, when co-signing a recovery. The fix is
    /// to sync the recovering device's identity, not to invite anyone.
    RecoveryActor {
        named: String,
    },
    /// No actor answers to that `<who>`, on the agent-sponsorship path — which
    /// says how to fix it in its own terms: an agent arrives by being started,
    /// not by being invited.
    AgentActor {
        named: String,
    },
    /// No actor answers to that `<who>`. `invite_hint` asks for the tail that
    /// says how to fix it, which the add path wants and the remove path does
    /// not — removing someone who was never here needs no invitation.
    Actor {
        named: String,
        invite_hint: bool,
    },
}

/// The three handles that name one edge of the issue graph.
#[derive(Debug)]
pub struct LinkRef {
    pub reff: String,
    pub kind: String,
    pub target: String,
}

/// Why no single project could be chosen for a request that needs one.
///
/// Each case carries the way out in its message: a request that cannot name its
/// project is usually a configuration gap, not a mistake, and the caller can
/// almost always fix it in one command.
#[derive(Debug)]
pub enum ProjectChoice {
    /// `project.default` names a project that no longer exists.
    StaleDefault { configured: String },
    /// The space has no projects yet.
    None,
    /// Several exist and nothing selected one.
    Ambiguous { keys: Vec<String> },
}

/// The caller lacks the standing this operation requires.
#[derive(Debug)]
pub enum Denied {
    /// A member holding neither Write nor Admin — a viewer — tried to mutate
    /// space content.
    ViewOnly,
    /// An admin-gated membership operation, attempted without admin.
    NotAdmin(AdminAction),
    /// Agents hold no membership authority of their own.
    NotHuman,
    /// Removing yourself would strand the space; leaving is a different verb.
    SelfRemoval,
    /// This device has not established an actor identity yet.
    NoActorIdentity { in_this_space: bool },
    /// The device that signed the invite grant does not currently speak for an
    /// admin. Authority is evaluated now, not when the invite was written, so a
    /// demoted issuer's outstanding invites stop admitting.
    IssuerNotAdmin,
    /// This node holds no admin standing, so it cannot seal a joiner in even
    /// though the invite itself is good.
    NodeNotAdmin,
}

/// The admin-gated operations, named so the message can say which was refused.
#[derive(Debug, Clone, Copy)]
pub enum AdminAction {
    AddMember,
    RemoveMember,
    RevokeInvite,
    RotateKey,
    DeleteIssue,
}

/// The request could not be understood.
#[derive(Debug)]
pub enum Invalid {
    /// A field that must carry text was empty.
    Empty(EmptyField),
    /// An edit that names no change.
    NothingToEdit,
    /// Not one of the priority names.
    Priority { value: String },
    /// Not a status this space's workflow defines.
    Status { value: String },
    /// Not one of [`LINK_KINDS`](super::LINK_KINDS).
    LinkKind { value: String },
    /// Not a usable project key. The rule is narrow because the key becomes the
    /// `KEY` in `KEY-1` refs, which both alias parsing and git-branch inference
    /// scan as a single alphabetic run.
    ProjectKey { value: String },
    /// An actor inception that does not cleanly incept for this space. A forged
    /// one must never enter the actors container, so this is checked against a
    /// candidate replay before admission.
    ActorInception { in_join_request: bool },
    /// Neither a ticket nor a bare nonce.
    InviteRef,
    /// An agent inception that does not cleanly incept for this space.
    AgentInception,
    /// The consent blob did not decode at all.
    DeviceConsentBlob,
    /// The consent blob decoded but does not bind this device to this actor.
    DeviceConsentMismatch,
    /// Not a 64-hex ed25519 device key.
    DeviceKey,
    /// A co-founder named for an elevation is not a device key. Distinct from
    /// [`DeviceKey`](Self::DeviceKey) because it echoes which of the named
    /// co-founders was rejected, out of a list the caller passed.
    CofounderDeviceKey { value: String },
}

/// The fields that must carry text. A closed set rather than a string: these
/// name domain inputs, and their refusals are not all phrased alike, so a
/// caller-supplied name could not render them anyway.
#[derive(Debug, Clone, Copy)]
pub enum EmptyField {
    Title,
    Comment,
    LabelName,
    ProjectNameKey,
}

/// The operation contradicts state that already exists.
#[derive(Debug)]
pub enum Conflict {
    InviteRedeemed,
    InviteRevoked,
    /// An issue-graph edge that would make a cycle or a self-reference.
    IssueGraph(GraphViolation),
    /// The request is well-formed; this space's workflow simply defines no
    /// status in the category the verb targets.
    NoStatusInCategory {
        category: StatusCategory,
    },
    ProjectKeyExists {
        key: String,
    },
    LabelExists {
        name: String,
    },
    /// The actor resolved, but no inception for it has reached this replica, so
    /// there is nothing to seal a key to yet. A state gap, not a bad argument —
    /// the same request succeeds once their identity syncs.
    ActorUnknown {
        short: String,
    },
    /// An agent whose identity has not reached this replica yet.
    AgentUnknown {
        short: String,
    },
    /// Already holds standing here, so there is nothing to sponsor.
    AlreadyPrincipal {
        short: String,
    },
    /// The named device is not one of this actor's.
    NotYourDevice,
    /// Revoking the last device would strand the actor; recovery is the verb
    /// for that, and it re-roots the device set rather than emptying it.
    OnlyDevice,
    /// No offline recovery key is present beside the store.
    RecoveryKeyMissing,
    /// The recovery key matches no actor's standing commitment here.
    RecoveryKeyUnmatched,
    /// The key resolved to an actor, but the replay does not agree the recovery
    /// took — the commitment does not match.
    RecoveryCommitmentMismatch,
}

#[derive(Debug, Clone, Copy)]
pub enum GraphViolation {
    SelfParent,
    SelfLink,
    Ancestor,
}

/// A ceremony step refused. These carry the operator-facing guidance the
/// original messages carried — a ceremony failure is usually actionable, and
/// the action is rarely obvious.
#[derive(Debug)]
pub enum Ceremony {
    /// Free-form ceremony refusal, carrying its own guidance verbatim. The
    /// ceremony surface is wide and mostly one-of-a-kind; structuring every
    /// distinct refusal would produce a variant per message and buy nothing.
    Refused { message: String },
    /// This device holds shares of the current group key that it cannot open.
    ///
    /// Structured rather than pre-rendered because the *cause* decides the
    /// remedy — a file protected under another Windows account is not an I/O
    /// fault — and because this is the one refusal whose text is built by
    /// looping over a collection. The loop belongs to the adapter.
    ShareUnusable {
        holders: Vec<super::DegradedRecoveryHolder>,
    },
    /// The request re-roots somewhere other than the actors the holder named.
    /// Carries where it actually points, since that is what the holder needs
    /// to see before deciding.
    RootMismatch { roots: Vec<crate::ids::ActorId> },
    /// The signing request authorizes a different proposal than the one named.
    ProposalMismatch { proposal: crate::dkg::TranscriptId },
}

impl ReplicaError {
    /// Convenience for the many ceremony refusals that are one-of-a-kind.
    pub fn ceremony(message: impl Into<String>) -> Self {
        Self::Ceremony(Box::new(Ceremony::Refused {
            message: message.into(),
        }))
    }
}

impl From<anyhow::Error> for ReplicaError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl fmt::Display for ReplicaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ref(e) => e.fmt(f),
            Self::ProjectChoice(e) => e.fmt(f),
            Self::NotFound(e) => e.fmt(f),
            Self::Denied(e) => e.fmt(f),
            Self::Invalid(e) => e.fmt(f),
            Self::Conflict(e) => e.fmt(f),
            Self::Ceremony(e) => e.fmt(f),
            Self::Internal(e) => write!(f, "{e:#}"),
        }
    }
}

impl fmt::Display for RefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatch { reff } => write!(f, "no issue matches '{reff}'"),
            // Rendered as a candidate list, never as a sentence; this exists so
            // the type is printable, not because anyone reads it.
            Self::Candidates { .. } => f.write_str("that reference matches more than one issue"),
        }
    }
}

impl fmt::Display for NotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Project { named } => write!(f, "no project matches '{named}'"),
            Self::Label { named } => write!(f, "no label matches '{named}'"),
            Self::Member { named } => write!(f, "no known member matches '{named}'"),
            Self::CustodyPackage { path } => write!(f, "no package at {path}"),
            Self::RecoveryActor { named } => write!(
                f,
                "no known actor matches '{named}' — sync the recovering device's identity first"
            ),
            Self::AgentActor { named } => write!(
                f,
                "no known actor for '{named}' — start the agent so it joins the space, then sponsor it"
            ),
            Self::Actor { named, invite_hint } => {
                write!(f, "no known actor matches '{named}'")?;
                if *invite_hint {
                    f.write_str(" — invite them first so their identity arrives")?;
                }
                Ok(())
            }
            Self::Link(link) => {
                let LinkRef { reff, kind, target } = &**link;
                write!(f, "no such link: {reff} {kind} {target}")
            }
        }
    }
}

impl fmt::Display for ProjectChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleDefault { configured } => write!(
                f,
                "project.default is '{configured}' but no such project exists — fix it: `lait config set project.default <KEY>`"
            ),
            Self::None => f.write_str(
                "no projects visible yet — still syncing, or create one: `lait projects new <name> --key <KEY>`",
            ),
            Self::Ambiguous { keys } => write!(
                f,
                "more than one project ({}) — pass -p <KEY> or set a default: `lait config set project.default <KEY>`",
                keys.join(", ")
            ),
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ViewOnly => f.write_str("view-only: your membership grants no write access"),
            Self::NotAdmin(action) => match action {
                AdminAction::AddMember => f.write_str("only an admin can add members"),
                AdminAction::RemoveMember => f.write_str("only an admin can remove members"),
                AdminAction::RevokeInvite => f.write_str("only an admin can revoke an invite"),
                AdminAction::RotateKey => f.write_str("only an admin can rotate the key"),
                AdminAction::DeleteIssue => {
                    f.write_str("no content authority to delete issues (view-only or agent)")
                }
            },
            Self::NotHuman => f.write_str("only a human member can sponsor an agent"),
            Self::IssuerNotAdmin => f.write_str("invite issuer is not a space admin"),
            Self::NodeNotAdmin => f.write_str("this node is not an admin"),
            Self::SelfRemoval => f.write_str("refusing to remove yourself"),
            Self::NoActorIdentity { in_this_space } => {
                if *in_this_space {
                    f.write_str("this device has no actor identity in this space yet")
                } else {
                    f.write_str("this device has no actor identity")
                }
            }
        }
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty(field) => match field {
                EmptyField::Title => f.write_str("title must not be empty"),
                EmptyField::Comment => f.write_str("comment body must not be empty"),
                EmptyField::LabelName => f.write_str("label name is required"),
                EmptyField::ProjectNameKey => f.write_str("project name and key are required"),
            },
            Self::NothingToEdit => f.write_str("nothing to edit"),
            Self::Priority { value } => write!(f, "bad priority '{value}'"),
            Self::Status { value } => write!(f, "no such status '{value}'"),
            // The accepted set is a constant, so the adapter renders it rather
            // than the failure carrying a copy of it.
            Self::LinkKind { value } => write!(
                f,
                "unknown link kind '{value}' — one of: {}",
                super::LINK_KINDS.join(", ")
            ),
            Self::ActorInception { in_join_request } => {
                if *in_join_request {
                    f.write_str("join request carried an invalid actor inception")
                } else {
                    f.write_str("invalid actor inception")
                }
            }
            Self::InviteRef => {
                f.write_str("not a valid invite — pass the ticket or its 32-hex nonce")
            }
            Self::AgentInception => f.write_str("invalid agent inception"),
            Self::DeviceConsentBlob => f.write_str("could not decode device consent blob"),
            Self::DeviceConsentMismatch => {
                f.write_str("device consent is not valid for this actor")
            }
            Self::DeviceKey => f.write_str("a device is a 64-hex ed25519 key"),
            Self::CofounderDeviceKey { value } => {
                write!(f, "'{value}' is not a device key (64 hex chars)")
            }
            Self::ProjectKey { value } => write!(
                f,
                "bad project key '{value}' — use 1-8 ASCII letters (it becomes the KEY in KEY-1 refs)"
            ),
        }
    }
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InviteRedeemed => f.write_str("invite already redeemed"),
            Self::InviteRevoked => f.write_str("this invite has been revoked"),
            Self::IssueGraph(v) => match v {
                GraphViolation::SelfParent => f.write_str("an issue cannot be its own parent"),
                GraphViolation::SelfLink => f.write_str("an issue cannot link to itself"),
                GraphViolation::Ancestor => {
                    f.write_str("that would make an issue its own ancestor")
                }
            },
            Self::NoStatusInCategory { category } => write!(
                f,
                "this space's workflow has no {}-category status",
                category.as_str()
            ),
            Self::ProjectKeyExists { key } => write!(f, "project key '{key}' already exists"),
            Self::LabelExists { name } => write!(f, "label '{name}' already exists"),
            Self::ActorUnknown { short } => write!(
                f,
                "unknown actor {short} — invite them so their identity arrives first"
            ),
            Self::AgentUnknown { short } => write!(
                f,
                "unknown agent {short} — start it so its identity joins first"
            ),
            Self::AlreadyPrincipal { short } => {
                write!(f, "{short} is already a space principal")
            }
            Self::NotYourDevice => f.write_str("not a device of your actor"),
            Self::OnlyDevice => {
                f.write_str("cannot revoke your only device — use `recover` instead")
            }
            Self::RecoveryKeyMissing => f.write_str(
                "no recovery.key found beside the store — restore your offline recovery key first",
            ),
            Self::RecoveryKeyUnmatched => {
                f.write_str("no actor in this space matches this recovery key")
            }
            Self::RecoveryCommitmentMismatch => {
                f.write_str("recovery key does not match this actor's commitment")
            }
        }
    }
}

impl fmt::Display for Ceremony {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { message } => f.write_str(message),
            Self::ShareUnusable { holders } => {
                f.write_str(
                    "this device holds a FROST share that cannot be used:
",
                )?;
                for h in holders {
                    let why = match &h.reason {
                        super::RecoveryArtifactFailure::Undecryptable(m) => {
                            format!("protected under another Windows account or machine ({m})")
                        }
                        super::RecoveryArtifactFailure::Io(m) => {
                            format!("present but could not be read ({m})")
                        }
                    };
                    let scope = match h.is_current_authority {
                        Some(true) => "the current recovery key",
                        // Unproven currency is reported as such rather than
                        // asserted either way.
                        None => "a recovery key whose group could not be identified",
                        Some(false) => unreachable!("superseded groups are filtered out"),
                    };
                    writeln!(f, "  transcript {}: {scope} — {why}", h.transcript)?;
                }
                f.write_str(
                    "This device cannot take part in recovery. Recovery remains possible only if the configured authority requirements can still be satisfied by the other holders, which this device cannot verify.",
                )
            }
            Self::ProposalMismatch { proposal } => write!(
                f,
                "that request authorizes proposal {}, not the one you named — refusing to co-sign",
                proposal.to_hex()
            ),
            Self::RootMismatch { roots } => {
                let roots = roots
                    .iter()
                    .map(|a| a.short())
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(
                    f,
                    "that request re-roots to {roots}, not the actor(s) you named — refusing to co-sign"
                )
            }
        }
    }
}
