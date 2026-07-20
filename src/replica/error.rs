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
        }
    }
}

impl fmt::Display for Ceremony {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { message } => f.write_str(message),
        }
    }
}
