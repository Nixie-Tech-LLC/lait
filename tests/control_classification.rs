//! M0.1 — exhaustive terminal-owner classification of every control request.
//!
//! Every `control::Request` variant is mapped to exactly one **terminal
//! owner** — the single orbital plane that serves it once the migration is
//! complete. The `match` in [`terminal_owner`] is exhaustive, so adding a
//! variant without a terminal owner fails the build; a daemon catch-all is
//! forbidden by construction because there is no catch-all class.
//!
//! Owners (plan 01, "External architecture"):
//! - **Session** — product intent/query through `IssueRouter` → Session;
//! - **Mechanics** — membership/ceremony/custody/admission through the active
//!   Orbit/Station's mechanics;
//! - **Station** — connect/neighbor/Contact operations;
//! - **Observation** — status/subscription projections;
//! - **Lifecycle** — Runtime/Orbit/Station/daemon process concerns and
//!   node-local configuration adapters.

use lait::control::Request;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owner {
    Session,
    Mechanics,
    Station,
    Observation,
    Lifecycle,
}

/// The exhaustive terminal-owner table. Compile-enforced: a new `Request`
/// variant without an arm here is a build failure, not a runtime catch-all.
fn terminal_owner(r: &Request) -> Owner {
    use Owner::*;
    match r {
        // ---- Session: product intents, queries, projections ----
        Request::IssueNew { .. }
        | Request::IssueEdit { .. }
        | Request::IssueMove { .. }
        | Request::Assign { .. }
        | Request::Label { .. }
        | Request::Comment { .. }
        | Request::IssueDelete { .. }
        | Request::IssueRestore { .. }
        | Request::IssueLink { .. }
        | Request::IssueUnlink { .. }
        | Request::IssueParent { .. }
        | Request::IssueGraph { .. }
        | Request::IssueStart { .. }
        | Request::IssueDone { .. }
        | Request::IssueStop { .. }
        | Request::IssueView { .. }
        | Request::List { .. }
        | Request::Board { .. }
        | Request::History { .. }
        | Request::ProjectNew { .. }
        | Request::ProjectList
        | Request::LabelNew { .. }
        | Request::LabelList
        | Request::Activity { .. }
        | Request::Inbox { .. } => Session,

        // ---- Mechanics: membership, admission, ceremonies, custody, devices ----
        Request::MemberAdd { .. }
        | Request::MemberRemove { .. }
        | Request::Members
        | Request::MemberLog
        | Request::AgentAdd { .. }
        | Request::KeyRotate
        | Request::InviteRevoke { .. }
        | Request::DeviceInvite
        | Request::DeviceAdd { .. }
        | Request::DeviceRevoke { .. }
        | Request::DeviceList
        | Request::SpaceRecover
        | Request::SpaceElevate { .. }
        | Request::SpaceRecoverApprove { .. }
        | Request::SpaceElevateApprove { .. }
        | Request::SpaceReshare { .. }
        | Request::SpaceCustodyExport { .. }
        | Request::SpaceCustodyImport { .. }
        | Request::Recover
        | Request::Invite { .. }
        | Request::Join { .. }
        | Request::Id => Mechanics,

        // ---- Station: connect/neighbor/Contact ----
        Request::Connect { .. } | Request::Who => Station,

        // ---- Observation: status + subscription projections ----
        Request::Status | Request::Subscribe { .. } => Observation,

        // ---- Lifecycle/deployment: daemon process + node-local config ----
        Request::Diagnose { .. }
        | Request::SeedAdd { .. }
        | Request::SeedList
        | Request::SeedRemove { .. }
        | Request::Log { .. }
        | Request::ConfigReload
        | Request::Stop
        | Request::Hello { .. }
        | Request::MemberAlias { .. } => Lifecycle,
    }
}

#[test]
fn every_request_variant_has_a_terminal_owner() {
    // Exhaustiveness is compile-enforced by `terminal_owner`'s match. Assert
    // the intended mapping for one representative per owner.
    assert_eq!(
        terminal_owner(&Request::IssueNew {
            title: "t".into(),
            project: None,
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        }),
        Owner::Session
    );
    assert_eq!(terminal_owner(&Request::Members), Owner::Mechanics);
    assert_eq!(terminal_owner(&Request::DeviceList), Owner::Mechanics);
    assert_eq!(
        terminal_owner(&Request::Connect { ticket: "x".into() }),
        Owner::Station
    );
    assert_eq!(terminal_owner(&Request::Status), Owner::Observation);
    assert_eq!(terminal_owner(&Request::Stop), Owner::Lifecycle);
}
