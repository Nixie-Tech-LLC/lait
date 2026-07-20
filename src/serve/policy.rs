//! What a request may do, and to whose space.
//!
//! `lait serve` exposes the control plane verbatim, so the browser is exactly as
//! privileged as the CLI — which is the intent: it is a Layer-B client, not a
//! lesser one. The two rules here are the places where that equivalence is
//! deliberately *not* total.

use crate::control::Request;

/// Whether `req` only reads.
///
/// An **allowlist**, and the direction matters. `Request` fields are add-only,
/// so a verb added after this was written must default to "not a read" — refused
/// for an identity that isn't ours — rather than quietly inherit permission. The
/// match is exhaustive rather than `_ => false` for the same reason: a new variant
/// should fail to *compile* until somebody classifies it, instead of picking a
/// side on its own.
///
/// `Inbox` is the one conditional, and it is why this cannot be a per-variant
/// list: `clear: true` advances the read watermark (`inbox::mark_read`), so it is
/// a write wearing a read's name.
pub fn is_read(req: &Request) -> bool {
    match req {
        Request::IssueView { .. }
        | Request::List { .. }
        | Request::Board { .. }
        | Request::History { .. }
        | Request::ProjectList
        | Request::LabelList
        | Request::Activity { .. }
        | Request::IssueGraph { .. }
        | Request::Members
        | Request::MemberLog
        | Request::MemberRequests
        | Request::DeviceInvite
        | Request::DeviceList
        | Request::Status
        | Request::Diagnose { .. }
        | Request::Id
        | Request::SeedList
        | Request::Log { .. }
        | Request::Who
        | Request::Hello { .. } => true,

        // Reads the inbox, but `clear` advances the watermark on the way out.
        Request::Inbox { clear } => !clear,

        // Writes: the replica plane…
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
        | Request::AgentAdd { .. }
        | Request::IssueStart { .. }
        | Request::IssueDone { .. }
        | Request::IssueStop { .. }
        // …the registries…
        | Request::ProjectNew { .. }
        | Request::LabelNew { .. }
        // …the ACL, every op of which is signed by whoever's daemon runs it…
        | Request::MemberAdd { .. }
        | Request::MemberRemove { .. }
        | Request::MemberApprove { .. }
        | Request::MemberAlias { .. }
        | Request::KeyRotate
        | Request::InviteRevoke { .. }
        | Request::DeviceAdd { .. }
        | Request::DeviceRevoke { .. }
        | Request::Recover
        | Request::SpaceRecover
        | Request::SpaceElevate { .. }
        | Request::SpaceRecoverApprove { .. }
        | Request::SpaceElevateApprove { .. }
        // …and custody, which handles a holder's own key material and a
        // passphrase, so it belongs to the operator at the machine and not to a
        // browser session…
        | Request::SpaceCustodyExport { .. }
        | Request::SpaceCustodyImport { .. }
        // …joining and inviting, which act *as* an identity on the wire…
        | Request::Invite { .. }
        | Request::Join { .. }
        | Request::Connect { .. }
        | Request::SeedAdd { .. }
        | Request::SeedRemove { .. }
        // …and node control.
        | Request::ConfigReload
        | Request::Stop => false,

        // Not a one-shot at all — see `serve::rpc`, which refuses it with a
        // pointer to the endpoint that streams (`GET /api/events`).
        Request::Subscribe { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::Filter;

    #[test]
    fn reads_are_reads() {
        assert!(is_read(&Request::Status));
        assert!(is_read(&Request::Members));
        assert!(is_read(&Request::Board {
            project: None,
            project_hint: None
        }));
        assert!(is_read(&Request::List {
            project: None,
            filter: Filter::default()
        }));
    }

    #[test]
    fn writes_are_not() {
        assert!(!is_read(&Request::IssueDelete {
            reff: "iss_1".into()
        }));
        assert!(!is_read(&Request::KeyRotate));
        assert!(!is_read(&Request::Invite {
            require_approval: false,
            reusable: false,
            ttl_hours: None,
        }));
    }

    #[test]
    fn inbox_is_a_read_only_until_it_clears() {
        // The trap this allowlist exists to catch: same verb, both sides of the
        // line, decided by a field rather than a variant.
        assert!(is_read(&Request::Inbox { clear: false }));
        assert!(!is_read(&Request::Inbox { clear: true }));
    }
}
