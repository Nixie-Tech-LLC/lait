//! The guided-join verifier core (see `docs/UI.md`, joining).
//!
//! A **pure projection** of live daemon state into an ordered list of onboarding
//! *gates*, so a stalled joiner gets one legible line naming what's blocking them
//! instead of a blank board. Kept deliberately free of I/O, ANSI, and daemon
//! types: it takes primitive inputs and returns a [`DiagnosisView`] DTO, so the
//! exact same logic backs CLI `doctor`, the `join` tail, and the MCP `doctor`
//! tool, and is unit-tested without a
//! running node. The daemon handler ([`crate::node`]) is the only caller that
//! gathers the inputs; everything downstream renders the DTO.

use serde::{Deserialize, Serialize};

use crate::dto::SCHEMA_VERSION;

/// The state of a single onboarding gate. `Skip` is *not* blocking (it means the
/// gate doesn't apply yet — e.g. board-sync while still `pending`); `Wait`/`Fail`
/// both block, the difference being whether time alone can clear it (`Wait`) or a
/// human/config change is required (`Fail`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateState {
    Pass,
    Wait,
    Fail,
    /// Something needs attention but does not stop you working. Deliberately
    /// **not** blocking: key-custody problems are urgent to fix and irrelevant
    /// to whether you are onboarded, so a warning must not hijack `blocked_on`
    /// and tell a joiner they are stuck.
    Warn,
    Skip,
}

impl GateState {
    /// A plain (non-ANSI) glyph for the gate, shared by human-facing renderers.
    /// Colour is layered on separately.
    pub fn glyph(self) -> &'static str {
        match self {
            GateState::Warn => "\u{26a0}", // ⚠
            GateState::Pass => "\u{2714}", // ✔
            GateState::Wait => "\u{231b}", // ⌛
            GateState::Fail => "\u{2718}", // ✘
            GateState::Skip => "\u{25cb}", // ○
        }
    }

    /// Whether this gate blocks "get to work". `Skip` never blocks.
    pub fn is_blocking(self) -> bool {
        matches!(self, GateState::Wait | GateState::Fail)
    }
}

/// One ordered gate in the diagnosis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosisGate {
    /// Stable machine id: `space` | `daemon` | `membership` | `peer` | `synced`.
    pub id: String,
    /// Human label for the gate (left column).
    pub label: String,
    pub state: GateState,
    /// Human detail (right column): the current value, or what we're waiting on.
    pub detail: String,
}

impl DiagnosisGate {
    fn new(id: &str, label: &str, state: GateState, detail: impl Into<String>) -> Self {
        DiagnosisGate {
            id: id.to_string(),
            label: label.to_string(),
            state,
            detail: detail.into(),
        }
    }
}

/// The versioned diagnosis DTO — what `Diagnose` returns on every surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosisView {
    pub schema_version: u32,
    pub gates: Vec<DiagnosisGate>,
    /// The id of the first non-passing gate — the one actionable blocker — or
    /// `None` when every gate passes (you're in and synced).
    pub blocked_on: Option<String>,
    /// A one-line human summary keyed off the blocking gate.
    pub summary: String,
}

/// Primitive inputs the daemon gathers for a diagnosis. Borrowed so the caller
/// need not clone its state just to project it.
#[derive(Debug, Clone, Copy)]
pub struct DiagnoseInput<'a> {
    /// The space id this store is bound to, if any (`None` before genesis).
    pub space: Option<&'a str>,
    /// The space's synced display name (may be empty on a pre-sync joiner).
    pub name: &'a str,
    /// This node's ACL standing: `admin` | `member` | `pending`.
    pub membership: &'a str,
    /// Count of currently-online peers.
    pub online_peers: usize,
    pub projects: usize,
    pub issues: usize,
    /// The space the caller *intended* to be in — supplied by the `join` tail
    /// (from the invite ticket) so a directory/store mismatch is caught. `None`
    /// for a standalone `doctor`, which can't know intent.
    pub expected_space: Option<&'a str>,
    /// Recovery shares present on this device that cannot be used. Borrowed as a
    /// slice so the struct stays `Copy`.
    pub degraded_recovery: &'a [crate::replica::DegradedRecoveryHolder],
    /// An outstanding rekey obligation this node cannot discharge itself — an
    /// actor evicted by a revoked invite still holds live keys and no admin has
    /// rotated past the fence yet.
    pub rekey_pending: Option<&'a str>,
    /// This device's custody standing for the recovery authority. Borrowed so
    /// the struct stays `Copy`.
    pub local_custody: Option<&'a crate::replica::LocalCustodyState>,
}

/// Project daemon state into the ordered gate list (pure — the validation core).
pub fn diagnose(input: DiagnoseInput<'_>) -> DiagnosisView {
    let bound = input.space.unwrap_or("(none)");
    let is_member = matches!(input.membership, "admin" | "member");

    // 1. space — the directory trap made legible. Only fails when the caller
    //    told us which space it expected (the `join` tail) and we bound a
    //    different one; a standalone doctor has no intent to compare against.
    let space = match input.expected_space {
        Some(exp) if input.space != Some(exp) => DiagnosisGate::new(
            "space",
            "space",
            GateState::Fail,
            format!(
                "this directory is space {bound}, but the invite is for {exp} \
                 — you're in a different store; cd to where you ran `lait join`, or target it with `-w`"
            ),
        ),
        _ => DiagnosisGate::new(
            "space",
            "space",
            GateState::Pass,
            if input.name.is_empty() {
                bound.to_string()
            } else {
                format!("{bound}  ('{}')", input.name)
            },
        ),
    };

    // 2. daemon — if we produced this projection, the daemon answered. An
    //    unreachable daemon never reaches here; the client reports that (exit 3).
    let daemon = DiagnosisGate::new("daemon", "daemon", GateState::Pass, "online");

    // 3. membership — the encryption gate. `pending` is a Wait (an admin clears
    //    it), not a Fail: nothing is wrong, you're just not approved yet.
    let membership = if is_member {
        DiagnosisGate::new(
            "membership",
            "membership",
            GateState::Pass,
            input.membership.to_string(),
        )
    } else {
        DiagnosisGate::new(
            "membership",
            "membership",
            GateState::Wait,
            "pending — waiting for an admin to approve you; the board stays encrypted until then",
        )
    };

    // Does the board already exist locally? A founder authors it; an approved
    // joiner has it once the catalog converges. Either way there's nothing left to
    // wait *for*, which is what decides whether an offline `peer` actually blocks.
    let is_admin = input.membership == "admin";
    let has_board = input.projects > 0 || input.issues > 0;

    // 4. peer — someone to sync *with*. This only **blocks** a joiner who still
    //    needs the board (member, not yet synced): for them an offline inviter is
    //    the real wall. A founder, or an already-synced member, isn't blocked by an
    //    empty room — they can work locally — so peer is informational (Skip), not a
    //    contradictory second blocker next to a passing `synced` gate.
    let peer = if input.online_peers > 0 {
        DiagnosisGate::new(
            "peer",
            "peer",
            GateState::Pass,
            format!("{} online", peers_phrase(input.online_peers)),
        )
    } else if is_admin {
        DiagnosisGate::new(
            "peer",
            "peer",
            GateState::Skip,
            "no coworker online yet — share an invite so your team can join",
        )
    } else if is_member && has_board {
        DiagnosisGate::new(
            "peer",
            "peer",
            GateState::Skip,
            "no peer online — you're synced; edits exchange whenever someone's online",
        )
    } else if is_member {
        DiagnosisGate::new(
            "peer",
            "peer",
            GateState::Wait,
            "no peer online yet — the board syncs when the inviter (or a seed) is online",
        )
    } else {
        // pending: membership is the actionable blocker; don't double-flag peer.
        DiagnosisGate::new(
            "peer",
            "peer",
            GateState::Skip,
            "waiting on approval first (see membership)",
        )
    };

    // 5. synced — the convergence fog. Skipped while pending (can't decrypt). A
    //    founder/admin's board is authoritative-local, so it always Passes (an empty
    //    one is "0 projects", not "still syncing"). An approved joiner Waits until
    //    the catalog arrives, then Passes with a count.
    let synced = if !is_member {
        DiagnosisGate::new(
            "synced",
            "synced",
            GateState::Skip,
            "board stays encrypted until you're approved",
        )
    } else if is_admin || has_board {
        DiagnosisGate::new(
            "synced",
            "synced",
            GateState::Pass,
            format!("{} project(s), {} issue(s)", input.projects, input.issues),
        )
    } else {
        DiagnosisGate::new(
            "synced",
            "synced",
            GateState::Wait,
            "you're in, but no board data yet — syncing…",
        )
    };

    // 6. keys — custody health. Last, and never blocking: these are urgent to
    //    fix but say nothing about whether you are onboarded. A joiner mid-setup
    //    must not be told they are blocked because a founder share is stranded.
    let mut key_notes: Vec<String> = Vec::new();
    for h in input.degraded_recovery {
        let scope = match h.is_current_authority {
            Some(true) => "the space recovery key",
            // Currency could not be established; say so rather than assert it.
            _ => "a recovery key (group unidentified)",
        };
        key_notes.push(format!(
            "your share of {scope} is unusable ({})",
            match &h.reason {
                crate::replica::RecoveryArtifactFailure::Undecryptable(_) =>
                    "protected under another Windows account or machine",
                crate::replica::RecoveryArtifactFailure::Io(_) => "present but could not be read",
            }
        ));
    }
    if let Some(note) = input.rekey_pending {
        key_notes.push(note.to_string());
    }
    match input.local_custody {
        // Usable today, unrecoverable tomorrow — and the difference is invisible
        // until it matters, which is exactly why it is worth a standing warning.
        Some(crate::replica::LocalCustodyState::BackupUnverified) => key_notes.push(
            "your share of an all-holders arrangement has no verified portable backup              (`space custody-export`)"
                .into(),
        ),
        Some(crate::replica::LocalCustodyState::Missing) => {
            key_notes.push("this device should hold a recovery share and does not".into())
        }
        _ => {}
    }
    let keys = if key_notes.is_empty() {
        DiagnosisGate::new("keys", "keys", GateState::Pass, "custody healthy")
    } else {
        DiagnosisGate::new("keys", "keys", GateState::Warn, key_notes.join("; "))
    };

    let gates = vec![space, daemon, membership, peer, synced, keys];
    let blocked = gates.iter().find(|g| g.state.is_blocking());
    let blocked_on = blocked.map(|g| g.id.clone());
    let summary = summarize(blocked, input.projects, input.issues);

    DiagnosisView {
        schema_version: SCHEMA_VERSION,
        gates,
        blocked_on,
        summary,
    }
}

fn peers_phrase(n: usize) -> String {
    if n == 1 {
        "1 peer".to_string()
    } else {
        format!("{n} peers")
    }
}

/// One-line summary keyed off the first blocking gate (or success).
fn summarize(blocked: Option<&DiagnosisGate>, projects: usize, issues: usize) -> String {
    match blocked.map(|g| g.id.as_str()) {
        None => {
            format!("you're in — {projects} project(s), {issues} issue(s) synced. get to work.")
        }
        Some("space") => "wrong directory: this store is a different space than the invite. \
             cd to where you ran `lait join`, or run `lait spaces`."
            .to_string(),
        Some("membership") => {
            "waiting for an admin to approve your join — the board is still encrypted.".to_string()
        }
        Some("peer") => {
            "waiting for the inviter (or a seed) to come online so the board can sync.".to_string()
        }
        Some("synced") => "connected — syncing the board now…".to_string(),
        Some(other) => format!("blocked on {other}."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> DiagnoseInput<'static> {
        DiagnoseInput {
            space: Some("ws_A"),
            name: "lait",
            membership: "member",
            online_peers: 1,
            projects: 2,
            issues: 3,
            expected_space: None,
            degraded_recovery: &[],
            rekey_pending: None,
            local_custody: None,
        }
    }

    fn degraded(current: Option<bool>) -> crate::replica::DegradedRecoveryHolder {
        crate::replica::DegradedRecoveryHolder {
            transcript: "a".repeat(64),
            reason: crate::replica::RecoveryArtifactFailure::Undecryptable("dpapi".into()),
            is_current_authority: current,
        }
    }

    #[test]
    fn a_degraded_share_warns_without_blocking_onboarding() {
        let held = vec![degraded(Some(true))];
        let v = diagnose(DiagnoseInput {
            degraded_recovery: &held,
            ..input()
        });
        assert_eq!(gate(&v, "keys").state, GateState::Warn);
        assert!(gate(&v, "keys").detail.contains("space recovery key"));
        assert!(gate(&v, "keys").detail.contains("another Windows account"));
        // The whole point: a custody problem is not an onboarding blocker.
        assert_eq!(
            v.blocked_on, None,
            "a warning must never hijack the onboarding blocker"
        );
    }

    #[test]
    fn an_unidentified_group_is_not_claimed_to_be_the_recovery_key() {
        let held = vec![degraded(None)];
        let v = diagnose(DiagnoseInput {
            degraded_recovery: &held,
            ..input()
        });
        assert!(gate(&v, "keys").detail.contains("group unidentified"));
        assert!(!gate(&v, "keys").detail.contains("the space recovery key"));
    }

    #[test]
    fn an_unbacked_indispensable_share_warns() {
        let v = diagnose(DiagnoseInput {
            local_custody: Some(&crate::replica::LocalCustodyState::BackupUnverified),
            ..input()
        });
        assert_eq!(gate(&v, "keys").state, GateState::Warn);
        assert!(gate(&v, "keys").detail.contains("portable backup"));
        assert_eq!(v.blocked_on, None, "custody is not an onboarding blocker");
    }

    #[test]
    fn a_ready_holder_does_not_warn() {
        let v = diagnose(DiagnoseInput {
            local_custody: Some(&crate::replica::LocalCustodyState::Ready),
            ..input()
        });
        assert_eq!(gate(&v, "keys").state, GateState::Pass);
    }

    #[test]
    fn a_pending_rekey_warns_on_the_same_gate() {
        let v = diagnose(DiagnoseInput {
            rekey_pending: Some("revoked invite: xyz still holds a space key"),
            ..input()
        });
        assert_eq!(gate(&v, "keys").state, GateState::Warn);
        assert!(gate(&v, "keys").detail.contains("still holds a space key"));
        assert_eq!(v.blocked_on, None);
    }

    #[test]
    fn a_blocked_joiner_still_reports_custody_separately() {
        let held = vec![degraded(Some(true))];
        let v = diagnose(DiagnoseInput {
            membership: "pending",
            degraded_recovery: &held,
            ..input()
        });
        // The onboarding blocker is unchanged, and the warning rides alongside.
        assert_eq!(v.blocked_on.as_deref(), Some("membership"));
        assert_eq!(gate(&v, "keys").state, GateState::Warn);
    }

    fn gate<'a>(v: &'a DiagnosisView, id: &str) -> &'a DiagnosisGate {
        v.gates.iter().find(|g| g.id == id).expect("gate present")
    }

    #[test]
    fn all_pass_when_member_online_and_synced() {
        let v = diagnose(input());
        assert_eq!(v.blocked_on, None, "a fully-synced member has no blocker");
        assert!(v.gates.iter().all(|g| g.state == GateState::Pass));
        assert_eq!(
            gate(&v, "keys").state,
            GateState::Pass,
            "custody is healthy"
        );
        assert!(v.summary.contains("get to work"));
    }

    #[test]
    fn pending_joiner_blocks_on_membership_and_skips_sync() {
        let v = diagnose(DiagnoseInput {
            membership: "pending",
            projects: 0,
            issues: 0,
            ..input()
        });
        assert_eq!(v.blocked_on.as_deref(), Some("membership"));
        assert_eq!(gate(&v, "membership").state, GateState::Wait);
        // While pending the board is encrypted, so sync is Skip (not a second
        // blocker) — the joiner is pointed at the one thing that matters.
        assert_eq!(gate(&v, "synced").state, GateState::Skip);
        assert!(v.summary.contains("approve"));
    }

    #[test]
    fn space_mismatch_is_the_first_blocker() {
        // The directory trap: bound to ws_A but the invite was for ws_B.
        let v = diagnose(DiagnoseInput {
            expected_space: Some("ws_B"),
            ..input()
        });
        assert_eq!(gate(&v, "space").state, GateState::Fail);
        assert_eq!(
            v.blocked_on.as_deref(),
            Some("space"),
            "a wrong-store mismatch must win over everything downstream"
        );
        assert!(gate(&v, "space").detail.contains("ws_B"));
        assert!(v.summary.contains("wrong directory"));
    }

    #[test]
    fn matching_expected_space_passes() {
        let v = diagnose(DiagnoseInput {
            expected_space: Some("ws_A"),
            ..input()
        });
        assert_eq!(gate(&v, "space").state, GateState::Pass);
        assert_eq!(v.blocked_on, None);
    }

    #[test]
    fn solo_founder_is_not_blocked() {
        // An admin/founder with a local board but nobody online yet is NOT blocked:
        // their board is authoritative-local, so an empty room is just "no coworkers
        // yet" (Skip), never "waiting for the inviter" (they ARE the inviter).
        let v = diagnose(DiagnoseInput {
            membership: "admin",
            online_peers: 0,
            ..input()
        });
        assert_eq!(gate(&v, "membership").state, GateState::Pass);
        assert_eq!(gate(&v, "peer").state, GateState::Skip);
        assert_eq!(gate(&v, "synced").state, GateState::Pass);
        assert_eq!(v.blocked_on, None, "a solo founder can get to work");
        assert!(v.summary.contains("get to work"));
    }

    #[test]
    fn synced_member_offline_is_not_blocked() {
        // A returning member who already has the board, opening doctor while the
        // inviter happens to be offline: nothing blocks them (local-first). Peer is
        // informational, not a contradictory blocker next to a passing sync gate.
        let v = diagnose(DiagnoseInput {
            membership: "member",
            online_peers: 0,
            projects: 2,
            issues: 3,
            ..input()
        });
        assert_eq!(gate(&v, "peer").state, GateState::Skip);
        assert_eq!(gate(&v, "synced").state, GateState::Pass);
        assert_eq!(v.blocked_on, None);
    }

    #[test]
    fn unsynced_member_offline_blocks_on_peer() {
        // The genuine convergence wall: approved but the board hasn't arrived AND no
        // peer is online to send it. THIS is when "waiting for the inviter" is right.
        let v = diagnose(DiagnoseInput {
            membership: "member",
            online_peers: 0,
            projects: 0,
            issues: 0,
            ..input()
        });
        assert_eq!(gate(&v, "peer").state, GateState::Wait);
        assert_eq!(v.blocked_on.as_deref(), Some("peer"));
        assert!(v.summary.contains("come online"));
    }

    #[test]
    fn member_online_but_unsynced_blocks_on_synced() {
        let v = diagnose(DiagnoseInput {
            membership: "member",
            projects: 0,
            issues: 0,
            ..input()
        });
        assert_eq!(gate(&v, "membership").state, GateState::Pass);
        assert_eq!(gate(&v, "peer").state, GateState::Pass);
        assert_eq!(gate(&v, "synced").state, GateState::Wait);
        assert_eq!(v.blocked_on.as_deref(), Some("synced"));
    }

    #[test]
    fn view_round_trips_through_json() {
        let v = diagnose(input());
        let json = serde_json::to_string(&v).unwrap();
        let back: DiagnosisView = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn gate_ordering_is_stable() {
        let v = diagnose(input());
        let ids: Vec<&str> = v.gates.iter().map(|g| g.id.as_str()).collect();
        //  is LAST on purpose: the first five are the onboarding sequence a
        // joiner walks, and custody health is orthogonal to it.
        assert_eq!(
            ids,
            ["space", "daemon", "membership", "peer", "synced", "keys"]
        );
    }
}
