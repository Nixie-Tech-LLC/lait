//! The guided-join verifier core (see `docs/GUIDED-JOIN.md`).
//!
//! A **pure projection** of live daemon state into an ordered list of onboarding
//! *gates*, so a stalled joiner gets one legible line naming what's blocking them
//! instead of a blank board. Kept deliberately free of I/O, ANSI, and daemon
//! types: it takes primitive inputs and returns a [`DiagnosisView`] DTO, so the
//! exact same logic backs all three client surfaces (CLI `doctor`, the `join`
//! tail, the MCP `doctor` tool, the TUI panel) and is unit-tested without a
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
    Skip,
}

impl GateState {
    /// A plain (non-ANSI) glyph for the gate — shared by the CLI and TUI renderers
    /// so the three surfaces read identically. Colour is layered on separately.
    pub fn glyph(self) -> &'static str {
        match self {
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
    /// Stable machine id: `workspace` | `daemon` | `membership` | `peer` | `synced`.
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
    /// The workspace id this store is bound to, if any (`None` before genesis).
    pub workspace: Option<&'a str>,
    /// The workspace's synced display name (may be empty on a pre-sync joiner).
    pub name: &'a str,
    /// This node's ACL standing: `admin` | `member` | `pending`.
    pub membership: &'a str,
    /// Count of currently-online peers.
    pub online_peers: usize,
    pub projects: usize,
    pub issues: usize,
    /// The workspace the caller *intended* to be in — supplied by the `join` tail
    /// (from the invite ticket) so a directory/store mismatch is caught. `None`
    /// for a standalone `doctor`, which can't know intent.
    pub expected_workspace: Option<&'a str>,
}

/// Project daemon state into the ordered gate list (pure — the validation core).
pub fn diagnose(input: DiagnoseInput<'_>) -> DiagnosisView {
    let bound = input.workspace.unwrap_or("(none)");
    let is_member = matches!(input.membership, "admin" | "member");

    // 1. workspace — the directory trap made legible. Only fails when the caller
    //    told us which workspace it expected (the `join` tail) and we bound a
    //    different one; a standalone doctor has no intent to compare against.
    let workspace = match input.expected_workspace {
        Some(exp) if input.workspace != Some(exp) => DiagnosisGate::new(
            "workspace",
            "space",
            GateState::Fail,
            format!(
                "this directory is space {bound}, but the invite is for {exp} \
                 — you're in a different store; cd to where you ran `lait join`, or target it with `-w`"
            ),
        ),
        _ => DiagnosisGate::new(
            "workspace",
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

    let gates = vec![workspace, daemon, membership, peer, synced];
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
        Some("workspace") => "wrong directory: this store is a different space than the invite. \
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
            workspace: Some("ws_A"),
            name: "lait",
            membership: "member",
            online_peers: 1,
            projects: 2,
            issues: 3,
            expected_workspace: None,
        }
    }

    fn gate<'a>(v: &'a DiagnosisView, id: &str) -> &'a DiagnosisGate {
        v.gates.iter().find(|g| g.id == id).expect("gate present")
    }

    #[test]
    fn all_pass_when_member_online_and_synced() {
        let v = diagnose(input());
        assert_eq!(v.blocked_on, None, "a fully-synced member has no blocker");
        assert!(v.gates.iter().all(|g| g.state == GateState::Pass));
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
    fn workspace_mismatch_is_the_first_blocker() {
        // The directory trap: bound to ws_A but the invite was for ws_B.
        let v = diagnose(DiagnoseInput {
            expected_workspace: Some("ws_B"),
            ..input()
        });
        assert_eq!(gate(&v, "workspace").state, GateState::Fail);
        assert_eq!(
            v.blocked_on.as_deref(),
            Some("workspace"),
            "a wrong-store mismatch must win over everything downstream"
        );
        assert!(gate(&v, "workspace").detail.contains("ws_B"));
        assert!(v.summary.contains("wrong directory"));
    }

    #[test]
    fn matching_expected_workspace_passes() {
        let v = diagnose(DiagnoseInput {
            expected_workspace: Some("ws_A"),
            ..input()
        });
        assert_eq!(gate(&v, "workspace").state, GateState::Pass);
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
        assert_eq!(ids, ["workspace", "daemon", "membership", "peer", "synced"]);
    }
}
