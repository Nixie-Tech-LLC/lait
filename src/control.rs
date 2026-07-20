//! Layer B — the local control protocol. Newline-delimited JSON over
//! the cross-platform local IPC channel (a Unix-domain socket on unix, a named
//! pipe on Windows; see [`control_name`]). One request → one response, plus the
//! streaming [`Request::Subscribe`] mode that writes [`Doorbell`] frames until
//! the client disconnects.
//!
//! This is an **imperative façade over a declarative CRDT**: a stable, versioned,
//! hand-maintained projection of durable state, never an automatic dump. `Ref`s
//! and `UserRef`s arrive as plain strings and are resolved **daemon-side**.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use interprocess::local_socket::{
    tokio::{prelude::*, Stream},
    Name,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::diagnose::DiagnosisView;
use crate::dto::{
    ActivityEvent, BoardView, Candidate, GraphView, InboxEntry, IssueView, JoinRequestDto,
    LabelDto, MemberDto, MemberLogEntry, ProjectDto, Row, SeedDto,
};

/// The control-plane protocol version this build **speaks** — CLI, web, and MCP
/// ↔ daemon channel, exchanged in the [`Request::Hello`] handshake.
///
/// The third plane to get one. The sync plane has [`crate::sync::PROTOCOL_VERSION`]
/// and the store has `dto::SCHEMA_VERSION`; the control channel had nothing, so a
/// client meeting a daemon of another vintage found out by failing to decode its
/// answer — which `ensure_daemon` read as "no daemon", spawned a doomed second one
/// over the held lock, and finally blamed a timeout. Same rules as the sync plane:
/// bump this for a backward-compatible change, raise
/// [`MIN_SUPPORTED_CONTROL_PROTOCOL`] only when dropping support for an old one.
///
/// Version 1 is the first: a daemon that does not answer `hello` at all predates
/// the handshake (v0.4.8 and earlier) and is reported as such.
pub const CONTROL_PROTOCOL_VERSION: u32 = 1;

/// The oldest control protocol a client still talks to. Raising this retires a
/// version; the gap to [`CONTROL_PROTOCOL_VERSION`] is the mixed-version window.
pub const MIN_SUPPORTED_CONTROL_PROTOCOL: u32 = 1;

/// Whether this build can talk to a daemon advertising control protocol `peer`.
///
/// Pure, so the window policy is unit-testable without a daemon — the same shape
/// as `sync::check_sync_protocol`. Returns a human-facing reason on refusal:
/// which side is behind decides who has to act.
pub fn check_control_protocol(peer: u32) -> Result<()> {
    if peer < MIN_SUPPORTED_CONTROL_PROTOCOL {
        return Err(anyhow!(
            "the daemon speaks control protocol v{peer}, older than the minimum \
             this build supports (v{MIN_SUPPORTED_CONTROL_PROTOCOL}); \
             restart it with `lait shutdown`"
        ));
    }
    if peer > CONTROL_PROTOCOL_VERSION {
        return Err(anyhow!(
            "the daemon speaks control protocol v{peer}, newer than this build's \
             v{CONTROL_PROTOCOL_VERSION}; upgrade lait with `lait update`"
        ));
    }
    Ok(())
}

/// The OS name of the control channel for a home (unix socket / Windows named
/// pipe). Daemon and clients derive it from the same home so they agree.
pub fn control_name(home: &Path) -> Result<Name<'static>> {
    #[cfg(unix)]
    {
        use interprocess::local_socket::GenericFilePath;
        crate::config::socket_path(home)
            .to_fs_name::<GenericFilePath>()
            .context("build control socket name")
    }
    #[cfg(windows)]
    {
        use interprocess::local_socket::GenericNamespaced;
        format!("lait-{}.sock", crate::config::home_hash(home))
            .to_ns_name::<GenericNamespaced>()
            .context("build control pipe name")
    }
}

/// A board position for `IssueMove` (`--top`, `--bottom`, `--before`, or `--after`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum BoardPos {
    Top,
    Bottom,
    Before { reff: String },
    After { reff: String },
}

/// List and board filter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Filter {
    #[serde(default)]
    pub mine: bool,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// Include done and tombstoned rows.
    #[serde(default)]
    pub all: bool,
}

/// A request from a client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    // ---- tracker (Layer-B façade over the issue model) ----
    IssueNew {
        title: String,
        #[serde(default)]
        project: Option<String>,
        /// Environment hint (the CLI's git-branch project key) — distinct from
        /// `project` because "user said X" must error loudly on a miss while
        /// "environment suggests X" must fall through silently (S: the
        /// choose-project chain). MCP always sends `None`.
        #[serde(default)]
        project_hint: Option<String>,
        #[serde(default)]
        assignees: Vec<String>,
        #[serde(default)]
        priority: Option<String>,
        #[serde(default)]
        labels: Vec<String>,
        #[serde(default)]
        body: Option<String>,
    },
    IssueEdit {
        reff: String,
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        status: Option<String>,
        #[serde(default)]
        priority: Option<String>,
        /// Full-buffer description replacement; the client holds
        /// no `LoroText` cursor; the daemon applies it as a text update).
        #[serde(default)]
        description: Option<String>,
    },
    IssueMove {
        reff: String,
        #[serde(default)]
        project: Option<String>,
        #[serde(default)]
        pos: Option<BoardPos>,
    },
    Assign {
        reff: String,
        who: Vec<String>,
        #[serde(default = "default_true")]
        add: bool,
    },
    Label {
        reff: String,
        #[serde(default)]
        add: Vec<String>,
        #[serde(default)]
        remove: Vec<String>,
    },
    Comment {
        reff: String,
        body: String,
    },
    IssueDelete {
        reff: String,
    },
    /// Restore a deleted issue — a signed content-authority op that clears the
    /// tombstone. Restore wins over a concurrent delete.
    IssueRestore {
        reff: String,
    },
    /// Link two issues (`blocks` | `relates` | `duplicates`) — an add-wins edge
    /// in the catalog structure document.
    IssueLink {
        reff: String,
        kind: String,
        target: String,
    },
    IssueUnlink {
        reff: String,
        kind: String,
        target: String,
    },
    /// Set (or clear, with `parent: None`) an issue's parent in the sub-issue
    /// hierarchy — a tree-move CRDT, so concurrent conflicting parents can
    /// never converge to a cycle.
    IssueParent {
        reff: String,
        #[serde(default)]
        parent: Option<String>,
    },
    /// The issue's graph neighborhood: parent, children, links, open blockers.
    IssueGraph {
        reff: String,
    },
    /// Work-state verbs: each is one commit and one activity row,
    /// bundling the fields a single human intent moves. Targets are picked by
    /// workflow *category* (first Active / Done / Backlog state), so they track
    /// whatever the workspace's column set is. They return `Response::Issue`
    /// (a fresh snapshot) — the one deviation from writes-echo-Ref, because the
    /// CLI needs the title to derive the git branch name.
    IssueStart {
        reff: String,
    },
    IssueDone {
        reff: String,
    },
    IssueStop {
        reff: String,
    },
    IssueView {
        reff: String,
    },
    List {
        #[serde(default)]
        project: Option<String>,
        #[serde(default)]
        filter: Filter,
    },
    Board {
        /// Optional since the choose-project chain can supply the view project
        /// (sole project / `project.default` / branch hint).
        #[serde(default)]
        project: Option<String>,
        #[serde(default)]
        project_hint: Option<String>,
    },
    History {
        reff: String,
    },
    ProjectNew {
        name: String,
        key: String,
    },
    ProjectList,
    LabelNew {
        name: String,
        #[serde(default)]
        color: Option<String>,
    },
    LabelList,
    Activity {
        #[serde(default)]
        since: u64,
    },
    /// The durable, addressed-to-you inbox (`inbox.json`): remote
    /// assignments/comments/status moves on your work, derived at import time.
    /// `clear` stamps the read watermark after listing.
    Inbox {
        #[serde(default)]
        clear: bool,
    },
    // ---- membership and authorization ----
    MemberAdd {
        who: String,
        #[serde(default)]
        admin: bool,
        /// Optional local petname to attach to the resolved key (never synced).
        #[serde(default)]
        as_name: Option<String>,
    },
    MemberRemove {
        who: String,
    },
    /// Sponsor an agent keypair. Any human member may sponsor;
    /// the agent is sealed the workspace key but holds no membership or content
    /// authority, and its standing dies with the sponsor.
    AgentAdd {
        /// The agent's ed25519 public key (64-hex).
        key: String,
    },
    KeyRotate,
    /// Revoke an outstanding invite so it can no longer admit anyone (admin-
    /// only). Accepts the invite ticket or its 32-hex nonce.
    InviteRevoke {
        /// The invite ticket, or its raw 32-hex nonce.
        invite: String,
    },
    /// Print a device-enrollment token for adding another device to *this*
    /// actor (lait/actor/1). The new machine consumes it with `device accept`.
    DeviceInvite,
    /// Add a device to our actor from its consent blob (produced by
    /// `device accept`), sealing it the workspace key.
    DeviceAdd {
        /// Hex-encoded consent binding from the joining device.
        consent: String,
    },
    /// Revoke a device from our actor and rotate the key to fence it.
    DeviceRevoke {
        device: String,
    },
    /// List the device keys currently bound to our actor.
    DeviceList,
    /// Break-glass **workspace** recovery (lait/space/1 W5): re-root the workspace
    /// to this device using the offline workspace recovery keys, as threshold
    /// `Recover` events. Distinct from [`Recover`](Self::Recover), which resets a
    /// single actor's devices.
    SpaceRecover,
    /// Elevate the workspace recovery authority from a solo bootstrap key to a
    /// `k`-of-N FROST group key over `cofounders` (device keys) + this device,
    /// via a dealer-free DKG that rides the synced ceremony bulletin board.
    SpaceElevate {
        cofounders: Vec<String>,
        k: u16,
    },
    /// Co-sign a pending break-glass recovery request as a holder of the current
    /// K-of-N group recovery key. Explicit per-request consent: the holder has
    /// checked out-of-band that `session` re-roots to the agreed party.
    SpaceRecoverApprove {
        session: String,
        /// The actor(s) the holder expects this recovery to re-root to — consent
        /// binds to the roots, so an injected request that re-roots elsewhere is
        /// refused before any share is contributed.
        expect: Vec<String>,
    },
    /// Co-sign a pending authority grant as a holder of the current group key,
    /// authorizing a replacement ceremony. Consent binds to the PROPOSAL, not to
    /// the session id: a request for a different proposal is refused.
    SpaceElevateApprove {
        session: String,
        proposal: String,
    },
    /// Export this device's recovery share as a portable, passphrase-protected
    /// package, verify it by reopening, and attest that on the board. An
    /// all-holders arrangement will not install until every custodian has done
    /// this.
    SpaceCustodyExport {
        path: String,
        passphrase: String,
    },
    /// Restore a recovery share from a portable package written by
    /// `SpaceCustodyExport`. Refuses to replace a readable share unless `force`.
    SpaceCustodyImport {
        path: String,
        passphrase: String,
        force: bool,
    },
    /// Recover our actor with the offline recovery key: reset the device set to
    /// this device (identity is restored; content-key access is re-sealed lazily
    /// by an admin/peer).
    Recover,
    Members,
    /// The membership audit log: the signed ACL DAG replayed in causal order
    /// with each op's authorization verdict (cryptographic provenance).
    MemberLog,
    /// List announced joiners that are not yet members.
    MemberRequests,
    /// Approve a pending join request **by id-prefix / key** — sugar over
    /// `MemberAdd` scoped to the pending set. The joiner's self-asserted nick is
    /// deliberately not a resolution input (it is unauthenticated); `as_name`
    /// lets the approver attach a trusted local petname at the same time.
    MemberApprove {
        who: String,
        #[serde(default)]
        as_name: Option<String>,
    },
    /// Set (or clear, with an empty name) a **local petname** for a key. Local to
    /// this node, never broadcast, never part of the signed ACL.
    MemberAlias {
        who: String,
        name: String,
    },
    /// Streaming dirty notifications for live clients. Turns the one-shot handler into a
    /// stream of [`Doorbell`] frames until the client disconnects.
    Subscribe {
        #[serde(default)]
        since: u64,
    },

    // ---- transport / presence ----
    Status,
    /// Guided-join verifier (`docs/UI.md`, joining): project live
    /// node state into an ordered list of onboarding gates so a stalled joiner
    /// gets one legible blocker instead of a blank board. `expected_workspace`
    /// (supplied by the `join` tail from the invite ticket) lets it catch a
    /// directory/store mismatch; `None` for a standalone `doctor`.
    Diagnose {
        #[serde(default)]
        expected_workspace: Option<String>,
    },
    Id,
    /// Mint an invite ticket. By default it carries a signed, single-use
    /// pre-authorization (Pattern A) so the joiner is auto-admitted on `join`.
    Invite {
        /// Mint a grant-less ticket: the joiner lands as a pending request that a
        /// human admin must `members approve` (the classic flow).
        #[serde(default)]
        require_approval: bool,
        /// Let the grant admit a whole team (valid until expiry) instead of one
        /// person (single-use).
        #[serde(default)]
        reusable: bool,
        /// Lifetime in hours before the grant expires (default 168 = 7 days).
        #[serde(default)]
        ttl_hours: Option<u64>,
    },
    Join {
        ticket: String,
    },
    Connect {
        ticket: String,
    },
    /// Pin an always-on seed peer. `arg` is a room ticket (adopt the
    /// workspace + backfill) or a bare endpoint id (pin only). Sticky across
    /// restarts; grants no trust.
    SeedAdd {
        arg: String,
    },
    /// List pinned seeds and their current reachability.
    SeedList,
    /// Unpin a seed by endpoint id (or id-prefix) or nick.
    SeedRemove {
        who: String,
    },
    /// Presence and transport event log.
    Log {
        since: u64,
    },
    Who,
    /// Re-read the layered local settings (`lait config set` sends this
    /// best-effort so a daemon-read key like `user.nick` applies live instead
    /// of silently waiting for a restart). Transport-plane like `Stop` — not
    /// part of the MCP tool surface.
    ConfigReload,
    Stop,
    /// Version handshake (see [`CONTROL_PROTOCOL_VERSION`]). The first thing a
    /// client sends, and the only request whose reply must stay decodable
    /// forever — it is what tells two mismatched builds *why* they can't talk
    /// instead of leaving them to fail at decoding something else.
    Hello {
        /// The client's version. Unused today (the client decides), but it is
        /// what a future daemon would need to refuse an ancient client, and it
        /// cannot be added later without another flag day.
        #[serde(default)]
        protocol_version: u32,
    },
}

fn default_true() -> bool {
    true
}

/// A response from the daemon. A snapshot at a version — there is
/// **no CAS token**. Internally tagged by `kind` (not `status`, which
/// would collide with `IssueView.status` when the `Issue` variant is flattened).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    /// Reply to [`Request::Hello`] — the daemon's control protocol version.
    ///
    /// Read by the client **before** any typed decoding (as raw JSON), so a
    /// version mismatch reports itself instead of surfacing as a decode error on
    /// some unrelated field. That means this variant's shape is load-bearing:
    /// `kind` and `protocol_version` must keep their names for as long as any
    /// supported version exists.
    Hello {
        protocol_version: u32,
    },
    Ok {
        message: Option<String>,
    },
    /// A write echoes the resolved canonical handle.
    Ref {
        reff: String,
    },
    Issue(Box<IssueView>),
    List {
        rows: Vec<Row>,
    },
    Board(Box<BoardView>),
    /// The issue-graph neighborhood (reply to [`Request::IssueGraph`]).
    Graph(Box<GraphView>),
    Activity {
        events: Vec<ActivityEvent>,
        last: u64,
    },
    /// The inbox snapshot: entries newest-first; `unread` counts entries past
    /// the read watermark.
    Inbox {
        entries: Vec<InboxEntry>,
        unread: u64,
    },
    Projects {
        projects: Vec<ProjectDto>,
    },
    Labels {
        labels: Vec<LabelDto>,
    },
    Members {
        members: Vec<MemberDto>,
    },
    /// The membership audit log (reply to [`Request::MemberLog`]).
    MemberLog {
        entries: Vec<MemberLogEntry>,
    },
    /// Pending join requests: announced joiners that are not yet members.
    JoinRequests {
        requests: Vec<JoinRequestDto>,
    },
    /// Pinned seeds ("remotes") and their reachability.
    Seeds {
        seeds: Vec<SeedDto>,
    },
    /// A ref resolved to many candidates, represented as a first-class outcome,
    /// or, when `near_miss_for` is set, matched **nothing** and these are the
    /// closest handles to what was typed.
    Candidates {
        candidates: Vec<Candidate>,
        /// The input that matched nothing, when these are near misses rather than
        /// an ambiguous prefix. Additive and `#[serde(default)]` on purpose: a
        /// client that predates it decodes the variant unchanged and just calls
        /// them candidates, so this stays safe in both directions within the
        /// epoch (cf. `sync::PROTOCOL_VERSION` on the sync plane).
        #[serde(default)]
        near_miss_for: Option<String>,
    },

    // ---- transport / presence ----
    // Boxed like `Issue`/`Board`: `StatusInfo` is the largest variant, and keeping
    // it inline makes `Response` (used as the `Err` type of the resolve helpers)
    // trip clippy's `result_large_err`.
    Status(Box<StatusInfo>),
    /// The guided-join verifier's ordered gate list (reply to [`Request::Diagnose`]).
    Diagnosis(Box<DiagnosisView>),
    Text {
        text: String,
    },
    Events {
        events: Vec<Event>,
        last: u64,
    },
    Who {
        peers: Vec<PresenceEntry>,
    },
    Error {
        message: String,
        // Named `error_kind`, not `kind`: the enum's internal tag is `kind`
        // (`#[serde(tag = "kind")]`), so a variant field of that name collides.
        #[serde(default)]
        error_kind: ErrorKind,
    },
}

/// Classifies a [`Response::Error`] so the process exit code is
/// derived from a **typed kind**, never by string-matching the human message.
/// `NotFound` (a ref / registry entry didn't resolve) maps to exit `2` alongside
/// the ambiguous [`Response::Candidates`] outcome; everything else is a plain
/// error → exit `1`. Kept minimal on purpose: "many candidates" already has its
/// own response variant, so the only extra rung the message layer needs is
/// "resolved to nothing."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    #[default]
    Error,
    NotFound,
}

impl Response {
    /// A generic failure — usage, validation, internal (exit `1`).
    pub fn err(msg: impl Into<String>) -> Self {
        Response::Error {
            message: msg.into(),
            error_kind: ErrorKind::Error,
        }
    }
    /// A ref or registry lookup that resolved to **nothing** (exit `2`).
    pub fn not_found(msg: impl Into<String>) -> Self {
        Response::Error {
            message: msg.into(),
            error_kind: ErrorKind::NotFound,
        }
    }
}

/// The streamed frame: the repeated reply to [`Request::Subscribe`].
/// A **batched, project-keyed dirty-set**, never state. The client
/// re-reads the authoritative projection for each dirty scope; it never patches
/// from a doorbell.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Doorbell {
    /// Per-daemon-boot nonce; a change means restart and requires a `Reset`.
    pub epoch: u64,
    /// Per-session cursor. Never persisted.
    pub seq: u64,
    /// `true` means ignore the rest and rebaseline from a fresh snapshot.
    pub reset: bool,
    /// Issue-row plane: which docs (by project) moved. Re-read these rows.
    pub dirty_by_project: HashMap<String, Vec<String>>,
    /// Catalog-structure changes.
    pub dirty_catalog: Vec<CatalogScope>,
    /// New feed rows exist; pull via `Activity{since}`. Rows are never streamed.
    pub activity_advanced: bool,
    /// New presence or join rows exist; pull via `Log{since}`. Rows are never
    /// streamed: like every other plane this is a dirty *flag*, not the events.
    /// The presence plane rings independently of the tracker dirty-set, so a
    /// peer coming online wakes a subscriber even when no doc moved.
    /// `default` so a frame from a pre-plane daemon (stale across `lait update`)
    /// still decodes because fields are add-only and absence means default.
    #[serde(default)]
    pub presence_advanced: bool,
}

/// Identifies which catalog structure became dirty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum CatalogScope {
    Projects,
    Labels,
    Workflow,
    Acl,
    Boards { project: String },
}

/// A presence or transport log entry kept in the daemon's ring buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub kind: EventKind,
    pub id: String,
    pub nick: String,
    pub text: String,
    pub ts: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Join,
    Presence,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceEntry {
    pub id: String,
    pub nick: String,
    /// Three-state presence: `online`, `away`, or `offline`.
    pub state: String,
    pub online: bool,
    pub last_seen_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub id: String,
    pub nick: String,
    /// The workspace display name (synced catalog value; empty on a joiner
    /// whose catalog hasn't arrived yet).
    pub name: String,
    pub online_peers: usize,
    pub workspace: Option<String>,
    pub issues: usize,
    pub projects: usize,
    /// This node's standing in the workspace ACL: `admin` | `member` | `pending`.
    /// `pending` means we joined from an invite but an admin hasn't approved us
    /// yet, so we cannot decrypt the board. Lets `status` tell a joiner
    /// the truth instead of implying the join already succeeded.
    #[serde(default)]
    pub membership: String,
    /// Joiners who have announced a join request but aren't members yet — the
    /// host-side nudge to run `members approve`. Only meaningful for an admin.
    #[serde(default)]
    pub pending_requests: usize,
    /// Recovery shares this device holds that exist but cannot be used.
    ///
    /// Structured, not preformatted: the CLI and web layers render it
    /// differently, and a rendered string would force one of them to parse
    /// prose. Persistent rather than recovery-only — an operator must be able to
    /// learn their founder share is unusable *before* the day they need it,
    /// which is exactly the day it is too late to fix.
    #[serde(default)]
    pub degraded_recovery: Vec<crate::tracker::DegradedRecoveryHolder>,
    /// This device's recovery readiness: the standing authority's shape and our
    /// own custody standing. Reports what THIS node knows; it deliberately makes
    /// no claim about whether other holders still have their shares.
    #[serde(default)]
    pub recovery: Option<crate::tracker::RecoveryStatus>,
}

/// What probing a home's control channel found. These three must be told apart
/// before deciding to spawn: treating them alike is how "a daemon is right there
/// but speaks a different wire shape" gets misreported as "no daemon", which then
/// spawns a doomed second daemon over a held lock and waits out the full timeout.
#[derive(Debug)]
pub enum Probe {
    /// Answered, and we understood the answer.
    Healthy,
    /// Nothing is listening: no daemon for this home. Safe to spawn.
    Absent,
    /// Something is listening, but we can't talk to it — a daemon from a
    /// different lait (it holds the lock, so spawning over it cannot work).
    Foreign {
        /// The handshake's diagnosis, including the way out.
        why: String,
        /// Whether stopping it and taking over is the right repair.
        ///
        /// **False when the other side is ahead of us.** Replacing a newer daemon
        /// with this build is a downgrade, and if it has already written the store
        /// at a newer `dto::SCHEMA_VERSION` then `store::check_schema_version`
        /// refuses to open it — so "helpfully" killing it stops the node dead.
        /// Also false for anything we can't identify: `daemon_pid` is only a claim
        /// from a file, and signalling a pid on a hunch is how you kill a stranger.
        replaceable: bool,
    },
}

/// Probe a home's control channel without spawning anything.
///
/// Two deliberate choices make this survive the very skew it exists to detect:
///
/// * **Absent vs present is decided at the transport level.** Whether `connect`
///   succeeds is a fact no protocol change can alter.
/// * **The version is read as raw JSON, before any typed decode.** Probing with a
///   typed request would mean a mismatched daemon fails on whatever field
///   happened to change (it was `StatusInfo.name`) and reports *that* instead of
///   the version. Only `kind` and `protocol_version` need to hold still.
pub async fn probe(home: &Path) -> Probe {
    // A probe that can hang defeats its own purpose: it exists to *diagnose* a
    // daemon that isn't answering, so it must not become the thing that isn't
    // answering. Neither side of the exchange is guaranteed to fail fast —
    // connecting to a Windows named pipe with no free instance parks rather than
    // erroring (see the teardown note in `node::run_daemon`) — and a local IPC
    // round trip that takes seconds is already broken by any measure.
    match tokio::time::timeout(PROBE_TIMEOUT, probe_inner(home)).await {
        Ok(p) => p,
        Err(_) => Probe::Foreign {
            why: format!(
                "it is not answering (no reply within {}s) — it may be wedged or \
                 shutting down; stop it and re-run",
                PROBE_TIMEOUT.as_secs()
            ),
            // A daemon we never heard from is not one we can identify, and an
            // unidentified pid is not a safe signal target.
            replaceable: false,
        },
    }
}

/// How long a local control round trip may take before the daemon counts as
/// unresponsive. Generous: the healthy path is sub-millisecond.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn probe_inner(home: &Path) -> Probe {
    let Ok(name) = control_name(home) else {
        return Probe::Absent;
    };
    // Connect failing is the real "no daemon" signal (no socket / nothing
    // accepting). Anything past this point means someone answered the door.
    let Ok(stream) = Stream::connect(name).await else {
        return Probe::Absent;
    };
    let line = match exchange_raw(
        stream,
        &Request::Hello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            return Probe::Foreign {
                why: format!("{e:#}"),
                replaceable: false,
            }
        }
    };
    // `Value`, not `Response`: this must parse regardless of what the rest of the
    // schema looks like on the other side.
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
        return Probe::Foreign {
            why: "it answered with something that isn't JSON — this may not be a \
                  lait daemon at all"
                .into(),
            replaceable: false,
        };
    };
    match v.get("kind").and_then(|k| k.as_str()) {
        Some("hello") => match v.get("protocol_version").and_then(|p| p.as_u64()) {
            Some(peer) => match check_control_protocol(peer as u32) {
                Ok(()) => Probe::Healthy,
                Err(e) => Probe::Foreign {
                    why: format!("{e:#}"),
                    // Only take over from a daemon that is *behind* us.
                    replaceable: (peer as u32) < CONTROL_PROTOCOL_VERSION,
                },
            },
            // Said hello without a version: not a shape we ever shipped.
            None => Probe::Foreign {
                why: "it answered `hello` without a protocol version".into(),
                replaceable: false,
            },
        },
        // A daemon that doesn't know `hello` rejects it as an unknown variant —
        // which is itself the answer: it predates the handshake (v0.4.8 or
        // earlier), so there is no version to negotiate. Definitively older,
        // therefore safe to replace.
        _ => Probe::Foreign {
            why: "it predates the control-protocol handshake (lait v0.4.8 or \
                  earlier), so this build cannot talk to it"
                .into(),
            replaceable: true,
        },
    }
}

/// Send one request to the daemon and read one response (one-shot path).
pub async fn request(home: &Path, req: &Request) -> Result<Response> {
    let name = control_name(home)?;
    let stream = Stream::connect(name).await.context("connect to daemon")?;
    exchange(stream, req).await
}

/// Write one request and read one response on an already-open stream.
async fn exchange(stream: Stream, req: &Request) -> Result<Response> {
    let line = exchange_raw(stream, req).await?;
    serde_json::from_str(line.trim()).context("decode response")
}

/// The same round trip, stopping at the raw response line.
///
/// Split from [`exchange`] for [`probe`]: typed decoding is exactly what a
/// version-mismatched daemon breaks, so the handshake has to look at the bytes
/// before serde gets an opinion about them.
async fn exchange_raw(stream: Stream, req: &Request) -> Result<String> {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut line = serde_json::to_string(req).context("encode request")?;
    line.push('\n');
    write_half
        .write_all(line.as_bytes())
        .await
        .context("write request")?;
    write_half.flush().await.ok();

    let mut reader = BufReader::new(read_half);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .await
        .context("read response")?;
    Ok(resp_line)
}

/// A live dirty-notification subscription — the client side of [`Request::Subscribe`]
/// stream. Holds the whole duplex stream (never split, so nothing
/// leaks); the subscribe verb is write-once, then read-many.
pub struct Subscription {
    reader: BufReader<Stream>,
}

impl Subscription {
    /// Read the next [`Doorbell`] frame. Returns `None` at EOF (daemon stopped).
    pub async fn next(&mut self) -> Result<Option<Doorbell>> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .await
            .context("read doorbell")?;
        if n == 0 {
            return Ok(None);
        }
        let db: Doorbell = serde_json::from_str(line.trim()).context("decode doorbell")?;
        Ok(Some(db))
    }
}

/// Open a streaming [`Request::Subscribe`] connection.
pub async fn subscribe(home: &Path, since: u64) -> Result<Subscription> {
    let name = control_name(home)?;
    let mut stream = Stream::connect(name).await.context("connect to daemon")?;
    let mut line =
        serde_json::to_string(&Request::Subscribe { since }).context("encode subscribe")?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .await
        .context("write subscribe")?;
    stream.flush().await.ok();
    Ok(Subscription {
        reader: BufReader::new(stream),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_protocol_window_accepts_supported_and_refuses_outside() {
        // Everything in [MIN_SUPPORTED_CONTROL_PROTOCOL, CONTROL_PROTOCOL_VERSION]
        // is accepted — the mixed-version window.
        assert!(check_control_protocol(CONTROL_PROTOCOL_VERSION).is_ok());
        assert!(check_control_protocol(MIN_SUPPORTED_CONTROL_PROTOCOL).is_ok());

        // A daemon newer than we understand: we must upgrade, so say so.
        let newer = check_control_protocol(CONTROL_PROTOCOL_VERSION + 1).unwrap_err();
        assert!(
            newer.to_string().contains("lait update"),
            "an out-of-window daemon must name the way out; got: {newer}",
        );

        // A daemon older than the window: it must be restarted onto this build.
        let older = check_control_protocol(MIN_SUPPORTED_CONTROL_PROTOCOL - 1).unwrap_err();
        assert!(
            older.to_string().contains("lait shutdown"),
            "an out-of-window daemon must name the way out; got: {older}",
        );
    }

    /// The handshake's own shape is the one thing that can never be allowed to
    /// drift: `probe` reads `kind` and `protocol_version` out of raw JSON, so
    /// renaming either would silently turn every version mismatch back into the
    /// unreadable failure this exists to replace.
    #[test]
    fn the_hello_reply_keeps_the_field_names_probe_reads_raw() {
        let json = serde_json::to_value(Response::Hello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
        })
        .unwrap();
        assert_eq!(json["kind"], "hello");
        assert_eq!(json["protocol_version"], CONTROL_PROTOCOL_VERSION);
    }

    /// A pre-handshake daemon (v0.4.8 and earlier) rejects `hello` as an unknown
    /// variant. That rejection is load-bearing: it is how `probe` recognises a
    /// daemon too old to have a version at all.
    #[test]
    fn hello_serializes_as_the_cmd_a_pre_handshake_daemon_will_reject() {
        let json = serde_json::to_value(Request::Hello {
            protocol_version: CONTROL_PROTOCOL_VERSION,
        })
        .unwrap();
        assert_eq!(json["cmd"], "hello");
    }

    /// Skew is **not** symmetric, and the repair must not pretend it is.
    ///
    /// Taking over from an older daemon is a fix; taking over from a newer one is
    /// a downgrade — and if it has written the store at a newer `SCHEMA_VERSION`,
    /// `store::check_schema_version` then refuses to open it and the node is
    /// stuck. So `replaceable` must be false for everything except a daemon we can
    /// positively identify as behind us.
    #[test]
    fn only_a_daemon_behind_us_is_ever_replaceable() {
        let foreign = |v: serde_json::Value| -> bool {
            // Mirrors probe's decision on a parsed hello reply.
            let peer = v["protocol_version"].as_u64().unwrap() as u32;
            assert!(
                check_control_protocol(peer).is_err(),
                "must be out of window"
            );
            peer < CONTROL_PROTOCOL_VERSION
        };
        assert!(
            !foreign(serde_json::json!({"protocol_version": CONTROL_PROTOCOL_VERSION + 1})),
            "a daemon ahead of this build must never be offered up for replacement",
        );
        // The mirror case only exists once the window has moved past v1; assert it
        // the moment it can be expressed, so raising MIN doesn't silently skip it.
        if MIN_SUPPORTED_CONTROL_PROTOCOL > 1 {
            assert!(foreign(
                serde_json::json!({"protocol_version": MIN_SUPPORTED_CONTROL_PROTOCOL - 1})
            ));
        }
    }
}
