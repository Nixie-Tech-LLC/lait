//! Layer B — the local control protocol (SCHEMA §7). Newline-delimited JSON over
//! the cross-platform local IPC channel (a Unix-domain socket on unix, a named
//! pipe on Windows; see [`control_name`]). One request → one response, plus the
//! streaming [`Request::Subscribe`] mode that writes [`Doorbell`] frames until
//! the client disconnects (S§7.5, UI.md §4.1).
//!
//! This is an **imperative façade over a declarative CRDT**: a stable, versioned,
//! hand-maintained projection of Layer A (S§1), never an auto-dump. `Ref`s and
//! `UserRef`s arrive as plain strings and are resolved **daemon-side** (UI.md §3).

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use interprocess::local_socket::{
    tokio::{prelude::*, Stream},
    Name,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::diagnose::DiagnosisView;
use crate::dto::{
    ActivityEvent, BoardView, Candidate, InboxEntry, IssueView, JoinRequestDto, LabelDto,
    MemberDto, ProjectDto, Row, SeedDto,
};

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

/// A board position for `IssueMove` (UI.md §5.1 `--top/--bottom/--before/--after`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum BoardPos {
    Top,
    Bottom,
    Before { reff: String },
    After { reff: String },
}

/// List/board filter (UI.md §2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default)]
    pub mine: bool,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// Include done + tombstoned rows (UI.md §2.2).
    #[serde(default)]
    pub all: bool,
}

/// A request from a client to the daemon (SCHEMA §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        /// Full-buffer description replace (P0, UI.md §5.3 — the client holds
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
    /// Work-state verbs (UI.md §2): each is ONE commit = one activity row,
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
    /// The durable, addressed-to-you inbox (S§8.1 `inbox.json`): remote
    /// assignments/comments/status moves on your work, derived at import time.
    /// `clear` stamps the read watermark after listing.
    Inbox {
        #[serde(default)]
        clear: bool,
    },
    // ---- membership / ACL (P3, S§6) ----
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
    KeyRotate,
    Members,
    /// List pending join requests (announced joiners not yet members, UI.md §8).
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
    /// Streaming doorbells for the TUI (S§7.5). Turns the one-shot handler into a
    /// stream of [`Doorbell`] frames until the client disconnects.
    Subscribe {
        #[serde(default)]
        since: u64,
    },

    // ---- transport / presence (kept from the skeleton; the P1 surface) ----
    Status,
    /// Guided-join verifier (UI onboarding, `docs/GUIDED-JOIN.md`): project live
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
    /// Pin an always-on seed peer (A§10). `arg` is a room ticket (adopt the
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
    /// Presence/system event log (P1 transport surface).
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
}

fn default_true() -> bool {
    true
}

/// A response from the daemon (SCHEMA §7). A snapshot at a version — there is
/// **no CAS token** (S§7.2). Internally tagged by `kind` (not `status`, which
/// would collide with `IssueView.status` when the `Issue` variant is flattened).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Ok {
        message: Option<String>,
    },
    /// A write echoes the resolved canonical handle (UI.md §2.2).
    Ref {
        reff: String,
    },
    Issue(Box<IssueView>),
    List {
        rows: Vec<Row>,
    },
    Board(Box<BoardView>),
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
    /// Pending join requests (announced joiners not yet members, UI.md §8).
    JoinRequests {
        requests: Vec<JoinRequestDto>,
    },
    /// Pinned seeds ("remotes") and their reachability (A§10).
    Seeds {
        seeds: Vec<SeedDto>,
    },
    /// A ref resolved to many candidates — a first-class outcome (UI.md §3.2).
    Candidates {
        candidates: Vec<Candidate>,
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

/// Classifies a [`Response::Error`] so the process exit code (UI.md §2.3) is
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
    /// A ref / registry lookup that resolved to **nothing** (exit `2`, UI.md §3.2).
    pub fn not_found(msg: impl Into<String>) -> Self {
        Response::Error {
            message: msg.into(),
            error_kind: ErrorKind::NotFound,
        }
    }
}

/// The streamed frame — the repeated reply to [`Request::Subscribe`] (S§7.5).
/// A **batched, project-keyed dirty-set**, never state (UI.md §4.2). The client
/// re-reads the authoritative projection for each dirty scope; it never patches
/// from a doorbell.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Doorbell {
    /// Per-daemon-boot nonce; a change ⇒ restart ⇒ treat as `Reset` (UI.md §4.1).
    pub epoch: u64,
    /// Per-session cursor (S§2). Never persisted.
    pub seq: u64,
    /// `true` ⇒ ignore the rest and rebaseline from a fresh snapshot (S§7.5).
    pub reset: bool,
    /// Issue-row plane: which docs (by project) moved. Re-read these rows.
    pub dirty_by_project: HashMap<String, Vec<String>>,
    /// Catalog-structure plane (UI.md §4.2).
    pub dirty_catalog: Vec<CatalogScope>,
    /// New feed rows exist — pull via `Activity{since}` (S§7.5). Never streamed.
    pub activity_advanced: bool,
    /// New presence/join rows exist — pull via `Log{since}` (S§7.5). Never
    /// streamed: like every other plane this is a dirty *flag*, not the events.
    /// The presence plane rings independently of the tracker dirty-set, so a
    /// peer coming online wakes a subscriber even when no doc moved.
    /// `default` so a frame from a pre-plane daemon (stale across `lait update`)
    /// still decodes (S§9 rule 1: fields are add-only, absent ⇒ default).
    #[serde(default)]
    pub presence_advanced: bool,
}

/// A catalog-structure dirty scope (SCHEMA §7, UI.md §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum CatalogScope {
    Projects,
    Labels,
    Workflow,
    Acl,
    Boards { project: String },
}

/// A presence/system log entry kept in the daemon's ring buffer (P1 transport).
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
    /// Three-state presence (UI.md §4.5): `online` | `away` | `offline`.
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
    /// yet — we can't decrypt the board (UI.md §8). Lets `status` tell a joiner
    /// the truth instead of implying the join already succeeded.
    #[serde(default)]
    pub membership: String,
    /// Joiners who have announced a join request but aren't members yet — the
    /// host-side nudge to run `members approve`. Only meaningful for an admin.
    #[serde(default)]
    pub pending_requests: usize,
}

/// Send one request to the daemon and read one response (one-shot path).
pub async fn request(home: &Path, req: &Request) -> Result<Response> {
    let name = control_name(home)?;
    let stream = Stream::connect(name).await.context("connect to daemon")?;
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
    let resp: Response = serde_json::from_str(resp_line.trim()).context("decode response")?;
    Ok(resp)
}

/// A live doorbell subscription — the TUI's read side of a [`Request::Subscribe`]
/// stream (UI.md §4.1). Holds the whole duplex stream (never split, so nothing
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

/// Open a streaming [`Request::Subscribe`] connection (UI.md §4.1).
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
