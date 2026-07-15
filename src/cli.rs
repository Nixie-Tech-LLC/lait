//! CLI client: builds control requests, auto-spawns the daemon, prints results.
//!
//! All three surfaces (CLI, TUI, MCP) are Layer-B clients of the daemon (UI.md
//! §1); this one renders `Response` snapshots for a human shell, or the versioned
//! `--json` DTO for scripts/agents (UI.md §2.3). Exit codes: `0` ok · `1`
//! usage/error · `2` ref not found / ambiguous · `3` daemon unreachable.

use std::{io::Write, path::Path, process::Stdio, time::Duration};

use anyhow::{anyhow, Context, Result};

use crate::{
    control::{self, request, ErrorKind, Event, EventKind, Request, Response},
    diagnose::{DiagnosisView, GateState},
    dto::{BoardView, IssueView, Priority, Row},
    proto::WorkspaceTicket,
    workspaces::{self, StorePresence, WorkspaceEntry},
};

/// Output mode threaded from the global `--json` / `--no-color` flags.
#[derive(Debug, Clone, Copy)]
pub struct Out {
    pub json: bool,
    pub color: bool,
}

impl Default for Out {
    fn default() -> Self {
        Out {
            json: false,
            color: true,
        }
    }
}

/// Minimal ANSI styling. Every helper is gated on `Out.color`, which already
/// folds in `--no-color`, `$NO_COLOR`, `--json`, and TTY detection (computed once
/// in `app::run`), so a renderer just passes `out.color` and never re-checks.
mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const DIM: &str = "\x1b[2m";
    pub const BOLD: &str = "\x1b[1m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const CYAN: &str = "\x1b[36m";
}

/// Wrap `s` in an ANSI code when `on`, else return it unstyled.
fn paint(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("{code}{s}{}", ansi::RESET)
    } else {
        s.to_string()
    }
}

/// Ensure a daemon is running for this home dir, spawning one if needed.
pub async fn ensure_daemon(home: &Path) -> Result<()> {
    if request(home, &Request::Status).await.is_ok() {
        return Ok(());
    }
    // A daemon can only open an initialized store — fail fast with guidance
    // instead of spawning a doomed process and timing out 20s later.
    if !crate::store::initialized_at(home) {
        return Err(anyhow!(
            "no space at {} — found one with `lait init`, or join one with `lait join <link>`",
            home.display()
        ));
    }
    let exe = std::env::current_exe().context("locate own executable")?;
    // Pin the resolved store for the spawned daemon so it binds the exact same
    // store regardless of its cwd (DUR-5). LAIT_HOME, when set (self-
    // contained / --home / resume), is inherited from our env and takes
    // precedence, so this is a no-op in that mode.
    std::process::Command::new(exe)
        .arg("daemon")
        .env("LAIT_STORE", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn daemon")?;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if request(home, &Request::Status).await.is_ok() {
            return Ok(());
        }
    }
    Err(anyhow!("daemon did not come online in time"))
}

/// Ensure the daemon is up, then send one request.
pub async fn client(home: &Path, req: Request) -> Result<Response> {
    ensure_daemon(home).await?;
    request(home, &req).await
}

/// Run a request, print the response, and exit with the right code (UI.md §2.3).
pub async fn run(home: &Path, req: Request, out: Out) -> Result<()> {
    match client(home, req).await {
        Ok(resp) => {
            let code = print_response(&resp, out);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Err(e) => {
            // daemon unreachable / spawn failure
            eprintln!("error: {e:#}");
            std::process::exit(3);
        }
    }
}

/// Emit a bare text value honouring the `--json` contract (UI.md §2.3): the
/// `Response::Text` DTO under `--json`, else the raw string. For client-side
/// commands (`id`, `invite`) that don't round-trip a daemon `Response` but must
/// still emit a parseable DTO under `--json` instead of leaking plain text.
pub fn emit_text(text: &str, out: Out) {
    if out.json {
        let resp = Response::Text {
            text: text.to_string(),
        };
        println!(
            "{}",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!("{text}");
    }
}

/// Emit an acknowledgement honouring `--json`: the `Response::Ok` DTO under
/// `--json`, else the human message (`init`, `install-mcp`, `resume`).
pub fn emit_ok(message: &str, out: Out) {
    if out.json {
        let resp = Response::Ok {
            message: Some(message.to_string()),
        };
        println!(
            "{}",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!("{message}");
    }
}

/// Render the guided-join verifier's gate list (human output). Each gate is a
/// coloured glyph + label + detail, followed by the one-line summary keyed off the
/// blocking gate. Under `--json` the caller emits the DTO instead (handled in
/// `print_response`), so this is the human path only.
fn print_diagnosis(v: &DiagnosisView, out: Out) {
    for g in &v.gates {
        let code = match g.state {
            GateState::Pass => ansi::GREEN,
            GateState::Wait => ansi::YELLOW,
            GateState::Fail => ansi::RED,
            GateState::Skip => ansi::DIM,
        };
        let glyph = paint(out.color, code, g.state.glyph());
        println!("{} {:<11} {}", glyph, g.label, g.detail);
    }
    println!();
    let code = if v.blocked_on.is_some() {
        ansi::YELLOW
    } else {
        ansi::GREEN
    };
    println!("{}", paint(out.color, code, &v.summary));
}

/// `join` display: send the join, echo the daemon's ack, then run the guided-join
/// verifier as a tail — passing the ticket's workspace as `expected_workspace`, so
/// a directory/store mismatch (the joiner ran `join` in the wrong folder) is caught
/// and named immediately instead of surfacing later as a blank board. Under
/// `--json` we emit only the join DTO (no verifier chrome), mirroring `run_invite`.
pub async fn run_join(home: &Path, ticket: String, out: Out) -> Result<()> {
    // Parse client-side to recover the intended workspace before the ticket is
    // moved into the request. A malformed ticket simply yields no expectation; the
    // daemon returns the real parse error.
    let parsed = ticket.parse::<WorkspaceTicket>().ok();
    // A pass-carrying ticket (Pattern A) admits automatically within seconds, so
    // a pending membership is worth polling out; a pass-less ticket waits on a
    // human admin and would only stall the readout.
    let has_pass = parsed.as_ref().is_some_and(|t| t.invite.is_some());
    let expected = parsed.map(|t| t.workspace);
    let resp = client(home, Request::Join { ticket }).await?;
    match &resp {
        Response::Ok { message } => {
            if out.json {
                emit_ok(message.as_deref().unwrap_or("ok"), out);
                return Ok(());
            }
            println!("{}", message.as_deref().unwrap_or("ok"));
        }
        // A join error (bad ticket, unreachable host) is terminal — print and stop.
        other => {
            let code = print_response(other, out);
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        }
    }
    // Human tail: the gate readout. Best-effort — a verifier hiccup must not make a
    // successful join look failed, so we degrade to a hint rather than erroring.
    //
    // Polled, not one-shot: right after `join` returns, admission (Pattern A's
    // auto-seal) and the gossip handshake are still in flight, so a t=0 snapshot
    // reads "waiting on a peer" moments before everything passes — the verifier
    // itself becoming the unreliable reporter. We re-diagnose until the gates
    // settle (all pass, or a Fail-state blocker that time won't clear) or a
    // deadline, and report the settled truth.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut last: Option<Response> = None;
    loop {
        match client(
            home,
            Request::Diagnose {
                expected_workspace: expected.clone(),
            },
        )
        .await
        {
            Ok(diag) => {
                let settled = match &diag {
                    Response::Diagnosis(v) => match v.blocked_on.as_deref() {
                        None => true,
                        // `workspace` is the one Fail-state blocker (wrong
                        // directory/store) — waiting can't clear it.
                        Some("workspace") => true,
                        // Pending membership clears itself only under a pass
                        // (Pattern A auto-seal); pass-less waits on a human.
                        Some("membership") => !has_pass,
                        // peer / synced — convergence in flight; keep polling.
                        Some(_) => false,
                    },
                    // Not a diagnosis (daemon error) — nothing to wait out.
                    _ => true,
                };
                let expired = tokio::time::Instant::now() >= deadline;
                if settled || expired {
                    print_diagnosis_or(&diag, out);
                    break;
                }
                last = Some(diag);
            }
            Err(e) => {
                // Degrade to the freshest readout we have, or a hint.
                match &last {
                    Some(diag) => print_diagnosis_or(diag, out),
                    None => eprintln!("(joined; run `lait doctor` for status — {e:#})"),
                }
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

/// One-line issue summary for the work-state verbs: `MP-3  fix login  in_progress`.
/// Prefers the friendly `KEY-n` handle; the collision-free short id is `--json`'s.
fn workstate_line(v: &crate::dto::IssueView) -> String {
    let handle = v.key_alias.as_deref().unwrap_or(&v.reff);
    format!("{handle}  {}  {}", v.title, v.status)
}

/// A git branch name for an issue: lowercased `KEY-n` + a hyphenated title slug
/// (≤40 chars of slug). Predictable by design — `done`/`show` infer the issue
/// back out of it, and so do agents (UI.md §2.2).
fn branch_name_for(v: &crate::dto::IssueView) -> String {
    let handle = v
        .key_alias
        .clone()
        .unwrap_or_else(|| v.reff.clone())
        .to_ascii_lowercase();
    let mut slug = String::new();
    for c in v.title.to_ascii_lowercase().chars() {
        if slug.len() >= 40 {
            break;
        }
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        handle
    } else {
        format!("{handle}-{slug}")
    }
}

/// Create + checkout the issue's branch, best-effort: outside a git work-tree
/// this silently does nothing; inside one, an existing branch is switched to and
/// any failure is a warning — a branch hiccup must never fail the `start`.
fn checkout_issue_branch(v: &crate::dto::IssueView, out: Out) {
    let in_repo = std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !in_repo {
        return;
    }
    let name = branch_name_for(v);
    // `switch -c` for a fresh branch; if it already exists, plain `switch`.
    let created = std::process::Command::new("git")
        .args(["switch", "-c", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let ok = created
        || std::process::Command::new("git")
            .args(["switch", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    if !out.json {
        if ok {
            println!(
                "{}",
                paint(
                    out.color,
                    ansi::DIM,
                    &format!(
                        "{} branch '{name}'",
                        if created {
                            "switched to new"
                        } else {
                            "switched to"
                        }
                    )
                )
            );
        } else {
            eprintln!("(could not create/switch branch '{name}' — continue manually)");
        }
    }
}

/// `lait start`: claim + activate + branch. The daemon does the atomic
/// state move; the branch is client-side sugar on top (skippable, best-effort).
pub async fn run_start(home: &Path, reff: String, no_branch: bool, out: Out) -> Result<()> {
    let resp = client(home, Request::IssueStart { reff }).await?;
    match &resp {
        Response::Issue(v) => {
            if out.json {
                print_response(&resp, out);
            } else {
                println!("{}  · you", workstate_line(v));
            }
            if !no_branch {
                checkout_issue_branch(v, out);
            }
            Ok(())
        }
        other => {
            let code = print_response(other, out);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
    }
}

/// `lait done` / `lait stop`: the branchless work-state verbs.
pub async fn run_workstate(home: &Path, req: Request, out: Out) -> Result<()> {
    let resp = client(home, req).await?;
    match &resp {
        Response::Issue(v) => {
            if out.json {
                print_response(&resp, out);
            } else {
                println!("{}", workstate_line(v));
            }
            Ok(())
        }
        other => {
            let code = print_response(other, out);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
    }
}

/// `lait new --start`: file the issue, then claim it (two honest commits).
pub async fn run_new_start(home: &Path, new_req: Request, out: Out) -> Result<()> {
    let resp = client(home, new_req).await?;
    match &resp {
        Response::Ref { reff } => {
            if !out.json {
                println!("{reff}");
            }
            run_start(home, reff.clone(), false, out).await
        }
        other => {
            let code = print_response(other, out);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
    }
}

/// Bare `lait` — the FOCUS view: unread inbox summary + your open issues.
/// Must answer "what's addressed to me / what am I on" faster than a browser
/// tab could open, and its empty states name the next command.
pub async fn run_focus(home: &Path, out: Out) -> Result<()> {
    let inbox = client(home, Request::Inbox { clear: false }).await?;
    let mine = request(
        home,
        &Request::List {
            project: None,
            filter: crate::control::Filter {
                mine: true,
                status: None,
                label: None,
                all: false,
            },
        },
    )
    .await?;
    if out.json {
        // Machine focus = the two DTOs on two lines (each independently stable).
        print_response(&inbox, out);
        print_response(&mine, out);
        return Ok(());
    }
    if let Response::Inbox { entries, unread } = &inbox {
        if *unread > 0 {
            let heads: Vec<String> = entries
                .iter()
                .take(3)
                .map(|e| format!("{} {}", inbox_line_verb(e), e.reff))
                .collect();
            println!(
                "{} {}",
                paint(out.color, ansi::CYAN, &format!("Inbox ({unread}):")),
                heads.join(" · ")
            );
        }
    }
    match &mine {
        Response::List { rows } if rows.is_empty() => {
            println!("nothing assigned to you — grab something: `lait ls`, or file one: `lait new \"...\"`");
        }
        Response::List { rows } => {
            for r in rows {
                println!("  {}  {:<10}  {}", r.reff, r.status, r.title);
            }
        }
        other => {
            print_response(other, out);
        }
    }
    Ok(())
}

/// The inbox verb phrase for a summary line ("assigned you", "commented on"…).
fn inbox_line_verb(e: &crate::dto::InboxEntry) -> String {
    let who = e.actor_nick.clone().unwrap_or_else(|| "someone".into());
    match e.kind.as_str() {
        "assigned" => format!("{who} assigned you"),
        "comment" => format!("{who} commented on"),
        _ => format!("{who} moved"),
    }
}

/// Render a `Diagnosis` response, or fall back gracefully if the daemon returned
/// some other variant (e.g. an error) to the tail request.
fn print_diagnosis_or(resp: &Response, out: Out) {
    match resp {
        Response::Diagnosis(v) => print_diagnosis(v, out),
        other => {
            print_response(other, out);
        }
    }
}

/// Live status of one registry entry: `missing` (store gone from disk), `up`
/// (a daemon answers on its control channel), or `idle` (store present, no
/// daemon). The probe is a short-deadline `Status` round-trip — never a spawn.
async fn workspace_status(e: &WorkspaceEntry) -> &'static str {
    if workspaces::presence(e) == StorePresence::Missing {
        return "missing";
    }
    let up = tokio::time::timeout(
        Duration::from_millis(300),
        request(Path::new(&e.path), &Request::Status),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    if up {
        "up"
    } else {
        "idle"
    }
}

/// `lait workspaces`: every workspace on this machine (founded and joined),
/// with live status. Honours `--json`.
pub async fn print_workspaces(out: Out) {
    let entries = workspaces::list();
    let mut statuses = Vec::with_capacity(entries.len());
    for e in &entries {
        statuses.push(workspace_status(e).await);
    }
    if out.json {
        let rows: Vec<serde_json::Value> = entries
            .iter()
            .zip(&statuses)
            .map(|(e, s)| {
                let mut v = serde_json::to_value(e).unwrap_or_default();
                if let Some(o) = v.as_object_mut() {
                    o.insert("status".into(), serde_json::json!(s));
                }
                v
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({ "spaces": rows }))
                .unwrap_or_else(|_| "{}".into())
        );
        return;
    }
    if entries.is_empty() {
        println!("(no spaces yet — `lait init` to found one, or `lait join <link>`)");
        return;
    }
    for (e, status) in entries.iter().zip(&statuses) {
        let short: String = e.workspace.chars().take(12).collect();
        let code = match *status {
            "up" => ansi::GREEN,
            "idle" => ansi::DIM,
            _ => ansi::RED,
        };
        let name = if e.name.is_empty() {
            "(unnamed)"
        } else {
            &e.name
        };
        let projects = if e.projects.is_empty() {
            String::new()
        } else {
            let keys: Vec<&str> = e.projects.iter().map(|p| p.key.as_str()).collect();
            format!("  [{}]", keys.join(", "))
        };
        let nick = if e.host_nick.is_empty() {
            String::new()
        } else {
            format!("  (from {})", e.host_nick)
        };
        println!(
            "{name}  {short}  {}  {}{projects}{nick}",
            e.origin,
            paint(out.color, code, status),
        );
        println!("  {}", paint(out.color, ansi::DIM, &e.path));
    }
}

/// The universal "no workspace here" error: any store-needing command run in a
/// directory with no discoverable `.lait/` gets this instead of a silently
/// minted decoy store. Points at the creation verbs and every known workspace.
pub fn err_no_store_here(out: Out) {
    eprintln!("no lait space in this directory (nothing is created implicitly).");
    let known = workspaces::list();
    if !known.is_empty() {
        eprintln!();
        eprintln!("spaces on this machine:");
        for e in &known {
            let name = if e.name.is_empty() {
                "(unnamed)"
            } else {
                &e.name
            };
            eprintln!(
                "  {} {name}  \u{2192}  {}",
                paint(out.color, ansi::DIM, "\u{2022}"),
                e.path
            );
        }
        eprintln!();
        eprintln!(
            "cd into one, target one from here with `-w <name>`, or `lait spaces` for details."
        );
    } else {
        eprintln!();
        eprintln!("found a space here with `lait init`, or join one with `lait join <link>`.");
    }
}

/// Print a response; return the process exit code it implies.
pub fn print_response(resp: &Response, out: Out) -> i32 {
    if out.json {
        let json = serde_json::to_string(resp).unwrap_or_else(|_| "{}".into());
        println!("{json}");
        return match resp {
            Response::Error { error_kind, .. } => exit_code_for_kind(*error_kind),
            Response::Candidates { .. } => 2,
            _ => 0,
        };
    }
    match resp {
        Response::Ok { message } => {
            println!("{}", message.as_deref().unwrap_or("ok"));
            0
        }
        Response::Ref { reff } => {
            println!("{reff}");
            0
        }
        Response::Issue(v) => {
            print_issue(v, out);
            0
        }
        Response::List { rows } => {
            print_rows(rows, out);
            0
        }
        Response::Board(b) => {
            print_board(b, out);
            0
        }
        Response::Inbox { entries, unread } => {
            if entries.is_empty() {
                println!("inbox zero — nothing addressed to you. the backlog is `lait ls`.");
                return 0;
            }
            // Newest-first + a ts watermark ⇒ exactly the first `unread` are unread.
            for (i, e) in entries.iter().enumerate() {
                let mark = if (i as u64) < *unread { "•" } else { " " };
                let detail = if e.detail.is_empty() {
                    String::new()
                } else {
                    format!("  — {}", e.detail)
                };
                println!(
                    "{} {}  {}  {}{}",
                    paint(out.color, ansi::CYAN, mark),
                    e.reff,
                    inbox_line_verb(e),
                    e.title,
                    detail
                );
            }
            println!(
                "{}",
                paint(
                    out.color,
                    ansi::DIM,
                    &format!("({unread} unread — `lait inbox --clear` to mark read)")
                )
            );
            0
        }
        Response::Activity { events, .. } => {
            if events.is_empty() {
                println!("(no activity yet — it fills as the space moves: `lait new \"...\"`)");
            }
            for e in events {
                let changes = if e.changes.is_empty() {
                    String::new()
                } else {
                    let cs: Vec<String> = e
                        .changes
                        .iter()
                        .map(|c| {
                            format!(
                                "{} {}→{}",
                                c.field,
                                c.from.as_deref().unwrap_or("∅"),
                                c.to.as_deref().unwrap_or("∅")
                            )
                        })
                        .collect();
                    format!("  {}", cs.join(", "))
                };
                let warn = if e.collision { " ⚠" } else { "" };
                println!("{} {} {}{}{}", e.reff, e.actor_nick, e.kind, changes, warn);
            }
            0
        }
        Response::Projects { projects } => {
            if projects.is_empty() {
                println!("(no projects — create one: `lait projects add KEY`)");
                // A just-joined peer sees this too, but should wait for sync, not
                // create — point them at the verifier so an empty board is legible.
                println!(
                    "{}",
                    paint(
                        out.color,
                        ansi::DIM,
                        "  just joined? run `lait doctor` to check sync status"
                    )
                );
            }
            for p in projects {
                println!("{:<6} {}  ({})", p.key, p.name, p.id);
            }
            0
        }
        Response::Labels { labels } => {
            if labels.is_empty() {
                println!("(no labels)");
            }
            for l in labels {
                println!("{:<16} {}  ({})", l.name, l.color, l.id);
            }
            0
        }
        Response::Members { members } => {
            if members.is_empty() {
                println!("(no members)");
            }
            for m in members {
                let you = if m.me { "  (you)" } else { "" };
                let name = if m.alias.is_empty() {
                    String::new()
                } else {
                    format!("  {}", m.alias)
                };
                println!("{:<7} {}{}{}", m.role, m.key.short(), name, you);
            }
            0
        }
        Response::JoinRequests { requests } => {
            if requests.is_empty() {
                println!("(no pending join requests)");
            } else {
                // The key is authenticated; the nick is a self-asserted claim.
                // Approve BY KEY after confirming the short id out-of-band.
                eprintln!("approve by key/prefix — nick is an unverified claim:");
            }
            for r in requests {
                let short: String = r.key.chars().take(12).collect();
                let claim = if r.nick.is_empty() {
                    String::new()
                } else {
                    format!("  (claims \"{}\")", r.nick)
                };
                println!("{}{}", short, claim);
            }
            0
        }
        Response::Seeds { seeds } => {
            if seeds.is_empty() {
                println!("(no pinned remotes — add one: `lait remote add <ticket>`)");
            }
            for s in seeds {
                let nick = if s.nick.is_empty() { "remote" } else { &s.nick };
                let short: String = s.id.chars().take(12).collect();
                println!("{}  {:<12}  {}", short, nick, s.state);
            }
            0
        }
        Response::Candidates { candidates } => {
            eprintln!("ambiguous ref — {} candidates:", candidates.len());
            for c in candidates {
                let alias = c
                    .key_alias
                    .as_deref()
                    .map(|a| format!(" [{a}]"))
                    .unwrap_or_default();
                eprintln!("  {}{}  {}", c.reff, alias, c.title);
            }
            2
        }
        Response::Status(s) => {
            println!("id:        {}", s.id);
            println!("nick:      {}", s.nick);
            let ws_line = match (s.name.is_empty(), s.workspace.as_deref()) {
                (false, Some(ws)) => format!("{} ({ws})", s.name),
                (true, Some(ws)) => ws.to_string(),
                (false, None) => s.name.clone(),
                (true, None) => "(none)".to_string(),
            };
            println!("space:     {ws_line}");
            if !s.membership.is_empty() {
                let code = if s.membership == "pending" {
                    ansi::YELLOW
                } else {
                    ansi::GREEN
                };
                println!("you:       {}", paint(out.color, code, &s.membership));
            }
            println!("issues:    {}", s.issues);
            println!("projects:  {}", s.projects);
            println!("online:    {} peer(s)", s.online_peers);
            // Directional nudges so neither side of a join stalls silently.
            if s.membership == "pending" {
                println!();
                println!(
                    "{}",
                    paint(
                        out.color,
                        ansi::CYAN,
                        "⌛ you've requested to join — waiting for an admin to approve you."
                    )
                );
                println!("   the board stays encrypted until then; it syncs automatically once you're in.");
            } else if s.pending_requests > 0 {
                let n = s.pending_requests;
                let plural = if n == 1 { "" } else { "s" };
                println!();
                println!(
                    "{}",
                    paint(
                        out.color,
                        ansi::YELLOW,
                        &format!(
                            "⚠ {n} pending join request{plural} — someone is waiting to be let in."
                        )
                    )
                );
                println!("   review: `lait members requests`   approve: `lait members approve <id> --as <name>`");
            }
            0
        }
        Response::Diagnosis(v) => {
            print_diagnosis(v, out);
            0
        }
        Response::Text { text } => {
            println!("{text}");
            0
        }
        Response::Events { events, .. } => {
            if events.is_empty() {
                println!("(no new events)");
            }
            for e in events {
                print_event(e);
            }
            0
        }
        Response::Who { peers } => {
            let mut peers = peers.clone();
            if peers.is_empty() {
                println!("(no peers seen yet)");
            }
            peers.sort_by_key(|p| (!p.online, p.nick.clone()));
            for p in peers {
                let (glyph, code) = match p.state.as_str() {
                    "online" => ("\u{25CF}", ansi::GREEN),
                    "away" => ("\u{25D0}", ansi::YELLOW),
                    _ => ("\u{25CB}", ansi::DIM),
                };
                println!("{} {}  ({})", paint(out.color, code, glyph), p.nick, p.id);
            }
            0
        }
        Response::Error {
            message,
            error_kind,
        } => {
            eprintln!("error: {message}");
            exit_code_for_kind(*error_kind)
        }
    }
}

/// Exit code from the typed error kind (UI.md §2.3), not from the message text.
fn exit_code_for_kind(kind: ErrorKind) -> i32 {
    match kind {
        ErrorKind::NotFound => 2,
        ErrorKind::Error => 1,
    }
}

fn prio_badge(p: Priority, color: bool) -> String {
    let badge = format!("·{}·", p.badge());
    let code = match p {
        Priority::Urgent => ansi::RED,
        Priority::High => ansi::YELLOW,
        Priority::Medium => ansi::CYAN,
        Priority::Low => ansi::DIM,
        Priority::None => ansi::DIM,
    };
    paint(color, code, &badge)
}

fn print_rows(rows: &[Row], out: Out) {
    if rows.is_empty() {
        println!(
            "(no issues here — file one: `lait new \"...\"`, or `lait ls --all` to include done)"
        );
        return;
    }
    for r in rows {
        let alias = r.key_alias.as_deref().unwrap_or(&r.reff);
        let asg = if r.assignee_summary.is_empty() {
            String::new()
        } else {
            format!("  {}", r.assignee_summary)
        };
        let dim = if r.provisional {
            paint(out.color, ansi::DIM, " (provisional)")
        } else {
            String::new()
        };
        println!(
            "{} {} {:<12} {}{}{}",
            paint(out.color, ansi::BOLD, &format!("{alias:<10}")),
            prio_badge(r.priority, out.color),
            r.status,
            r.title,
            asg,
            dim
        );
    }
}

fn print_board(b: &BoardView, out: Out) {
    println!(
        "{} · {}",
        paint(out.color, ansi::BOLD, &b.project.key),
        b.project.name
    );
    for col in &b.columns {
        let header = format!("┌ {} ({}) ", col.state.name, col.rows.len());
        println!("\n{}", paint(out.color, ansi::CYAN, &header));
        for r in &col.rows {
            let alias = r.key_alias.as_deref().unwrap_or(&r.reff);
            let asg = if r.assignee_summary.is_empty() {
                String::new()
            } else {
                format!("  {}", r.assignee_summary)
            };
            println!(
                "│ {:<10} {} {}{}",
                alias,
                prio_badge(r.priority, out.color),
                r.title,
                asg
            );
        }
    }
}

fn print_issue(v: &IssueView, out: Out) {
    let alias = v.key_alias.as_deref().unwrap_or(&v.reff);
    println!(
        "{}  {}",
        paint(out.color, ansi::BOLD, alias),
        paint(out.color, ansi::BOLD, &v.title)
    );
    println!("{}", paint(out.color, ansi::DIM, &"─".repeat(60)));
    println!("id:       {}", v.reff);
    println!("project:  {}", v.project_key.as_deref().unwrap_or("?"));
    println!("status:   {}", v.status);
    println!("priority: {}", v.priority.as_str());
    if !v.assignees.is_empty() {
        let names: Vec<String> = v.assignees.iter().map(|u| u.short()).collect();
        println!("assignees: {}", names.join(", "));
    }
    if !v.label_names.is_empty() {
        println!("labels:   {}", v.label_names.join(", "));
    }
    if v.provisional {
        println!("(provisional — issue body not yet synced)");
    }
    if !v.description.is_empty() {
        println!("\n{}", v.description);
    }
    if !v.comments.is_empty() {
        println!("\n## Comments ({})", v.comments.len());
        for c in &v.comments {
            println!("{} · {}  {}", c.author.short(), c.ts, c.body);
        }
    }
}

/// `invite` display: bare token + link + a scannable terminal QR of the link,
/// best-effort clipboard, and the optional `--email <addr>` (open the OS mail
/// client with a prefilled invite). The QR always renders in human output; it is
/// suppressed only under `--json` so scripts get clean, parseable output.
pub async fn run_invite(
    home: &Path,
    email: Option<String>,
    require_approval: bool,
    reusable: bool,
    ttl_hours: Option<u64>,
    out: Out,
) -> Result<()> {
    let resp = client(
        home,
        Request::Invite {
            require_approval,
            reusable,
            ttl_hours,
        },
    )
    .await?;
    let token = match resp {
        Response::Text { text } => text.trim().to_string(),
        other => {
            print_response(&other, out);
            return Ok(());
        }
    };
    // Under --json, emit the ticket as the versioned DTO and stop — no bare
    // lines, no QR/clipboard/mail chrome (the link is derivable from the ticket).
    if out.json {
        emit_text(&token, out);
        return Ok(());
    }
    let link = token
        .parse::<WorkspaceTicket>()
        .map(|t| t.link())
        .unwrap_or_else(|_| format!("lait://join/{token}"));
    println!("{token}");
    println!("{link}");
    let copied = copy_to_clipboard(&token);
    // The QR is a scan-on-your-phone convenience; an invite ticket is long, so the
    // matrix can be taller/wider than the terminal. Render it only when it fits —
    // otherwise it explodes the scrollback for no gain (the link is right above and
    // on the clipboard). Suppress with $LAIT_NO_QR for a clean, QR-free invite.
    if std::env::var_os("LAIT_NO_QR").is_none() {
        match render_qr(&link) {
            Ok(q) => {
                let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
                let qw = q.lines().map(|l| l.chars().count()).max().unwrap_or(0);
                let qh = q.lines().count();
                if qw <= cols as usize && qh + 3 <= rows as usize {
                    println!("\n{q}");
                } else {
                    println!("(QR omitted — too large for this terminal; use the link above)");
                }
            }
            Err(e) => eprintln!("(qr unavailable: {e:#})"),
        }
    }
    if copied {
        println!("(copied to clipboard)");
    }
    // Tell the host what this ticket actually does, so the mental model matches
    // the flow (Pattern A: default tickets self-approve).
    let hint = if require_approval {
        "your teammate runs `lait join <link>`, then you `lait members approve` them"
    } else if reusable {
        "anyone who runs `lait join <link>` is admitted automatically until it expires"
    } else {
        "your teammate runs `lait join <link>` and is admitted automatically — no approve step"
    };
    println!("→ {hint}");
    if let Some(addr) = email {
        match open_mail_invite(&addr, &link) {
            Ok(()) => {
                if !out.json {
                    println!("(opening your mail client to {addr}…)");
                }
            }
            Err(e) => eprintln!("(could not open mail client: {e:#})"),
        }
    }
    Ok(())
}

/// Copy `s` to the system clipboard, best-effort, using the platform's native
/// tool: `clip` (Windows), `pbcopy` (macOS), or `wl-copy`/`xclip` (Linux).
/// `pub(crate)` so the interactive members picker can copy a fresh invite link.
pub(crate) fn copy_to_clipboard(s: &str) -> bool {
    #[cfg(target_os = "windows")]
    let candidates: &[(&str, &[&str])] = &[
        ("clip", &[]),
        (
            "powershell",
            &["-NoProfile", "-Command", "$input | Set-Clipboard"],
        ),
    ];
    #[cfg(target_os = "macos")]
    let candidates: &[(&str, &[&str])] = &[("pbcopy", &[])];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates: &[(&str, &[&str])] =
        &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"])];

    for (cmd, args) in candidates {
        let Ok(mut child) = std::process::Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(s.as_bytes());
        }
        if child.wait().map(|st| st.success()).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Render a scannable QR of the invite link as terminal half-block glyphs. Uses
/// the lowest error-correction level (`L`) so a long invite ticket yields the
/// smallest module count — the QR still scans, but takes far fewer lines than the
/// default level. `pub(crate)`: the TUI invite panel renders the same QR.
pub(crate) fn render_qr(data: &str) -> Result<String> {
    use qrcode::{render::unicode, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .context("build QR code")?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

/// Open the OS default mail client with a prefilled invite (mailto). lait sends
/// nothing itself — it just hands the URL to the platform handler.
fn open_mail_invite(addr: &str, link: &str) -> Result<()> {
    let subject = "Invitation to my lait space";
    let body = format!(
        "You're invited to my lait space.\n\n\
         1. Install lait\n   \
         macOS/Linux:  curl --proto '=https' --tlsv1.2 -LsSf \
         https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.sh | sh\n   \
         Windows:      powershell -c \"irm \
         https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.ps1 | iex\"\n\n\
         2. Join the space\n   lait join {link}\n\n\
         The link carries a one-time pass, so that admits you automatically and \
         your device gets the space key (run `lait status` to see when you're \
         in). lait is local-first and end-to-end encrypted.\n"
    );
    let mailto = format!(
        "mailto:{}?subject={}&body={}",
        addr,
        percent_encode(subject),
        percent_encode(&body)
    );
    open_url(&mailto)
}

/// Minimal RFC-3986 percent-encoding for mailto query components (unreserved set
/// passes through; everything else is `%XX`). Avoids a url-crate dependency.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Hand a URL to the OS default handler. Uses `rundll32 …FileProtocolHandler` on
/// Windows (robust with `&` in mailto query strings, unlike `cmd start`).
fn open_url(url: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("launch OS url handler")?;
    Ok(())
}

fn kind_str(k: &EventKind) -> &'static str {
    match k {
        EventKind::Join => "join",
        EventKind::Presence => "presence",
        EventKind::System => "system",
    }
}

fn print_event(e: &Event) {
    match e.kind {
        // Surface the joiner's short key so an admin can approve them straight from
        // the log (`lait members approve <that-prefix>`), not just `--json`.
        EventKind::Join => {
            let short: String = e.id.chars().take(8).collect();
            println!("[join] {} ({}): {}", e.nick, short, e.text);
        }
        EventKind::Presence => println!("[presence] {}: {}", e.nick, e.text),
        EventKind::System => println!("[system] {}: {}", e.nick, e.text),
    }
}

/// Build the per-OS shell invocation for a `watch --exec` hook. `sh -c` doesn't
/// exist on stock Windows, so a hook there silently failed to start; use the
/// native `cmd /C` instead (mirrors how `copy_to_clipboard`/`open_url` split).
fn hook_command(cmd: &str) -> std::process::Command {
    #[cfg(windows)]
    {
        let mut c = std::process::Command::new("cmd");
        c.arg("/C").arg(cmd);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    }
}

fn run_hook(cmd: &str, e: &Event) {
    let json = serde_json::to_string(e).unwrap_or_default();
    let mut command = hook_command(cmd);
    let child = command
        .env("LAIT_EVENT_SEQ", e.seq.to_string())
        .env("LAIT_EVENT_KIND", kind_str(&e.kind))
        .env("LAIT_EVENT_NICK", &e.nick)
        .env("LAIT_EVENT_ID", &e.id)
        .env("LAIT_EVENT_TEXT", &e.text)
        .env("LAIT_EVENT_TS", e.ts.to_string())
        .stdin(Stdio::piped())
        .spawn();
    match child {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(json.as_bytes());
            }
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(err) => eprintln!("watch: hook failed to start: {err}"),
    }
}

/// Wrap `s` as a single-quoted PowerShell string literal (doubling embedded
/// quotes) so an event nick/text can't break out of the notify command.
#[cfg(target_os = "windows")]
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn desktop_notify(e: &Event) {
    let title = format!("lait: {}", e.nick);
    #[cfg(target_os = "macos")]
    {
        let script = format!("display notification {:?} with title {:?}", e.text, title);
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        // Best-effort tray balloon via PowerShell NotifyIcon — no external module
        // (BurntToast etc.) required, works on stock Windows 10/11.
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; \
             $n = New-Object System.Windows.Forms.NotifyIcon; \
             $n.Icon = [System.Drawing.SystemIcons]::Information; \
             $n.Visible = $true; \
             $n.ShowBalloonTip(5000, {}, {}, 'Info'); \
             Start-Sleep -Milliseconds 6000; $n.Dispose()",
            ps_single_quote(&title),
            ps_single_quote(&e.text),
        );
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("notify-send")
            .arg(&title)
            .arg(&e.text)
            .spawn();
    }
}

/// Foreground presence-notification runner (the `watch` command).
///
/// Parks on a streaming [`Request::Subscribe`] and treats the doorbell purely as
/// a **wake signal**: a frame carries a dirty *flag*, never the events, so each
/// `presence_advanced` ring is followed by a `Log{since}` re-read for the
/// authoritative rows (UI.md §4.2).
///
/// Two cursors are in play and they are **not** interchangeable: `cursor` is an
/// `EventLog` seq (what `Log{since}` filters on), while the doorbell carries its
/// own per-session `seq`. We never compare them. The doorbell's `epoch` is the
/// one field that matters here — a change means the daemon restarted, which
/// resets the `EventLog` seq to 0 (S§2), voiding our cursor. Rebaselining to 0
/// on an epoch change is what keeps `watch` from going deaf across a restart:
/// the old `Wait` poll loop held its stale high-water and silently matched
/// nothing forever (S§7.5).
pub async fn watch(
    home: &Path,
    since: Option<u64>,
    exec: Option<String>,
    notify: bool,
) -> Result<()> {
    ensure_daemon(home).await?;
    // Default to the current high-water: `watch` follows from now, not from the
    // start of the daemon's history.
    let mut cursor = match since {
        Some(n) => n,
        None => match request(home, &Request::Log { since: 0 }).await? {
            Response::Events { last, .. } => last,
            _ => 0,
        },
    };
    eprintln!("watching from seq {cursor} (Ctrl-C to stop)\u{2026}");

    let mut epoch: Option<u64> = None;
    loop {
        let mut sub = match control::subscribe(home, 0).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("watch: {e}; reconnecting\u{2026}");
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = ensure_daemon(home).await;
                continue;
            }
        };
        loop {
            let frame = match sub.next().await {
                Ok(Some(f)) => f,
                // EOF or a broken stream: the daemon stopped or restarted. Drop
                // to the outer loop, which respawns it and re-subscribes.
                Ok(None) => break,
                Err(e) => {
                    eprintln!("watch: {e}; reconnecting\u{2026}");
                    break;
                }
            };
            // A new epoch ⇒ a new daemon ⇒ the EventLog seq restarted at 0, so
            // anything we remember is from a log that no longer exists.
            if epoch.is_some_and(|prev| prev != frame.epoch) {
                eprintln!("watch: daemon restarted; rebaselining\u{2026}");
                cursor = 0;
            }
            epoch = Some(frame.epoch);
            // `reset` covers first-frame + doorbell ring-overrun. Our EventLog
            // cursor survives both (only an epoch change voids it), so a reset
            // is just another reason to re-read.
            if !(frame.presence_advanced || frame.reset) {
                continue;
            }
            match request(home, &Request::Log { since: cursor }).await {
                Ok(Response::Events { events, last }) => {
                    for e in &events {
                        print_event(e);
                        if let Some(cmd) = &exec {
                            run_hook(cmd, e);
                        }
                        if notify {
                            desktop_notify(e);
                        }
                    }
                    cursor = last.max(cursor);
                }
                Ok(_) => {}
                Err(e) => eprintln!("watch: {e}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = ensure_daemon(home).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::Priority;

    #[test]
    fn paint_is_gated_on_color() {
        // Color off → the string passes through untouched (pipes/`--no-color`/
        // `$NO_COLOR`/non-tty stay clean); color on → wrapped in the code + reset.
        assert_eq!(paint(false, ansi::RED, "hi"), "hi");
        let on = paint(true, ansi::RED, "hi");
        assert!(on.starts_with(ansi::RED) && on.ends_with(ansi::RESET) && on.contains("hi"));
    }

    #[test]
    fn exit_code_is_derived_from_typed_kind_not_prose() {
        // A resolution miss → exit 2, regardless of the (rewordable) message.
        assert_eq!(exit_code_for_kind(ErrorKind::NotFound), 2);
        assert_eq!(exit_code_for_kind(ErrorKind::Error), 1);
        // The constructors carry the kind, and it survives a DTO round-trip so a
        // --json consumer / MCP agent sees the same classification.
        let nf = Response::not_found("no issue matches 'ENG-9x'");
        let json = serde_json::to_string(&nf).unwrap();
        assert!(json.contains("\"error_kind\":\"not_found\""));
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::Error { error_kind, .. } => assert_eq!(error_kind, ErrorKind::NotFound),
            other => panic!("round-trip changed variant: {other:?}"),
        }
        // A legacy error object with no error_kind field defaults to Error (exit 1).
        let legacy: Response =
            serde_json::from_str(r#"{"kind":"error","message":"boom"}"#).unwrap();
        assert!(matches!(
            legacy,
            Response::Error {
                error_kind: ErrorKind::Error,
                ..
            }
        ));
    }

    #[test]
    fn prio_badge_colorless_is_plain() {
        assert_eq!(prio_badge(Priority::Urgent, false), "·U·");
        // Colored urgent badge carries an ANSI escape but the same visible text.
        let c = prio_badge(Priority::Urgent, true);
        assert!(c.contains("·U·") && c.contains('\u{1b}'));
    }
}
