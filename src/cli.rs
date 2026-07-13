//! CLI client: builds control requests, auto-spawns the daemon, prints results.
//!
//! All three surfaces (CLI, TUI, MCP) are Layer-B clients of the daemon (UI.md
//! §1); this one renders `Response` snapshots for a human shell, or the versioned
//! `--json` DTO for scripts/agents (UI.md §2.3). Exit codes: `0` ok · `1`
//! usage/error · `2` ref not found / ambiguous · `3` daemon unreachable.

use std::{io::Write, path::Path, process::Stdio, time::Duration};

use anyhow::{anyhow, Context, Result};

use crate::{
    control::{request, Event, EventKind, Request, Response},
    dto::{BoardView, IssueView, Priority, Row},
    proto::RoomTicket,
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

/// Ensure a daemon is running for this home dir, spawning one if needed.
pub async fn ensure_daemon(home: &Path) -> Result<()> {
    if request(home, &Request::Status).await.is_ok() {
        return Ok(());
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

/// Print a response; return the process exit code it implies.
pub fn print_response(resp: &Response, out: Out) -> i32 {
    if out.json {
        let json = serde_json::to_string(resp).unwrap_or_else(|_| "{}".into());
        println!("{json}");
        return match resp {
            Response::Error { message } => exit_code_for_error(message),
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
        Response::Activity { events, .. } => {
            if events.is_empty() {
                println!("(no activity)");
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
                println!("(no projects — create one: `lait projects new <name> --key KEY`)");
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
            println!("workspace: {}", s.workspace.as_deref().unwrap_or("(none)"));
            println!("room:      {}", s.room);
            println!("issues:    {}", s.issues);
            println!("projects:  {}", s.projects);
            println!("online:    {} peer(s)", s.online_peers);
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
                let dot = match p.state.as_str() {
                    "online" => "\u{25CF}",
                    "away" => "\u{25D0}",
                    _ => "\u{25CB}",
                };
                println!("{dot} {}  ({})", p.nick, p.id);
            }
            0
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
            exit_code_for_error(message)
        }
    }
}

fn exit_code_for_error(message: &str) -> i32 {
    let resolution_error = message.contains("no issue matches")
        || message.contains("no project matches")
        || message.contains("no user matches")
        || message.contains("no label matches")
        || message.contains("more than one project");
    if resolution_error {
        2
    } else {
        1
    }
}

fn prio_badge(p: Priority) -> String {
    format!("·{}·", p.badge())
}

fn print_rows(rows: &[Row], _out: Out) {
    if rows.is_empty() {
        println!("(no issues)");
        return;
    }
    for r in rows {
        let alias = r.key_alias.as_deref().unwrap_or(&r.reff);
        let asg = if r.assignee_summary.is_empty() {
            String::new()
        } else {
            format!("  {}", r.assignee_summary)
        };
        let dim = if r.provisional { " (provisional)" } else { "" };
        println!(
            "{:<10} {} {:<12} {}{}{}",
            alias,
            prio_badge(r.priority),
            r.status,
            r.title,
            asg,
            dim
        );
    }
}

fn print_board(b: &BoardView, _out: Out) {
    println!("{} · {}", b.project.key, b.project.name);
    for col in &b.columns {
        println!("\n┌ {} ({}) ", col.state.name, col.rows.len());
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
                prio_badge(r.priority),
                r.title,
                asg
            );
        }
    }
}

fn print_issue(v: &IssueView, _out: Out) {
    let alias = v.key_alias.as_deref().unwrap_or(&v.reff);
    println!("{}  {}", alias, v.title);
    println!("{}", "─".repeat(60));
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
pub async fn run_invite(home: &Path, email: Option<String>, out: Out) -> Result<()> {
    let resp = client(home, Request::Invite).await?;
    let token = match resp {
        Response::Text { text } => text.trim().to_string(),
        other => {
            print_response(&other, out);
            return Ok(());
        }
    };
    let link = token
        .parse::<RoomTicket>()
        .map(|t| t.link())
        .unwrap_or_else(|_| format!("lait://join/{token}"));
    println!("{token}");
    println!("{link}");
    if !out.json {
        match render_qr(&link) {
            Ok(q) => println!("\n{q}"),
            Err(e) => eprintln!("(qr unavailable: {e:#})"),
        }
    }
    if copy_to_clipboard(&token) && !out.json {
        println!("(copied to clipboard — paste into `lait connect`)");
    }
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
fn copy_to_clipboard(s: &str) -> bool {
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

/// Render a scannable QR of the invite link as terminal half-block glyphs.
fn render_qr(data: &str) -> Result<String> {
    use qrcode::{render::unicode, QrCode};
    let code = QrCode::new(data.as_bytes()).context("build QR code")?;
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
    let subject = "Invitation to my lait workspace";
    let body = format!(
        "You're invited to my lait workspace.\n\n\
         1. Install lait\n   \
         macOS/Linux:  curl --proto '=https' --tlsv1.2 -LsSf \
         https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.sh | sh\n   \
         Windows:      powershell -c \"irm \
         https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.ps1 | iex\"\n\n\
         2. Join the workspace\n   lait connect {link}\n\n\
         That announces a join request; I'll approve you and your device gets the \
         workspace key automatically. lait is local-first and end-to-end encrypted.\n"
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

fn run_hook(cmd: &str, e: &Event) {
    let json = serde_json::to_string(e).unwrap_or_default();
    let child = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
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

fn desktop_notify(e: &Event) {
    let title = format!("lait: {}", e.nick);
    if cfg!(target_os = "macos") {
        let script = format!("display notification {:?} with title {:?}", e.text, title);
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .spawn();
    } else {
        let _ = std::process::Command::new("notify-send")
            .arg(&title)
            .arg(&e.text)
            .spawn();
    }
}

/// Foreground presence-notification runner (the `watch` command).
pub async fn watch(
    home: &Path,
    since: Option<u64>,
    exec: Option<String>,
    notify: bool,
    timeout_ms: u64,
) -> Result<()> {
    ensure_daemon(home).await?;
    let mut cursor = match since {
        Some(n) => n,
        None => match request(home, &Request::Log { since: 0 }).await? {
            Response::Events { last, .. } => last,
            _ => 0,
        },
    };
    eprintln!("watching from seq {cursor} (Ctrl-C to stop)\u{2026}");
    loop {
        let resp = match request(
            home,
            &Request::Wait {
                since: cursor,
                timeout_ms,
            },
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("watch: {e}; reconnecting\u{2026}");
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = ensure_daemon(home).await;
                continue;
            }
        };
        if let Response::Events { events, last } = resp {
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
    }
}
