//! CLI client: builds control requests, auto-spawns the daemon, prints results.
//!
//! All three surfaces (CLI, TUI, MCP) are Layer-B clients of the daemon (UI.md
//! §1); this one renders `Response` snapshots for a human shell, or the versioned
//! `--json` DTO for scripts/agents (UI.md §2.3). Exit codes: `0` ok · `1`
//! usage/error · `2` ref not found / ambiguous · `3` daemon unreachable.

use std::{io::Write, path::Path, process::Stdio, time::Duration};

use anyhow::{anyhow, Context, Result};

use crate::{
    control::{request, ErrorKind, Event, EventKind, Request, Response},
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
            if !s.membership.is_empty() {
                let code = if s.membership == "pending" {
                    ansi::YELLOW
                } else {
                    ansi::GREEN
                };
                println!("you:       {}", paint(out.color, code, &s.membership));
            }
            println!("room:      {}", s.room);
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
        .parse::<RoomTicket>()
        .map(|t| t.link())
        .unwrap_or_else(|_| format!("lait://join/{token}"));
    println!("{token}");
    println!("{link}");
    match render_qr(&link) {
        Ok(q) => println!("\n{q}"),
        Err(e) => eprintln!("(qr unavailable: {e:#})"),
    }
    if copy_to_clipboard(&token) {
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
         2. Join the workspace\n   lait join {link}\n\n\
         The link carries a one-time pass, so that admits you automatically and \
         your device gets the workspace key (run `lait status` to see when you're \
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
