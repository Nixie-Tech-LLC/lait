//! CLI client: builds control requests, auto-spawns the daemon, prints results.

use std::{io::Write, path::Path, process::Stdio, time::Duration};

use anyhow::{anyhow, Context, Result};

use crate::{
    config::socket_path,
    control::{request, Event, EventKind, Request, Response},
    proto::{RoomTicket, Tier},
};

/// Ensure a daemon is running for this home dir, spawning one if needed.
pub async fn ensure_daemon(home: &Path) -> Result<()> {
    let socket = socket_path(home);
    if request(&socket, &Request::Status).await.is_ok() {
        return Ok(());
    }

    let exe = std::env::current_exe().context("locate own executable")?;
    std::process::Command::new(exe)
        .arg("daemon")
        .env("GROUPCHAT_HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn daemon")?;

    // Wait for the daemon to come online (it binds a relay before serving).
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if request(&socket, &Request::Status).await.is_ok() {
            return Ok(());
        }
    }
    Err(anyhow!("daemon did not come online in time"))
}

/// Ensure the daemon is up, then send one request.
pub async fn client(home: &Path, req: Request) -> Result<Response> {
    ensure_daemon(home).await?;
    request(&socket_path(home), &req).await
}

/// Run a request and pretty-print the response for terminal users.
pub async fn run(home: &Path, req: Request) -> Result<()> {
    let resp = client(home, req).await?;
    print_response(resp);
    Ok(())
}

/// `invite` gets special display: print the bare token (for agents to paste into
/// `connect`) AND the `groupchat://` link (for humans/chat apps), and best-effort
/// copy the token to the clipboard so there's nothing to hand-select.
pub async fn run_invite(home: &Path) -> Result<()> {
    let resp = client(home, Request::Invite).await?;
    let token = match resp {
        Response::Text { text } => text.trim().to_string(),
        other => {
            print_response(other);
            return Ok(());
        }
    };
    let link = token
        .parse::<RoomTicket>()
        .map(|t| t.link())
        .unwrap_or_else(|_| format!("groupchat://join/{token}"));
    let copied = copy_to_clipboard(&token);
    println!("{token}");
    println!("{link}");
    if copied {
        println!("(copied to clipboard — paste into `groupchat connect`)");
    }
    Ok(())
}

/// Best-effort copy to the OS clipboard. Tries macOS `pbcopy`, then Wayland
/// `wl-copy`, then X11 `xclip`. Returns whether it succeeded; never errors.
fn copy_to_clipboard(s: &str) -> bool {
    let candidates: [(&str, &[&str]); 3] = [
        ("pbcopy", &[]),
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
    ];
    for (cmd, args) in candidates {
        let Ok(mut child) = std::process::Command::new(cmd)
            .args(args)
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

fn print_response(resp: Response) {
    match resp {
        Response::Ok { message } => {
            if let Some(m) = message {
                println!("{m}");
            } else {
                println!("ok");
            }
        }
        Response::Text { text } => println!("{text}"),
        Response::Status(s) => {
            println!("id:        {}", s.id);
            println!("nick:      {}", s.nick);
            println!("room:      {}", s.room);
            println!("online:    {} peer(s)", s.online_peers);
            println!("contacts:  {}", s.contacts);
            println!("resources: {}", s.resources);
        }
        Response::Events { events, last } => {
            for e in &events {
                print_event(e);
            }
            if events.is_empty() {
                println!("(no new messages)");
            } else {
                println!("--- last seq {last} ---");
            }
        }
        Response::Contacts { contacts } => {
            if contacts.is_empty() {
                println!("(no contacts)");
            }
            for c in contacts {
                println!("{}  {}", c.nick, c.id);
            }
        }
        Response::Who { mut peers } => {
            if peers.is_empty() {
                println!("(no peers seen yet)");
            }
            peers.sort_by_key(|p| (!p.online, p.nick.clone()));
            for p in peers {
                let dot = if p.online { "\u{25CF}" } else { "\u{25CB}" };
                let star = if p.is_contact { " \u{2713}contact" } else { "" };
                println!("{dot} {}  ({}){star}", p.nick, p.id);
            }
        }
        Response::Resources { resources } => {
            if resources.is_empty() {
                println!("(no resources shared)");
            }
            for r in resources {
                println!("{}  from {}\n    {}", r.label, r.from, r.ticket);
            }
        }
        Response::Receipts { messages } => {
            if messages.is_empty() {
                println!("(no tracked messages)");
            }
            for m in messages {
                let flag = if m.overdue { " \u{26A0} overdue" } else { "" };
                println!(
                    "msg {} [{}]{}  \u{201C}{}\u{201D}",
                    m.msg_id,
                    tier_str(&m.tier),
                    flag,
                    m.text
                );
                for r in m.recipients {
                    let mark = |b: bool| if b { "\u{2713}" } else { "\u{2014}" };
                    println!(
                        "    {} {}delivered {}seen {}acked  ({})",
                        r.nick,
                        mark(r.delivered),
                        mark(r.seen),
                        mark(r.acked),
                        r.id
                    );
                }
            }
        }
        Response::Error { message } => {
            eprintln!("error: {message}");
        }
    }
}

/// Short machine-readable name for a tier (also a hook env var value).
fn tier_str(t: &Tier) -> &'static str {
    match t {
        Tier::Ambient => "ambient",
        Tier::Direct => "direct",
        Tier::NeedsAck => "needs_ack",
        Tier::Interrupt => "interrupt",
    }
}

/// A short urgency badge for a tier, shown ahead of the event text.
fn tier_badge(t: &Tier) -> &'static str {
    match t {
        Tier::Ambient => "",
        Tier::Direct => "\u{1F514} ",       // 🔔
        Tier::NeedsAck => "\u{23F0} ",      // ⏰
        Tier::Interrupt => "\u{1F6A8} ",    // 🚨
    }
}

/// Short machine-readable name for an event kind (also used as a hook env var).
fn kind_str(k: &EventKind) -> &'static str {
    match k {
        EventKind::Chat => "chat",
        EventKind::Join => "join",
        EventKind::Call => "call",
        EventKind::Resource => "resource",
        EventKind::Presence => "presence",
        EventKind::Receipt => "receipt",
        EventKind::System => "system",
    }
}

/// Print one event the way `log`/`watch` show it. A tier badge (🔔/⏰/🚨) marks
/// urgency; needs_ack/interrupt chat lines show their seq so you can `ack` them.
fn print_event(e: &Event) {
    let tag = match e.kind {
        EventKind::Chat => "",
        EventKind::Join => "[join] ",
        EventKind::Call => "[call] ",
        EventKind::Resource => "[resource] ",
        EventKind::Presence => "[presence] ",
        EventKind::Receipt => "[receipt] ",
        EventKind::System => "[system] ",
    };
    let badge = tier_badge(&e.tier);
    // Prompt the reader to ack messages that asked for one.
    let ack_hint = if matches!(e.kind, EventKind::Chat)
        && e.tier >= Tier::NeedsAck
        && e.msg_id.is_some()
    {
        format!("  \u{2190} ack {}", e.seq)
    } else {
        String::new()
    };
    println!("{badge}{tag}{}: {}{ack_hint}", e.nick, e.text);
}

/// Run a user hook for an event: the event fields are exported as environment
/// variables and the full event JSON is piped to the command's stdin. Detached
/// so a slow hook never stalls the watch loop.
fn run_hook(cmd: &str, e: &Event) {
    let json = serde_json::to_string(e).unwrap_or_default();
    let child = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("GROUPCHAT_EVENT_SEQ", e.seq.to_string())
        .env("GROUPCHAT_EVENT_KIND", kind_str(&e.kind))
        .env("GROUPCHAT_EVENT_NICK", &e.nick)
        .env("GROUPCHAT_EVENT_ID", &e.id)
        .env("GROUPCHAT_EVENT_TEXT", &e.text)
        .env("GROUPCHAT_EVENT_DIRECT", if e.direct { "true" } else { "false" })
        .env("GROUPCHAT_EVENT_TIER", tier_str(&e.tier))
        .env(
            "GROUPCHAT_EVENT_PREEMPT",
            if e.tier >= Tier::Interrupt { "true" } else { "false" },
        )
        .env(
            "GROUPCHAT_EVENT_MSG_ID",
            e.msg_id.map(|m| m.to_string()).unwrap_or_default(),
        )
        .env("GROUPCHAT_EVENT_TS", e.ts.to_string())
        .stdin(Stdio::piped())
        .spawn();
    match child {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(json.as_bytes());
            }
            // Reap in the background so we don't block or leave a zombie.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(err) => eprintln!("watch: hook failed to start: {err}"),
    }
}

/// Fire a desktop notification for an event (best-effort, platform-native).
fn desktop_notify(e: &Event) {
    let title = format!("groupchat: {}", e.nick);
    if cfg!(target_os = "macos") {
        let script = format!(
            "display notification {:?} with title {:?}",
            e.text, title
        );
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

/// Foreground notification runner: block on `chat_wait`, print each event, and
/// for matching events run a hook command and/or raise a desktop notification.
/// Loops forever (Ctrl-C to stop), reconnecting if the daemon restarts.
#[allow(clippy::too_many_arguments)]
pub async fn watch(
    home: &Path,
    since: Option<u64>,
    direct_only: bool,
    min_tier: Option<Tier>,
    exec: Option<String>,
    on_interrupt: Option<String>,
    notify: bool,
    timeout_ms: u64,
) -> Result<()> {
    ensure_daemon(home).await?;
    let sock = socket_path(home);

    // Default: start from "now" so we don't replay the whole backlog.
    let mut cursor = match since {
        Some(n) => n,
        None => match request(&sock, &Request::Log { since: 0 }).await? {
            Response::Events { last, .. } => last,
            _ => 0,
        },
    };
    eprintln!("watching from seq {cursor} (Ctrl-C to stop)\u{2026}");

    loop {
        let resp = match request(&sock, &Request::Wait { since: cursor, timeout_ms }).await {
            Ok(r) => r,
            Err(e) => {
                // Daemon may have restarted; re-ensure and keep going.
                eprintln!("watch: {e}; reconnecting\u{2026}");
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = ensure_daemon(home).await;
                continue;
            }
        };
        if let Response::Events { events, last } = resp {
            for e in &events {
                print_event(e);
                // The preemption hook fires only for interrupt-tier ("notify
                // anyway") events — independent of the direct/min-tier gate.
                if e.tier >= Tier::Interrupt {
                    if let Some(cmd) = &on_interrupt {
                        run_hook(cmd, e);
                    }
                }
                let passes = !direct_only && min_tier.map(|m| e.tier >= m).unwrap_or(true)
                    || direct_only && e.direct;
                if passes {
                    if let Some(cmd) = &exec {
                        run_hook(cmd, e);
                    }
                    if notify {
                        desktop_notify(e);
                    }
                }
            }
            cursor = last.max(cursor);
        }
    }
}
