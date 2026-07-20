//! Interactive `lait members` selector: an **inline** picker, not a
//! full-screen TUI. Run bare in a terminal, `lait members` renders a small,
//! arrow-key list *in place* below the prompt (ratatui's inline viewport — no
//! alternate screen, scrollback preserved): pending join requests on top
//! (approvable), ACL members below. It bundles the everyday membership chores so
//! you never have to retype a key:
//!
//!   * **enter** — detail view (a member's ACL standing, or a request's full key)
//!   * **y / n** — approve / dismiss a highlighted request (admin)
//!   * **r** — rename: set a local petname (`MemberAlias`; empty clears)
//!   * **d** — remove a member (admin; rotates the space key — confirmed)
//!   * **i** — mint a fresh invite link and copy it to the clipboard (admin)
//!   * **q / esc** — quit
//!
//! Approving is key-first: you confirm the authenticated key out-of-band, never
//! the self-asserted nickname. Administrator-only actions are hidden unless this
//! node is an admin.
//!
//! Like every other surface, this is a Layer-B client over the daemon control
//! socket, not an embedded node: it snapshots the roster with `Members` +
//! `MemberRequests` and mutates via `MemberApprove` / `MemberAlias` /
//! `MemberRemove` / `Invite`, then re-reads. Rendering is a ratatui
//! `Viewport::Inline` terminal (diffing, scrolling, width-clipping handled for
//! us); key input is an async crossterm `EventStream` so daemon requests can be
//! awaited inline in the loop. Non-interactive callers (`--json`, pipes,
//! redirects) never reach here: `app.rs` keeps the plain `Request::Members` dump.

use std::collections::HashSet;
use std::io::Stdout;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use crossterm::event::{Event as CEvent, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use n0_future::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::Paragraph,
    Terminal, TerminalOptions, Viewport,
};

use crate::cli::ensure_daemon;
use crate::control::{request, Request, Response};
use crate::dto::{JoinRequestDto, MemberDto};
use crate::list_picker::{row_line, window, Cell};
use crate::proto::WorkspaceTicket;

/// One selectable row: a pending request (approvable) or an existing member.
#[derive(Clone)]
enum Item {
    Request(JoinRequestDto),
    Member(MemberDto),
}

/// Which view the inline picker is showing.
#[derive(Clone)]
enum Mode {
    /// The roster: requests then members.
    List,
    /// Detail of the highlighted item.
    Detail,
    /// Approving the highlighted request: an optional local petname to attach as
    /// we seal them in (mirrors `members approve --as <name>`).
    Approve { buffer: String },
    /// Setting a local petname on the highlighted key (`MemberAlias`). Empty
    /// clears it. Local-only, never synced.
    Rename { buffer: String },
    /// Confirming removal of the highlighted member (rotates the space key).
    ConfirmRemove,
}

struct App {
    home: PathBuf,
    requests: Vec<JoinRequestDto>,
    members: Vec<MemberDto>,
    /// Flattened, dismissal-filtered selectable rows (requests first).
    items: Vec<Item>,
    /// Request keys hidden from this session's view (`n`). The request itself
    /// lives in the daemon's event ring until it ages out — this is view-only.
    dismissed: HashSet<String>,
    sel: usize,
    mode: Mode,
    /// A transient one-line result (approve outcome, dismissal note).
    status: Option<String>,
}

impl App {
    fn new(home: PathBuf) -> Self {
        App {
            home,
            requests: Vec::new(),
            members: Vec::new(),
            items: Vec::new(),
            dismissed: HashSet::new(),
            sel: 0,
            mode: Mode::List,
            status: None,
        }
    }

    /// Re-read the roster from the daemon. Members are authoritative; a
    /// `MemberRequests` failure (e.g. a non-admin, or a transient) degrades to an
    /// empty request list so a plain member still gets a working picker.
    async fn reload(&mut self) -> Result<()> {
        self.members = match request(&self.home, &Request::Members).await? {
            Response::Members { members } => members,
            Response::Error { message, .. } => return Err(anyhow!(message)),
            other => return Err(anyhow!("unexpected response to members: {other:?}")),
        };
        self.requests = match request(&self.home, &Request::MemberRequests).await {
            Ok(Response::JoinRequests { requests }) => requests,
            _ => Vec::new(),
        };
        self.rebuild();
        Ok(())
    }

    /// Rebuild `items` from the current roster minus dismissed requests, clamping
    /// the selection so it never dangles past the end.
    fn rebuild(&mut self) {
        let mut items = Vec::new();
        for r in &self.requests {
            if !self.dismissed.contains(&r.key) {
                items.push(Item::Request(r.clone()));
            }
        }
        for m in &self.members {
            items.push(Item::Member(m.clone()));
        }
        self.items = items;
        if self.sel >= self.items.len() {
            self.sel = self.items.len().saturating_sub(1);
        }
    }

    /// Count of leading request rows (the rest of `items` are members).
    fn n_requests(&self) -> usize {
        self.items
            .iter()
            .filter(|i| matches!(i, Item::Request(_)))
            .count()
    }

    /// Whether this node is an admin — gates the approve/remove/invite actions so
    /// a plain member isn't offered chores the ACL will reject.
    fn is_admin(&self) -> bool {
        self.members.iter().any(|m| m.me && m.role == "admin")
    }

    fn selected_is_request(&self) -> bool {
        matches!(self.items.get(self.sel), Some(Item::Request(_)))
    }

    fn selected_is_member(&self) -> bool {
        matches!(self.items.get(self.sel), Some(Item::Member(_)))
    }

    /// The authenticated key of the highlighted item (a member's ACL key or a
    /// request's announced key) — the ref every mutation resolves against.
    fn selected_key(&self) -> Option<String> {
        match self.items.get(self.sel)? {
            Item::Request(r) => Some(r.key.clone()),
            Item::Member(m) => Some(m.key.as_str().to_string()),
        }
    }

    /// The current local petname of the highlighted item (empty if none) — used
    /// to pre-fill the rename buffer so an edit starts from the existing name.
    fn selected_alias(&self) -> String {
        match self.items.get(self.sel) {
            Some(Item::Member(m)) => m.alias.clone(),
            _ => String::new(),
        }
    }

    /// A human label for the highlighted item (alias if set, else a short key)
    /// for confirmation prompts.
    fn selected_label(&self) -> String {
        match self.items.get(self.sel) {
            Some(Item::Member(m)) if !m.alias.is_empty() => m.alias.clone(),
            Some(Item::Member(m)) => m.key.chars().take(12).collect::<String>(),
            Some(Item::Request(r)) => r.key.chars().take(12).collect(),
            None => String::new(),
        }
    }

    /// Approve the request at `key`, attaching `name` as a local petname when
    /// non-empty, then re-read so the freshly-sealed joiner moves into MEMBERS.
    async fn approve(&mut self, key: &str, name: String) {
        let as_name = Some(name).filter(|s| !s.trim().is_empty());
        let req = Request::MemberApprove {
            who: key.to_string(),
            as_name,
        };
        self.mutate(req, "approved — space key sealed to them")
            .await;
    }

    /// Set (or, with an empty `name`, clear) the local petname on `key`.
    async fn rename(&mut self, key: &str, name: String) {
        let cleared = name.trim().is_empty();
        let req = Request::MemberAlias {
            who: key.to_string(),
            name,
        };
        let ok = if cleared {
            "local name cleared"
        } else {
            "renamed"
        };
        self.mutate(req, ok).await;
    }

    /// Remove the member at `key` (admin-only) — rotates the space key.
    async fn remove(&mut self, key: &str) {
        let req = Request::MemberRemove {
            who: key.to_string(),
        };
        self.mutate(req, "removed — space key rotated").await;
    }

    /// Send a mutating request, set a success/failure status, and re-read the
    /// roster on success. Shared by approve/rename/remove.
    async fn mutate(&mut self, req: Request, ok_msg: &str) {
        match request(&self.home, &req).await {
            Ok(Response::Error { message, .. }) => self.status = Some(format!("failed: {message}")),
            Ok(_) => {
                self.status = Some(ok_msg.to_string());
                if let Err(e) = self.reload().await {
                    self.status = Some(format!("{ok_msg}, but reload failed: {e:#}"));
                }
            }
            Err(e) => self.status = Some(format!("failed: {e:#}")),
        }
    }

    /// Mint a fresh default invite (Pattern A: single-use, auto-admit, 7-day) and
    /// copy the link to the clipboard — the inline analogue of `lait invite`
    /// (the QR is impractical in a small viewport).
    async fn reinvite(&mut self) {
        let req = Request::Invite {
            require_approval: false,
            reusable: false,
            ttl_hours: None,
        };
        match request(&self.home, &req).await {
            Ok(Response::Text { text }) => {
                let token = text.trim().to_string();
                let link = token
                    .parse::<WorkspaceTicket>()
                    .map(|t| t.link())
                    .unwrap_or_else(|_| token.clone());
                self.status = Some(if crate::cli::copy_to_clipboard(&link) {
                    "invite link copied — single-use, auto-admit, expires in 7d".into()
                } else {
                    "invite created, but clipboard copy failed — use `lait invite`".into()
                });
            }
            Ok(Response::Error { message, .. }) => {
                self.status = Some(format!("invite failed: {message}"))
            }
            Ok(_) => self.status = Some("invite failed: unexpected response".into()),
            Err(e) => self.status = Some(format!("invite failed: {e:#}")),
        }
    }
}

/// Entry point for a bare, interactive `lait members`. Auto-spawns the daemon
/// like other local CLI flows, snapshots the roster, and runs the inline picker; the
/// terminal (raw mode + viewport) is always restored before returning.
pub async fn run(home: &Path) -> Result<()> {
    ensure_daemon(home).await?;
    let mut app = App::new(home.to_path_buf());
    app.reload().await?;

    let mut terminal = init_terminal(&app)?;
    let mut events = EventStream::new();
    let outcome = run_loop(&mut terminal, &mut app, &mut events).await;
    restore_terminal(&mut terminal, outcome.as_ref().ok().and_then(|s| s.clone()));
    outcome.map(|_| ())
}

/// The key loop. Returns the final one-line summary to leave in the scrollback.
async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    events: &mut EventStream,
) -> Result<Option<String>> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        let ev = match events.next().await {
            Some(Ok(ev)) => ev,
            Some(Err(_)) | None => return Ok(app.status.clone()),
        };
        let CEvent::Key(k) = ev else { continue };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        // Raw mode swallows the terminal's own Ctrl-C; honour it as a quit so the
        // user is never trapped in the picker.
        if k.modifiers.contains(KeyModifiers::CONTROL) && matches!(k.code, KeyCode::Char('c')) {
            return Ok(app.status.clone());
        }

        let admin = app.is_admin();
        // Clone the mode so we can freely mutate `app` while handling the key
        // (the small text buffers make this cheap and sidestep a self-borrow knot).
        match app.mode.clone() {
            Mode::List => match k.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(app.status.clone()),
                KeyCode::Up | KeyCode::Char('k') => {
                    app.sel = app.sel.saturating_sub(1);
                    app.status = None;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if app.sel + 1 < app.items.len() {
                        app.sel += 1;
                    }
                    app.status = None;
                }
                KeyCode::Enter => {
                    if !app.items.is_empty() {
                        app.mode = Mode::Detail;
                    }
                }
                KeyCode::Char('y') if admin && app.selected_is_request() => {
                    app.mode = Mode::Approve {
                        buffer: String::new(),
                    };
                }
                KeyCode::Char('n') if app.selected_is_request() => {
                    if let Some(Item::Request(r)) = app.items.get(app.sel).cloned() {
                        app.dismissed.insert(r.key);
                        app.status = Some(
                            "dismissed from this view (the request lingers until it ages out)"
                                .into(),
                        );
                        app.rebuild();
                    }
                }
                KeyCode::Char('r') if !app.items.is_empty() => {
                    app.mode = Mode::Rename {
                        buffer: app.selected_alias(),
                    };
                }
                KeyCode::Char('d') if admin && app.selected_is_member() => {
                    app.mode = Mode::ConfirmRemove;
                }
                KeyCode::Char('i') if admin => app.reinvite().await,
                _ => {}
            },
            Mode::Detail => match k.code {
                KeyCode::Esc | KeyCode::Char('q') => app.mode = Mode::List,
                KeyCode::Char('y') if admin && app.selected_is_request() => {
                    app.mode = Mode::Approve {
                        buffer: String::new(),
                    };
                }
                KeyCode::Char('n') if app.selected_is_request() => app.mode = Mode::List,
                KeyCode::Char('r') => {
                    app.mode = Mode::Rename {
                        buffer: app.selected_alias(),
                    };
                }
                KeyCode::Char('d') if admin && app.selected_is_member() => {
                    app.mode = Mode::ConfirmRemove;
                }
                // Enter backs out of a member detail; a request detail waits for y/n.
                KeyCode::Enter if !app.selected_is_request() => app.mode = Mode::List,
                _ => {}
            },
            Mode::Approve { mut buffer } => match k.code {
                KeyCode::Esc => app.mode = Mode::Detail,
                KeyCode::Enter => {
                    if let Some(key) = app.selected_key() {
                        app.approve(&key, buffer).await;
                    }
                    app.mode = Mode::List;
                }
                KeyCode::Backspace => {
                    buffer.pop();
                    app.mode = Mode::Approve { buffer };
                }
                KeyCode::Char(c) => {
                    buffer.push(c);
                    app.mode = Mode::Approve { buffer };
                }
                _ => app.mode = Mode::Approve { buffer },
            },
            Mode::Rename { mut buffer } => match k.code {
                KeyCode::Esc => app.mode = Mode::List,
                KeyCode::Enter => {
                    if let Some(key) = app.selected_key() {
                        app.rename(&key, buffer).await;
                    }
                    app.mode = Mode::List;
                }
                KeyCode::Backspace => {
                    buffer.pop();
                    app.mode = Mode::Rename { buffer };
                }
                KeyCode::Char(c) => {
                    buffer.push(c);
                    app.mode = Mode::Rename { buffer };
                }
                _ => app.mode = Mode::Rename { buffer },
            },
            Mode::ConfirmRemove => match k.code {
                KeyCode::Char('y') => {
                    if let Some(key) = app.selected_key() {
                        app.remove(&key).await;
                    }
                    app.mode = Mode::List;
                }
                KeyCode::Char('n') | KeyCode::Esc => app.mode = Mode::List,
                _ => {}
            },
        }
    }
}

// ---- rendering (ratatui widgets into the inline viewport) ----

fn draw(f: &mut ratatui::Frame, app: &App) {
    let foot = footer_lines(app);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(foot.len() as u16)])
        .split(f.area());
    let body = chunks[0];
    let lines = match &app.mode {
        Mode::List => list_lines(app, body),
        Mode::Detail => detail_lines(app),
        Mode::Approve { buffer } => input_lines("APPROVE JOIN REQUEST", app, buffer, true),
        Mode::Rename { buffer } => input_lines("RENAME (local name)", app, buffer, false),
        Mode::ConfirmRemove => confirm_remove_lines(app),
    };
    // Paragraph clips over-wide lines to the area for us — no manual truncation.
    f.render_widget(Paragraph::new(lines), body);
    f.render_widget(Paragraph::new(foot), chunks[1]);
}

fn header(s: &str) -> Line<'static> {
    Line::styled(
        s.to_string(),
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
}

fn list_lines(app: &App, area: Rect) -> Vec<Line<'static>> {
    if app.items.is_empty() {
        return vec![Line::from("  (no members)")];
    }

    // Flatten both sections into cells so scrolling is uniform.
    let mut cells: Vec<Cell> = Vec::new();
    let n_req = app.n_requests();
    if n_req > 0 {
        cells.push(Cell::Header("PENDING JOIN REQUESTS"));
        for i in 0..n_req {
            cells.push(Cell::Row {
                idx: i,
                text: item_text(app, i),
            });
        }
        cells.push(Cell::Blank);
    }
    cells.push(Cell::Header("MEMBERS"));
    for i in n_req..app.items.len() {
        cells.push(Cell::Row {
            idx: i,
            text: item_text(app, i),
        });
    }

    // Window the cells to the body height, keeping the selected row visible.
    let cells = window(&cells, app.sel, area.height as usize);
    cells
        .iter()
        .map(|c| match c {
            Cell::Header(h) => header(h),
            Cell::Blank => Line::from(""),
            Cell::Row { idx, text } => row_line(
                *idx == app.sel,
                text,
                area.width as usize,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        })
        .collect()
}

/// The unstyled text for item `i` (a bullet marks a request; a role marks a
/// member). Selection styling is added by [`row_line`].
fn item_text(app: &App, i: usize) -> String {
    match &app.items[i] {
        Item::Request(r) => {
            let short: String = r.key.chars().take(12).collect();
            let claim = if r.nick.is_empty() {
                String::new()
            } else {
                format!("   claims \"{}\"", r.nick)
            };
            format!("● {short}{claim}")
        }
        Item::Member(m) => {
            let name = if m.alias.is_empty() {
                String::new()
            } else {
                format!("   {}", m.alias)
            };
            let you = if m.me { "   (you)" } else { "" };
            format!(
                "{:<6} {}{}{}",
                m.role,
                m.key.chars().take(12).collect::<String>(),
                name,
                you
            )
        }
    }
}

fn detail_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match app.items.get(app.sel) {
        Some(Item::Request(r)) => {
            let claims = if r.nick.is_empty() {
                "(none)".to_string()
            } else {
                format!("\"{}\"", r.nick)
            };
            lines.push(header("REQUEST DETAIL"));
            lines.push(Line::from(format!("  full key:  {}", r.key)));
            lines.push(Line::from(format!("  claims:    {claims}")));
            lines.push(Line::from(format!("  seen:      {}", ago(r.ts))));
            lines.push(Line::styled(
                "  ⚠ confirm this key out-of-band before approving.",
                Style::default().fg(Color::Yellow),
            ));
            let who = if r.nick.is_empty() {
                "this joiner".to_string()
            } else {
                r.nick.clone()
            };
            lines.push(Line::styled(
                format!("  Approve {who}? [y/n]   esc to go back"),
                Style::default().add_modifier(Modifier::BOLD),
            ));
        }
        Some(Item::Member(m)) => {
            let name = if m.alias.is_empty() {
                "(none)".to_string()
            } else {
                m.alias.clone()
            };
            lines.push(header("MEMBER DETAIL"));
            lines.push(Line::from(format!("  role:  {}", m.role)));
            lines.push(Line::from(format!("  key:   {}", m.key.as_str())));
            lines.push(Line::from(format!("  name:  {name}")));
            lines.push(Line::from(format!(
                "  you:   {}",
                if m.me { "yes" } else { "no" }
            )));
        }
        None => lines.push(Line::from("(nothing selected)")),
    }
    lines
}

/// A single-line text-input panel shared by approve (with optional name) and
/// rename. `key_hint` shows the target key when approving.
fn input_lines(title: &str, app: &App, buffer: &str, key_hint: bool) -> Vec<Line<'static>> {
    let mut lines = vec![header(title)];
    if key_hint {
        if let Some(key) = app.selected_key() {
            lines.push(Line::from(format!("  key:  {key}")));
        }
    }
    lines.push(Line::styled(
        format!("  local name (optional): {buffer}_"),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    if !key_hint {
        lines.push(Line::styled(
            "  (empty clears · local only, never synced)",
            Style::default().fg(Color::DarkGray),
        ));
    }
    lines
}

fn confirm_remove_lines(app: &App) -> Vec<Line<'static>> {
    let label = app.selected_label();
    vec![
        header("REMOVE MEMBER"),
        Line::styled(
            "  ⚠ removes them and rotates the space key.",
            Style::default().fg(Color::Yellow),
        ),
        Line::styled(
            format!("  Remove {label}? [y/n]   esc to cancel"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ]
}

/// The mode's footer: a help line and, when set, a transient status line. The
/// help is contextual — it names only the actions available on the current row
/// (and hides admin-only actions from non-admins).
fn footer_lines(app: &App) -> Vec<Line<'static>> {
    let admin = app.is_admin();
    let help = match &app.mode {
        Mode::List => {
            let mut p = vec!["↑/↓ move", "enter details"];
            if admin && app.selected_is_request() {
                p.push("y approve");
            }
            if app.selected_is_request() {
                p.push("n dismiss");
            }
            if !app.items.is_empty() {
                p.push("r rename");
            }
            if admin && app.selected_is_member() {
                p.push("d remove");
            }
            if admin {
                p.push("i invite");
            }
            p.push("q quit");
            p.join(" · ")
        }
        Mode::Detail => {
            let mut p: Vec<&str> = Vec::new();
            if admin && app.selected_is_request() {
                p.push("y approve");
            }
            p.push("r rename");
            if admin && app.selected_is_member() {
                p.push("d remove");
            }
            p.push("esc back");
            p.join(" · ")
        }
        Mode::Approve { .. } => "type a local name · enter approve · esc cancel".to_string(),
        Mode::Rename { .. } => "type a name · enter save · esc cancel".to_string(),
        Mode::ConfirmRemove => "y remove · n cancel · esc cancel".to_string(),
    };
    let mut lines = vec![Line::styled(help, Style::default().fg(Color::DarkGray))];
    if let Some(s) = &app.status {
        lines.push(Line::styled(s.clone(), Style::default().fg(Color::Green)));
    }
    lines
}

/// Coarse "N{s,m,h,d} ago" from a unix-seconds timestamp — good enough for a
/// request's freshness. Falls back to the raw stamp if the clock is behind it.
fn ago(ts: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if ts == 0 || now < ts {
        return format!("{ts} (unix)");
    }
    let d = now - ts;
    if d < 60 {
        format!("{d}s ago")
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}

// ---- inline terminal lifecycle ----

/// An inline viewport (not the alternate screen) sized to fit the initial roster,
/// capped to the terminal height. ratatui reserves these lines below the prompt
/// and redraws within them; the rest of the scrollback is untouched.
fn init_terminal(app: &App) -> Result<Terminal<CrosstermBackend<Stdout>>> {
    let (_, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    // list body: (req header + requests + blank) if any, + members header +
    // members, then up to 2 footer lines. Clamp to the terminal, floor at 6.
    let sections = if app.n_requests() > 0 { 3 } else { 1 };
    let needed = (sections + app.items.len() + 2) as u16;
    let height = needed.clamp(6, rows.saturating_sub(1).max(6));

    enable_raw_mode().map_err(|e| anyhow!("enable raw mode: {e}"))?;
    let backend = CrosstermBackend::new(std::io::stdout());
    let terminal = Terminal::with_options(
        backend,
        TerminalOptions {
            viewport: Viewport::Inline(height),
        },
    )
    .map_err(|e| anyhow!("init inline terminal: {e}"))?;
    Ok(terminal)
}

/// Tear down: leave raw mode, wipe the viewport so the menu disappears, and drop
/// a single result line into the normal flow.
fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>, summary: Option<String>) {
    terminal.clear().ok();
    terminal.show_cursor().ok();
    disable_raw_mode().ok();
    if let Some(s) = summary {
        println!("{s}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    fn sample() -> App {
        let mut app = App::new(std::path::PathBuf::from("."));
        app.requests = vec![JoinRequestDto {
            key: "a1b2c3d4".repeat(8), // 64-hex
            nick: "alice".to_string(),
            ts: 0,
        }];
        app.members = vec![
            MemberDto {
                key: format!("act_{}", "9f2a".repeat(16)),
                role: "admin".to_string(),
                me: true,
                sponsor: None,
                alias: String::new(),
            },
            MemberDto {
                key: format!("act_{}", "3b7c".repeat(16)),
                role: "member".to_string(),
                me: false,
                sponsor: None,
                alias: "carol".to_string(),
            },
        ];
        app.rebuild();
        app
    }

    /// Render the whole frame to a `TestBackend` buffer and flatten it to text.
    fn rendered(app: &App) -> String {
        let mut term = Terminal::new(TestBackend::new(80, 16)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        buf.content()
            .iter()
            .map(|c| c.symbol())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn list_shows_both_sections_and_request_actions() {
        let app = sample(); // sel 0 = the request, we are admin
        let out = rendered(&app);
        assert!(out.contains("PENDING JOIN REQUESTS"));
        assert!(out.contains("MEMBERS"));
        assert!(out.contains("alice"));
        assert!(out.contains("carol"));
        assert!(out.contains("y approve"), "approve hint for a request");
        assert!(out.contains("r rename"));
        assert!(out.contains("i invite"), "admin invite hint");
    }

    #[test]
    fn member_row_offers_remove_not_approve() {
        let mut app = sample();
        app.sel = 1; // the admin member
        let out = rendered(&app);
        assert!(!out.contains("y approve"), "no approve on a member row");
        assert!(out.contains("d remove"), "remove offered on a member");
        assert!(out.contains("r rename"));
    }

    #[test]
    fn non_admin_hides_admin_actions() {
        let mut app = sample();
        // Demote ourselves: the "me" member becomes a plain member.
        app.members[0].role = "member".to_string();
        app.rebuild();
        app.sel = 1; // a request is at 0; pick a member row
        let out = rendered(&app);
        assert!(!out.contains("i invite"), "no invite for a non-admin");
        assert!(!out.contains("d remove"), "no remove for a non-admin");
        assert!(out.contains("r rename"), "rename is local, always offered");
    }

    #[test]
    fn confirm_remove_warns_about_key_rotation() {
        let mut app = sample();
        app.sel = 1;
        app.mode = Mode::ConfirmRemove;
        let out = rendered(&app);
        assert!(out.contains("REMOVE MEMBER"));
        assert!(out.contains("rotates the space key"));
        assert!(out.contains("Remove"));
    }

    #[test]
    fn rename_prefills_existing_alias() {
        let mut app = sample();
        app.sel = 2; // carol, alias "carol"
        app.mode = Mode::Rename {
            buffer: app.selected_alias(),
        };
        let out = rendered(&app);
        assert!(out.contains("RENAME"));
        assert!(out.contains("carol"), "edit starts from the current name");
    }

    #[test]
    fn request_detail_warns_before_approving() {
        let mut app = sample();
        app.mode = Mode::Detail; // sel 0 is the request
        let out = rendered(&app);
        assert!(out.contains("REQUEST DETAIL"));
        assert!(out.contains("confirm this key out-of-band"));
        assert!(out.contains("Approve alice?"));
    }
}
