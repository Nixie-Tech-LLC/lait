//! The `lait tui` full-screen board client (UI.md §4–§6). A [ratatui]
//! client over the daemon's control socket — never an embedded node (UI.md §1).
//!
//! It opens two logical channels over the one socket: the **command channel**
//! (ordinary request→response, for edits and snapshot re-reads) and the
//! **subscribe channel** (the live [`Doorbell`] stream, UI.md §4.1). The event
//! stream is **doorbells, not deltas**: a frame rings "these scopes are dirty",
//! and the client re-reads the authoritative projection — it never patches from a
//! doorbell (UI.md §4.2). Edits echo through a **correlation-free optimistic
//! overlay** cleared on any doorbell for their scope (UI.md §4.3).
//!
//! [ratatui]: https://ratatui.rs

use std::collections::HashMap;
use std::io::Stdout;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use crossterm::event::{Event as CEvent, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use n0_future::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};

use crate::cli::ensure_daemon;
use crate::control::{request, Doorbell, Filter, Request, Response, Subscription};
use crate::diagnose::{DiagnosisView, GateState};
use crate::dto::{BoardView, IssueView, MemberDto, ProjectDto, Row};
use crate::workspaces::{self, WorkspaceEntry};

/// Which view is on the navigation stack top (UI.md §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Board,
    List,
    Activity,
    Detail,
    Members,
    Doctor,
    Workspaces,
    Help,
}

/// An input modal (quick-create, edit, comment).
#[derive(Debug, Clone)]
struct Modal {
    prompt: String,
    buffer: String,
    action: ModalAction,
}

#[derive(Debug, Clone)]
enum ModalAction {
    Create,
    EditTitle(String),
    SetStatus(String),
    SetPriority(String),
    Comment(String),
    Assign(String),
}

/// The optimistic overlay: a local prediction keyed by `(doc_id, field)` cleared
/// on any doorbell for its scope (UI.md §4.3). Correlation-free.
#[derive(Debug, Default)]
struct Overlay {
    // doc_id -> (field -> predicted value)
    by_doc: HashMap<String, HashMap<String, String>>,
}

impl Overlay {
    fn set(&mut self, doc_id: &str, field: &str, value: &str) {
        self.by_doc
            .entry(doc_id.to_string())
            .or_default()
            .insert(field.to_string(), value.to_string());
    }
    fn clear_doc(&mut self, doc_id: &str) {
        self.by_doc.remove(doc_id);
    }
    fn get<'a>(&'a self, doc_id: &str, field: &str) -> Option<&'a str> {
        self.by_doc
            .get(doc_id)
            .and_then(|m| m.get(field))
            .map(|s| s.as_str())
    }
    fn has(&self, doc_id: &str) -> bool {
        self.by_doc.contains_key(doc_id)
    }
}

struct App {
    home: PathBuf,
    view: View,
    prev_view: View,
    projects: Vec<ProjectDto>,
    project_idx: usize,
    /// Whether the configured `project.default` was applied to `project_idx`
    /// (first successful project load only — Tab cycling then owns it).
    applied_default_project: bool,
    /// Unread-inbox badge for the header (refreshed on doorbell activity).
    inbox_unread: u64,
    board: Option<BoardView>,
    list: Vec<Row>,
    col_idx: usize,
    row_idx: usize,
    detail: Option<IssueView>,
    activity: Vec<String>,
    members: Vec<MemberDto>,
    overlay: Overlay,
    modal: Option<Modal>,
    status: String,
    /// Sync indicator (UI.md §8): online peer count from the last status poll.
    peers_online: usize,
    /// Last guided-join diagnosis (the `Doctor` panel), refreshed on entry + `r`.
    diagnosis: Option<DiagnosisView>,
    /// Joined-workspace registry rows for the selector, and the cursor into them.
    workspaces: Vec<WorkspaceEntry>,
    ws_idx: usize,
    quit: bool,
}

impl App {
    fn new(home: PathBuf) -> Self {
        App {
            home,
            view: View::Board,
            prev_view: View::Board,
            projects: Vec::new(),
            project_idx: 0,
            applied_default_project: false,
            inbox_unread: 0,
            board: None,
            list: Vec::new(),
            col_idx: 0,
            row_idx: 0,
            detail: None,
            activity: Vec::new(),
            members: Vec::new(),
            overlay: Overlay::default(),
            modal: None,
            status: String::new(),
            peers_online: 0,
            diagnosis: None,
            workspaces: Vec::new(),
            ws_idx: 0,
            quit: false,
        }
    }

    /// Refresh the guided-join diagnosis for the `Doctor` panel.
    async fn reload_diagnosis(&mut self) -> Result<()> {
        if let Response::Diagnosis(v) = self
            .req(Request::Diagnose {
                expected_workspace: None,
            })
            .await?
        {
            self.diagnosis = Some(*v);
        }
        Ok(())
    }

    /// Refresh the joined-workspace registry for the selector (store-free read).
    async fn reload_workspaces(&mut self) -> Result<()> {
        self.workspaces = workspaces::list();
        if self.ws_idx >= self.workspaces.len() {
            self.ws_idx = 0;
        }
        Ok(())
    }

    /// Refresh the ambient sync indicator (peers online) — polled on a timer so
    /// the P1 status bar stays live without a doorbell for presence (UI.md §8).
    async fn refresh_status(&mut self) {
        if let Ok(Response::Status(s)) = self.req(Request::Status).await {
            self.peers_online = s.online_peers;
        }
    }

    fn current_project(&self) -> Option<&ProjectDto> {
        self.projects.get(self.project_idx)
    }

    /// The doc/row currently under focus in the board.
    fn focused_row(&self) -> Option<Row> {
        match self.view {
            View::List => self.list.get(self.row_idx).cloned(),
            _ => {
                let b = self.board.as_ref()?;
                let col = b.columns.get(self.col_idx)?;
                col.rows.get(self.row_idx).cloned()
            }
        }
    }

    async fn req(&self, req: Request) -> Result<Response> {
        request(&self.home, &req).await
    }

    async fn reload_projects(&mut self) -> Result<()> {
        if let Response::Projects { projects } = self.req(Request::ProjectList).await? {
            self.projects = projects;
            if self.project_idx >= self.projects.len() {
                self.project_idx = 0;
            }
            // First load: land on the configured `project.default` when set.
            if !self.applied_default_project {
                self.applied_default_project = true;
                if let Some(dflt) =
                    crate::config::Settings::load(Some(&self.home)).default_project()
                {
                    if let Some(i) = self
                        .projects
                        .iter()
                        .position(|p| p.key.eq_ignore_ascii_case(&dflt))
                    {
                        self.project_idx = i;
                    }
                }
            }
        }
        Ok(())
    }

    async fn reload_board(&mut self) -> Result<()> {
        let Some(p) = self.current_project().map(|p| p.key.clone()) else {
            self.board = None;
            return Ok(());
        };
        match self
            .req(Request::Board {
                project: Some(p),
                project_hint: None,
            })
            .await?
        {
            Response::Board(b) => {
                self.board = Some(*b);
                self.clamp_selection();
            }
            Response::Error { message, .. } => self.status = message,
            _ => {}
        }
        Ok(())
    }

    async fn reload_list(&mut self) -> Result<()> {
        let project = self.current_project().map(|p| p.key.clone());
        match self
            .req(Request::List {
                project,
                filter: Filter::default(),
            })
            .await?
        {
            Response::List { rows } => {
                self.list = rows;
                if self.row_idx >= self.list.len() {
                    self.row_idx = self.list.len().saturating_sub(1);
                }
            }
            Response::Error { message, .. } => self.status = message,
            _ => {}
        }
        Ok(())
    }

    async fn reload_activity(&mut self) -> Result<()> {
        if let Response::Activity { events, .. } = self.req(Request::Activity { since: 0 }).await? {
            self.activity = events
                .iter()
                .rev()
                .map(|e| format!("{} {} {}", e.reff, e.actor_nick, e.kind))
                .collect();
        }
        Ok(())
    }

    async fn reload_members(&mut self) -> Result<()> {
        if let Response::Members { members } = self.req(Request::Members).await? {
            self.members = members;
        }
        Ok(())
    }

    fn clamp_selection(&mut self) {
        if let Some(b) = &self.board {
            if self.col_idx >= b.columns.len() {
                self.col_idx = b.columns.len().saturating_sub(1);
            }
            let col_len = b
                .columns
                .get(self.col_idx)
                .map(|c| c.rows.len())
                .unwrap_or(0);
            if self.row_idx >= col_len {
                self.row_idx = col_len.saturating_sub(1);
            }
        }
    }

    /// Re-read whatever the current view needs (used on doorbell + `r`).
    async fn refresh_current(&mut self) -> Result<()> {
        match self.view {
            View::Board => self.reload_board().await?,
            View::List => self.reload_list().await?,
            View::Activity => self.reload_activity().await?,
            View::Members => self.reload_members().await?,
            View::Detail => {
                if let Some(d) = &self.detail {
                    let reff = d.reff.clone();
                    if let Response::Issue(v) = self.req(Request::IssueView { reff }).await? {
                        self.detail = Some(*v);
                    }
                }
            }
            View::Doctor => self.reload_diagnosis().await?,
            View::Workspaces => self.reload_workspaces().await?,
            View::Help => {}
        }
        Ok(())
    }

    /// Refresh the header's inbox-unread badge (cheap; the durable file read is
    /// daemon-side). Best-effort — a hiccup just keeps the old count.
    async fn refresh_inbox_count(&mut self) {
        if let Ok(Response::Inbox { unread, .. }) = self.req(Request::Inbox { clear: false }).await
        {
            self.inbox_unread = unread;
        }
    }

    /// Apply a doorbell: clear overlays for dirty docs, re-read affected views
    /// (UI.md §4.2–§4.3). Doorbells are dirty-notices — the client re-reads.
    async fn on_doorbell(&mut self, db: Doorbell) -> Result<()> {
        if db.reset {
            // rebaseline wholesale (UI.md §4.1)
            self.overlay = Overlay::default();
            self.reload_projects().await?;
            self.refresh_current().await?;
            self.refresh_inbox_count().await;
            return Ok(());
        }
        for docs in db.dirty_by_project.values() {
            for d in docs {
                self.overlay.clear_doc(d);
            }
        }
        // Re-read the current view if any dirty scope could touch it. At P0 a
        // single-project workspace always intersects; the visibility filter
        // (UI.md §4.2) is a P1 optimisation once multiple projects sync.
        self.refresh_current().await?;
        // Inbox entries only arise from imports, which ring activity_advanced.
        if db.activity_advanced {
            self.refresh_inbox_count().await;
        }
        Ok(())
    }
}

/// Launch the TUI (UI.md §4). Auto-spawns the daemon like the CLI.
pub async fn run(home: &Path) -> Result<()> {
    ensure_daemon(home).await?;
    let mut app = App::new(home.to_path_buf());
    app.reload_projects().await?;
    app.reload_board().await?;
    app.reload_activity().await?;
    app.refresh_inbox_count().await;

    let mut terminal = init_terminal()?;
    let mut sub = crate::control::subscribe(home, 0).await.ok();
    let mut events = EventStream::new();

    let res = run_loop(&mut terminal, &mut app, &mut sub, &mut events).await;
    restore_terminal(&mut terminal)?;
    res
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    sub: &mut Option<Subscription>,
    events: &mut EventStream,
) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    app.refresh_status().await;
    loop {
        terminal.draw(|f| draw(f, app))?;
        if app.quit {
            return Ok(());
        }

        // Wait for a terminal event, a doorbell, or a periodic status tick (the
        // ambient sync indicator, which presence doesn't doorbell for).
        tokio::select! {
            _ = tick.tick() => { app.refresh_status().await; }
            maybe_ev = events.next() => {
                match maybe_ev {
                    Some(Ok(CEvent::Key(key))) if key.kind == KeyEventKind::Press => {
                        handle_key(app, key.code, key.modifiers).await?;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => return Ok(()),
                }
            }
            db = next_doorbell(sub) => {
                match db {
                    Some(db) => { let _ = app.on_doorbell(db).await; }
                    None => {
                        // subscription ended (daemon restart); re-subscribe.
                        *sub = crate::control::subscribe(&app.home, 0).await.ok();
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        }
    }
}

/// Await the next doorbell, or park forever if there is no subscription.
async fn next_doorbell(sub: &mut Option<Subscription>) -> Option<Doorbell> {
    match sub {
        Some(s) => s.next().await.ok().flatten(),
        None => {
            // no subscription: never resolves (the select's other arm drives).
            std::future::pending::<Option<Doorbell>>().await
        }
    }
}

async fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) -> Result<()> {
    // Modal input takes precedence.
    if app.modal.is_some() {
        return handle_modal_key(app, code).await;
    }
    match code {
        KeyCode::Char('q') => {
            if app.view == View::Board || app.view == View::List {
                app.quit = true;
            } else {
                pop_view(app);
            }
        }
        KeyCode::Esc => pop_view(app),
        KeyCode::Char('?') => {
            app.prev_view = app.view;
            app.view = View::Help;
        }
        KeyCode::Char('1') => {
            app.view = View::Board;
            app.reload_board().await?;
        }
        KeyCode::Char('2') => {
            app.view = View::List;
            app.reload_list().await?;
        }
        KeyCode::Char('3') => {
            app.view = View::Activity;
            app.reload_activity().await?;
        }
        KeyCode::Char('4') => {
            app.view = View::Members;
            app.reload_members().await?;
        }
        // Onboarding: [d]octor = guided-join verifier; [w]orkspaces = selector.
        KeyCode::Char('d') => {
            app.prev_view = app.view;
            app.view = View::Doctor;
            app.reload_diagnosis().await?;
        }
        KeyCode::Char('w') => {
            app.prev_view = app.view;
            app.view = View::Workspaces;
            app.reload_workspaces().await?;
        }
        KeyCode::Char('r') => app.refresh_current().await?,
        KeyCode::Char('p') if mods.contains(KeyModifiers::CONTROL) => {}
        KeyCode::Tab => {
            if !app.projects.is_empty() {
                app.project_idx = (app.project_idx + 1) % app.projects.len();
                app.col_idx = 0;
                app.row_idx = 0;
                app.reload_board().await?;
            }
        }
        KeyCode::Char('j') | KeyCode::Down => move_row(app, 1),
        KeyCode::Char('k') | KeyCode::Up => move_row(app, -1),
        KeyCode::Char('h') | KeyCode::Left => move_col(app, -1),
        KeyCode::Char('l') | KeyCode::Right => move_col(app, 1),
        KeyCode::Char('H') => status_move(app, -1).await?,
        KeyCode::Char('L') => status_move(app, 1).await?,
        KeyCode::Enter => open_detail(app).await?,
        KeyCode::Char('c') => {
            app.modal = Some(Modal {
                prompt: "New issue title".into(),
                buffer: String::new(),
                action: ModalAction::Create,
            });
        }
        KeyCode::Char('e') => start_edit_title(app),
        KeyCode::Char('a') => start_assign(app),
        KeyCode::Char('p') => start_priority(app),
        KeyCode::Char('s') => start_status(app),
        KeyCode::Char('C') => start_comment(app),
        _ => {}
    }
    Ok(())
}

async fn handle_modal_key(app: &mut App, code: KeyCode) -> Result<()> {
    let Some(modal) = app.modal.as_mut() else {
        return Ok(());
    };
    match code {
        KeyCode::Esc => {
            app.modal = None;
        }
        KeyCode::Enter => {
            let modal = app.modal.take().unwrap();
            submit_modal(app, modal).await?;
        }
        KeyCode::Backspace => {
            modal.buffer.pop();
        }
        KeyCode::Char(ch) => modal.buffer.push(ch),
        _ => {}
    }
    Ok(())
}

async fn submit_modal(app: &mut App, modal: Modal) -> Result<()> {
    let buf = modal.buffer.trim().to_string();
    let req = match &modal.action {
        ModalAction::Create => {
            if buf.is_empty() {
                return Ok(());
            }
            let project = app.current_project().map(|p| p.key.clone());
            Request::IssueNew {
                title: buf,
                project,
                project_hint: None,
                assignees: vec![],
                priority: None,
                labels: vec![],
                body: None,
            }
        }
        ModalAction::EditTitle(reff) => {
            // optimistic overlay
            if let Some(row) = app.focused_row() {
                app.overlay.set(row.doc_id.as_str(), "title", &buf);
            }
            Request::IssueEdit {
                reff: reff.clone(),
                title: Some(buf),
                status: None,
                priority: None,
            }
        }
        ModalAction::SetStatus(reff) => Request::IssueEdit {
            reff: reff.clone(),
            title: None,
            status: Some(buf),
            priority: None,
        },
        ModalAction::SetPriority(reff) => Request::IssueEdit {
            reff: reff.clone(),
            title: None,
            status: None,
            priority: Some(buf),
        },
        ModalAction::Comment(reff) => {
            if buf.is_empty() {
                return Ok(());
            }
            Request::Comment {
                reff: reff.clone(),
                body: buf,
            }
        }
        ModalAction::Assign(reff) => Request::Assign {
            reff: reff.clone(),
            who: vec![buf],
            add: true,
        },
    };
    match app.req(req).await? {
        Response::Error { message, .. } => {
            // validate-then-commit: on error nothing changed — roll back overlay.
            if let Some(row) = app.focused_row() {
                app.overlay.clear_doc(row.doc_id.as_str());
            }
            app.status = message;
        }
        _ => {
            app.status.clear();
        }
    }
    app.refresh_current().await?;
    Ok(())
}

fn start_edit_title(app: &mut App) {
    if let Some(row) = app.focused_row() {
        app.modal = Some(Modal {
            prompt: "Edit title".into(),
            buffer: row.title.clone(),
            action: ModalAction::EditTitle(row.reff),
        });
    }
}
fn start_assign(app: &mut App) {
    if let Some(row) = app.focused_row() {
        app.modal = Some(Modal {
            prompt: "Assign (@me / key)".into(),
            buffer: String::new(),
            action: ModalAction::Assign(row.reff),
        });
    }
}
fn start_priority(app: &mut App) {
    if let Some(row) = app.focused_row() {
        app.modal = Some(Modal {
            prompt: "Priority (none/low/medium/high/urgent)".into(),
            buffer: String::new(),
            action: ModalAction::SetPriority(row.reff),
        });
    }
}
fn start_status(app: &mut App) {
    if let Some(row) = app.focused_row() {
        app.modal = Some(Modal {
            prompt: "Status id".into(),
            buffer: String::new(),
            action: ModalAction::SetStatus(row.reff),
        });
    }
}
fn start_comment(app: &mut App) {
    let reff = match app.view {
        View::Detail => app.detail.as_ref().map(|d| d.reff.clone()),
        _ => app.focused_row().map(|r| r.reff),
    };
    if let Some(reff) = reff {
        app.modal = Some(Modal {
            prompt: "Comment".into(),
            buffer: String::new(),
            action: ModalAction::Comment(reff),
        });
    }
}

async fn open_detail(app: &mut App) -> Result<()> {
    if let Some(row) = app.focused_row() {
        if let Response::Issue(v) = app.req(Request::IssueView { reff: row.reff }).await? {
            app.detail = Some(*v);
            app.prev_view = app.view;
            app.view = View::Detail;
        }
    }
    Ok(())
}

/// `H`/`L`: move the focused issue to the previous/next workflow status
/// (an `IssueEdit --status`, UI.md §5.1), with an optimistic overlay.
async fn status_move(app: &mut App, dir: i32) -> Result<()> {
    let Some(b) = &app.board else { return Ok(()) };
    let Some(row) = app.focused_row() else {
        return Ok(());
    };
    let states: Vec<String> = b.columns.iter().map(|c| c.state.id.clone()).collect();
    let cur = states.iter().position(|s| s == &row.status).unwrap_or(0);
    let next = (cur as i32 + dir).clamp(0, states.len() as i32 - 1) as usize;
    if next == cur {
        return Ok(());
    }
    let target = states[next].clone();
    app.overlay.set(row.doc_id.as_str(), "status", &target);
    let resp = app
        .req(Request::IssueEdit {
            reff: row.reff.clone(),
            title: None,
            status: Some(target),
            priority: None,
        })
        .await?;
    if let Response::Error { message, .. } = resp {
        app.overlay.clear_doc(row.doc_id.as_str());
        app.status = message;
    }
    app.reload_board().await?;
    Ok(())
}

fn move_row(app: &mut App, delta: i32) {
    // The workspace selector has its own cursor into the registry rows.
    if app.view == View::Workspaces {
        let len = app.workspaces.len();
        if len == 0 {
            return;
        }
        let ni = (app.ws_idx as i32 + delta).clamp(0, len as i32 - 1);
        app.ws_idx = ni as usize;
        return;
    }
    let len = match app.view {
        View::List => app.list.len(),
        _ => app
            .board
            .as_ref()
            .and_then(|b| b.columns.get(app.col_idx))
            .map(|c| c.rows.len())
            .unwrap_or(0),
    };
    if len == 0 {
        return;
    }
    let ni = (app.row_idx as i32 + delta).clamp(0, len as i32 - 1);
    app.row_idx = ni as usize;
}

fn move_col(app: &mut App, delta: i32) {
    if app.view != View::Board {
        return;
    }
    if let Some(b) = &app.board {
        let n = b.columns.len();
        if n == 0 {
            return;
        }
        let ni = (app.col_idx as i32 + delta).clamp(0, n as i32 - 1);
        app.col_idx = ni as usize;
        app.row_idx = 0;
    }
}

fn pop_view(app: &mut App) {
    match app.view {
        View::Detail | View::Help | View::Doctor | View::Workspaces => app.view = app.prev_view,
        View::List | View::Activity | View::Members => app.view = View::Board,
        View::Board => app.quit = true,
    }
}

// ---- rendering ----

fn draw(f: &mut ratatui::Frame, app: &App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    match app.view {
        View::Board => draw_board(f, app, chunks[1]),
        View::List => draw_list(f, app, chunks[1]),
        View::Activity => draw_activity(f, app, chunks[1]),
        View::Members => draw_members(f, app, chunks[1]),
        View::Detail => draw_detail(f, app, chunks[1]),
        View::Doctor => draw_doctor(f, app, chunks[1]),
        View::Workspaces => draw_workspaces(f, app, chunks[1]),
        View::Help => draw_help(f, chunks[1]),
    }
    draw_footer(f, app, chunks[2]);

    if let Some(modal) = &app.modal {
        draw_modal(f, modal, area);
    }
}

fn draw_header(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let proj = app
        .current_project()
        .map(|p| format!("{} · {}", p.key, p.name))
        .unwrap_or_else(|| "no project".into());
    let view = match app.view {
        View::Board => "board",
        View::List => "list",
        View::Activity => "activity",
        View::Members => "members",
        View::Detail => "detail",
        View::Doctor => "doctor",
        View::Workspaces => "spaces",
        View::Help => "help",
    };
    // Sync indicator (UI.md §8): peers online / offline.
    let (sync_txt, sync_color) = if app.peers_online > 0 {
        (format!("⇅ {} peer(s)", app.peers_online), Color::Green)
    } else {
        ("○ offline".to_string(), Color::DarkGray)
    };
    let inbox = if app.inbox_unread > 0 {
        Span::styled(
            format!("   inbox {}", app.inbox_unread),
            Style::default().fg(Color::Cyan),
        )
    } else {
        Span::raw(String::new())
    };
    let line = Line::from(vec![
        Span::styled(proj, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("   [{view}]   ")),
        Span::styled(sync_txt, Style::default().fg(sync_color)),
        inbox,
        Span::styled(
            "   [?] help  [1/2/3/4] views  [d]octor [w] spaces  [c] new  [q] quit",
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn effective_status<'a>(app: &'a App, row: &'a Row) -> String {
    app.overlay
        .get(row.doc_id.as_str(), "status")
        .map(|s| s.to_string())
        .unwrap_or_else(|| row.status.clone())
}
fn effective_title(app: &App, row: &Row) -> String {
    app.overlay
        .get(row.doc_id.as_str(), "title")
        .map(|s| s.to_string())
        .unwrap_or_else(|| row.title.clone())
}

fn draw_board(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let Some(b) = &app.board else {
        f.render_widget(
            Paragraph::new(
                "(no projects visible yet — still syncing, or create one: `lait projects new`)",
            ),
            area,
        );
        return;
    };
    let n = b.columns.len().max(1);
    let constraints: Vec<Constraint> = (0..n)
        .map(|_| Constraint::Percentage((100 / n) as u16))
        .collect();
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(area);
    for (ci, col) in b.columns.iter().enumerate() {
        let focused_col = ci == app.col_idx;
        let mut lines = Vec::new();
        for (ri, row) in col.rows.iter().enumerate() {
            let selected = focused_col && ri == app.row_idx;
            let alias = row.key_alias.as_deref().unwrap_or(&row.reff);
            let opt = if app.overlay.has(row.doc_id.as_str()) {
                "▲"
            } else {
                " "
            };
            let prefix = if selected { "▌" } else { " " };
            let title = effective_title(app, row);
            let mut style = Style::default();
            if selected {
                style = style.add_modifier(Modifier::REVERSED);
            }
            if row.provisional {
                style = style.fg(Color::DarkGray);
            }
            lines.push(Line::styled(
                format!(
                    "{prefix}{} ·{}·{opt} {}",
                    alias,
                    row.priority.badge(),
                    title
                ),
                style,
            ));
        }
        if lines.is_empty() {
            lines.push(Line::styled(
                "  (empty)",
                Style::default().fg(Color::DarkGray),
            ));
        }
        let title = format!(" {} ({}) ", col.state.name, col.rows.len());
        let border = if focused_col {
            Color::Cyan
        } else {
            Color::DarkGray
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border))
            .title(title);
        f.render_widget(Paragraph::new(lines).block(block), cols[ci]);
    }
}

fn draw_list(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    for (i, row) in app.list.iter().enumerate() {
        let selected = i == app.row_idx;
        let alias = row.key_alias.as_deref().unwrap_or(&row.reff);
        let mut style = Style::default();
        if selected {
            style = style.add_modifier(Modifier::REVERSED);
        }
        let asg = if row.assignee_summary.is_empty() {
            String::new()
        } else {
            format!("  {}", row.assignee_summary)
        };
        lines.push(Line::styled(
            format!(
                "{:<10} ·{}· {:<12} {}{}",
                alias,
                row.priority.badge(),
                effective_status(app, row),
                effective_title(app, row),
                asg
            ),
            style,
        ));
    }
    if lines.is_empty() {
        lines.push(Line::from("(no issues)"));
    }
    let block = Block::default().borders(Borders::ALL).title(" Issues ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_activity(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let lines: Vec<Line> = if app.activity.is_empty() {
        vec![Line::from("(no activity)")]
    } else {
        app.activity.iter().map(|s| Line::from(s.clone())).collect()
    };
    let block = Block::default().borders(Borders::ALL).title(" Activity ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_members(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    if app.members.is_empty() {
        lines.push(Line::from("(no members yet)"));
    }
    for m in &app.members {
        let you = if m.me { "  (you)" } else { "" };
        let style = if m.role == "admin" {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        lines.push(Line::styled(
            format!("{:<7} {}{}", m.role, m.key.short(), you),
            style,
        ));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Members (signed ACL — verified identity) ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_detail(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let Some(v) = &app.detail else {
        f.render_widget(Paragraph::new("(no issue)"), area);
        return;
    };
    let mut lines = vec![
        Line::styled(
            format!("{}  {}", v.key_alias.as_deref().unwrap_or(&v.reff), v.title),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::from(format!(
            "status {}   priority {}   project {}",
            v.status,
            v.priority.as_str(),
            v.project_key.as_deref().unwrap_or("?")
        )),
    ];
    if !v.assignees.is_empty() {
        let names: Vec<String> = v.assignees.iter().map(|u| u.short()).collect();
        lines.push(Line::from(format!("assignees {}", names.join(", "))));
    }
    if !v.label_names.is_empty() {
        lines.push(Line::from(format!("labels {}", v.label_names.join(", "))));
    }
    lines.push(Line::from(""));
    if !v.description.is_empty() {
        for l in v.description.lines() {
            lines.push(Line::from(l.to_string()));
        }
        lines.push(Line::from(""));
    }
    if !v.comments.is_empty() {
        lines.push(Line::styled(
            format!("Comments ({})", v.comments.len()),
            Style::default().add_modifier(Modifier::BOLD),
        ));
        for c in &v.comments {
            lines.push(Line::from(format!(
                "{} · {}  {}",
                c.author.short(),
                c.ts,
                c.body
            )));
        }
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Issue  [C]omment [e]dit [Esc] ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_help(f: &mut ratatui::Frame, area: Rect) {
    let text = "\
 Keys
   1/2/3/4   board / list / activity / members
   j k       move within a column
   h l       move across columns
   H L       move issue to prev/next status
   Tab       cycle project
   Enter     open detail
   c         create issue     e  edit title
   a         assign           C  comment
   d         doctor (guided-join verifier)
   w         workspaces (which dir holds which board)
   r         reload (self-heal)
   ? / Esc   help / back      q  quit";
    let block = Block::default().borders(Borders::ALL).title(" Help ");
    f.render_widget(Paragraph::new(text).block(block), area);
}

/// The guided-join verifier panel: the ordered gate readout with a colour per
/// state, then the one-line summary. Mirrors the CLI `doctor` output (same DTO).
fn draw_doctor(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match &app.diagnosis {
        None => lines.push(Line::from("(diagnosing… press r to refresh)")),
        Some(v) => {
            for g in &v.gates {
                let color = match g.state {
                    GateState::Pass => Color::Green,
                    GateState::Wait => Color::Yellow,
                    GateState::Fail => Color::Red,
                    GateState::Skip => Color::DarkGray,
                };
                lines.push(Line::from(vec![
                    Span::styled(g.state.glyph(), Style::default().fg(color)),
                    Span::raw(format!(" {:<11} ", g.label)),
                    Span::raw(g.detail.clone()),
                ]));
            }
            lines.push(Line::from(""));
            let summary_color = if v.blocked_on.is_some() {
                Color::Yellow
            } else {
                Color::Green
            };
            lines.push(Line::styled(
                v.summary.clone(),
                Style::default().fg(summary_color),
            ));
        }
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Doctor — guided-join verifier  [r] refresh  [Esc] back ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// The joined-workspace selector: which directory holds which board, current row
/// highlighted. Selecting shows how to switch (cd there) — full live re-binding is
/// out of scope for this panel, which is navigation, not a daemon re-home.
fn draw_workspaces(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    if app.workspaces.is_empty() {
        lines.push(Line::from(
            "(no spaces yet — `lait init` or `lait join <link>`)",
        ));
    }
    for (i, e) in app.workspaces.iter().enumerate() {
        let selected = i == app.ws_idx;
        let marker = if selected { "> " } else { "  " };
        let nick = if e.host_nick.is_empty() {
            String::new()
        } else {
            format!("  (from {})", e.host_nick)
        };
        let style = if selected {
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan)
        } else {
            Style::default()
        };
        let name = if e.name.is_empty() {
            "(unnamed)"
        } else {
            e.name.as_str()
        };
        let short: String = e.workspace.chars().take(12).collect();
        lines.push(Line::styled(
            format!("{marker}{name}  {short}  {}{nick}", e.origin),
            style,
        ));
        lines.push(Line::styled(
            format!("    {}", e.path),
            Style::default().fg(Color::DarkGray),
        ));
    }
    if let Some(sel) = app.workspaces.get(app.ws_idx) {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            format!("→ to switch: cd {}  (then run `lait tui`)", sel.path),
            Style::default().fg(Color::DarkGray),
        ));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Spaces  [j/k] move  [Esc] back ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_footer(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let msg = if app.status.is_empty() {
        "●=you  ▲=optimistic  ·U/H/M/L·=priority".to_string()
    } else {
        app.status.clone()
    };
    f.render_widget(
        Paragraph::new(Line::styled(msg, Style::default().fg(Color::DarkGray))),
        area,
    );
}

fn draw_modal(f: &mut ratatui::Frame, modal: &Modal, area: Rect) {
    let w = area.width.min(70);
    let h = 3;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + area.height / 3;
    let rect = Rect::new(x, y, w, h);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(format!(" {} ", modal.prompt));
    let line = Line::from(vec![
        Span::raw(&modal.buffer),
        Span::styled("▏", Style::default().fg(Color::Cyan)),
    ]);
    f.render_widget(ratatui::widgets::Clear, rect);
    f.render_widget(Paragraph::new(line).block(block), rect);
}

fn init_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    use crossterm::execute;
    use crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
    enable_raw_mode().map_err(|e| anyhow!("enable raw mode: {e}"))?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(|e| anyhow!("enter alt screen: {e}"))?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend).map_err(|e| anyhow!("init terminal: {e}"))?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    use crossterm::execute;
    use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    Ok(())
}
