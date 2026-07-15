//! App state + the daemon-facing side of the TUI: reload fns, doorbell
//! routing (U§4.2 — every dirty scope refreshes exactly the panels that show
//! it), the optimistic [`Overlay`] (U§4.3, moved verbatim from the old
//! client), action execution, and the focus model.
//!
//! Focus is DERIVED, never stored: the top of the overlay `stack` wins, then
//! peek-vs-board, then the active screen. `Esc` pops stack → closes peek →
//! returns to Board → quits.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::Result;
use ratatui::layout::Rect;

use crate::cmdspec::Special;
use crate::control::{
    request, BoardPos, CatalogScope, Doorbell, Event as LogEvent, Filter, Request, Response,
};
use crate::diagnose::DiagnosisView;
use crate::dto::{
    ActivityEvent, BoardView, InboxEntry, IssueView, JoinRequestDto, MemberDto, Priority,
    ProjectDto, Row, SeedDto,
};
use crate::workspaces::{self, WorkspaceEntry};

use super::action::Action;
use super::keymap::{FocusKind, Keymap};
use super::palette::PaletteState;
use super::theme::Theme;
use super::widgets::confirm::{ConfirmIntent, ConfirmState};
use super::widgets::editor::{EditorIntent, EditorOutcome, EditorState};
use super::widgets::picker::{PickIntent, PickItem, PickerState};
use super::widgets::statusbar::StatusLine;

/// Full-body screens. Board is the root; the rest land across stages (an
/// unbuilt screen renders a stub so navigation never dead-ends).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Screen {
    Board,
    Inbox,
    Activity,
    Members,
    Spaces,
    ConfigPanel,
    Doctor,
    Remotes,
    Log,
}

/// The right-side issue detail, co-visible with the board (NOT on the overlay
/// stack — a picker can sit over peek over board and all three render).
pub struct PeekState {
    pub view: IssueView,
    /// The issue's derived activity timeline (`Request::History`), fetched
    /// with the view.
    pub history: Vec<ActivityEvent>,
    pub scroll: u16,
    pub expanded: bool,
    pub focused: bool,
}

/// Modal layers; top of the stack owns input.
pub enum OverlayLayer {
    Editor(Box<EditorState>),
    Palette(Box<PaletteState>),
    Picker(Box<PickerState>),
    Confirm(ConfirmState),
    /// Live `/` filter input: edits `App::filter_text` keystroke-by-keystroke;
    /// Esc restores what it was on open.
    Filter {
        prev: String,
    },
    /// A minted invite: link + QR, dismissed by any key.
    Invite {
        link: String,
        qr: Option<String>,
    },
    Help,
}

/// Mouse hit-testing: regions are rebuilt every draw (base first, overlays
/// last; lookup scans backwards so the top layer eats the click).
pub struct HitRegion {
    pub rect: Rect,
    pub target: HitTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitTarget {
    ProjectTab(usize),
    SavedTab(usize),
    ColumnHeader(usize),
    BoardRow { col: usize, row: usize },
    Peek,
    ListRow(usize),
    LegendAction(Action),
}

/// The optimistic overlay: a local prediction keyed by `(doc_id, field)`,
/// cleared on any doorbell for its scope (U§4.3). Correlation-free.
#[derive(Debug, Default)]
pub struct Overlay {
    by_doc: HashMap<String, HashMap<String, String>>,
}

impl Overlay {
    pub fn set(&mut self, doc_id: &str, field: &str, value: &str) {
        self.by_doc
            .entry(doc_id.to_string())
            .or_default()
            .insert(field.to_string(), value.to_string());
    }
    pub fn clear_doc(&mut self, doc_id: &str) {
        self.by_doc.remove(doc_id);
    }
    pub fn get<'a>(&'a self, doc_id: &str, field: &str) -> Option<&'a str> {
        self.by_doc
            .get(doc_id)
            .and_then(|m| m.get(field))
            .map(|s| s.as_str())
    }
    pub fn has(&self, doc_id: &str) -> bool {
        self.by_doc.contains_key(doc_id)
    }
}

/// One selectable Members-screen row: a pending request (approvable) or an
/// existing member — the members_ui domain, merged (requests always on top).
#[derive(Clone)]
pub enum MemberItem {
    Request(JoinRequestDto),
    Member(MemberDto),
}

/// A saved view tab — persisted as JSON under the store-layer `tui.tabs` key.
/// `filter` uses the daemon's List semantics (mine/status/label — never
/// re-implemented client-side); `text` is the live client-side text filter.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SavedTab {
    pub name: String,
    #[serde(default)]
    pub filter: Filter,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
}

/// One config-panel row (key + effective value + which layer supplied it).
#[derive(Debug, Clone)]
pub struct ConfigRow {
    pub key: String,
    pub value: String,
    pub origin: &'static str,
    pub help: &'static str,
}

/// Per-list cursor + scroll window for list-shaped screens.
#[derive(Debug, Default, Clone, Copy)]
pub struct ListCursor {
    pub sel: usize,
    #[allow(dead_code)] // list windowing lands with the Stage-2 list_picker
    pub scroll: usize,
}

pub struct App {
    pub home: PathBuf,
    // ---- daemon-derived data (plain DTOs; tests construct these directly) ----
    pub projects: Vec<ProjectDto>,
    pub project_idx: usize,
    applied_default_project: bool,
    pub board: Option<BoardView>,
    pub activity: Vec<ActivityEvent>,
    pub inbox_unread: u64,
    pub inbox_entries: Vec<InboxEntry>,
    pub members: Vec<MemberDto>,
    pub member_requests: Vec<JoinRequestDto>,
    /// Request keys hidden from this session's view (`n`) — view-only; the
    /// request lives in the daemon's event ring until it ages out.
    pub dismissed_requests: HashSet<String>,
    pub spaces: Vec<WorkspaceEntry>,
    pub seeds: Vec<SeedDto>,
    pub log_events: Vec<LogEvent>,
    pub config_rows: Vec<ConfigRow>,
    pub diagnosis: Option<DiagnosisView>,
    pub peers_online: usize,
    // ---- saved view tabs (store-layer `tui.tabs`) ----
    pub tabs: Vec<SavedTab>,
    pub active_tab: Option<usize>,
    /// doc-ids matching the active tab's daemon-side filter (`Request::List`
    /// intersection — Board takes no Filter; mine/label semantics stay server
    /// truth). `None` = no active tab.
    pub tab_docs: Option<HashSet<String>>,
    /// Set by a live space switch: the run loop re-subscribes to the (new)
    /// daemon after the current event is handled.
    pub needs_resubscribe: bool,
    // ---- prediction ----
    pub overlay: Overlay,
    // ---- UI state ----
    pub screen: Screen,
    pub peek: Option<PeekState>,
    pub stack: Vec<OverlayLayer>,
    pub col_idx: usize,
    pub row_idx: usize,
    pub list_cursors: HashMap<Screen, ListCursor>,
    pub filter_text: String,
    /// Multi-select (canonical reffs, board order of insertion). Non-empty
    /// selection makes issue verbs bulk (one Request per reff, sequential).
    pub selection: Vec<String>,
    /// Cursor into the actionable `?` help overlay.
    pub help_sel: usize,
    pub theme: Theme,
    pub keymap: Keymap,
    pub regions: Vec<HitRegion>,
    pub status: StatusLine,
    /// Last mouse-down (for double-click detection — 400ms window).
    pub last_click: Option<(std::time::Instant, HitTarget)>,
    pub quit: bool,
}

impl App {
    pub fn new(home: PathBuf, theme: Theme, keymap: Keymap) -> Self {
        App {
            home,
            projects: Vec::new(),
            project_idx: 0,
            applied_default_project: false,
            board: None,
            activity: Vec::new(),
            inbox_unread: 0,
            inbox_entries: Vec::new(),
            members: Vec::new(),
            member_requests: Vec::new(),
            dismissed_requests: HashSet::new(),
            spaces: Vec::new(),
            seeds: Vec::new(),
            log_events: Vec::new(),
            config_rows: Vec::new(),
            diagnosis: None,
            peers_online: 0,
            tabs: Vec::new(),
            active_tab: None,
            tab_docs: None,
            needs_resubscribe: false,
            overlay: Overlay::default(),
            screen: Screen::Board,
            peek: None,
            stack: Vec::new(),
            col_idx: 0,
            row_idx: 0,
            list_cursors: HashMap::new(),
            filter_text: String::new(),
            selection: Vec::new(),
            help_sel: 0,
            theme,
            keymap,
            regions: Vec::new(),
            status: StatusLine::default(),
            last_click: None,
            quit: false,
        }
    }

    // ---- focus ----

    /// The input-owning context. Editor/Help layers consume raw keys before
    /// the keymap; the returned kind picks the binding table otherwise.
    pub fn focus(&self) -> FocusKind {
        if matches!(self.stack.last(), Some(OverlayLayer::Help)) {
            return FocusKind::Help;
        }
        match (self.screen, &self.peek) {
            (Screen::Board, Some(p)) if p.focused => FocusKind::Peek,
            (Screen::Board, _) => FocusKind::Board,
            // A peek opened from a list screen takes over the body — it owns
            // motion until Esc closes it.
            (_, Some(_)) => FocusKind::Peek,
            (Screen::Inbox, _) => FocusKind::Inbox,
            (Screen::Members, _) => FocusKind::Members,
            (Screen::Spaces, _) => FocusKind::Spaces,
            (Screen::ConfigPanel, _) => FocusKind::Config,
            (Screen::Remotes, _) => FocusKind::Remotes,
            _ => FocusKind::List,
        }
    }

    pub fn editor_mut(&mut self) -> Option<&mut EditorState> {
        match self.stack.last_mut() {
            Some(OverlayLayer::Editor(e)) => Some(e.as_mut()),
            _ => None,
        }
    }

    fn push_editor(&mut self, ed: EditorState) {
        self.stack.push(OverlayLayer::Editor(Box::new(ed)));
    }

    // ---- data access ----

    pub fn current_project(&self) -> Option<&ProjectDto> {
        self.projects.get(self.project_idx)
    }

    /// Rows of the focused board column, post-filter.
    pub fn column_rows(&self, col: usize) -> Vec<&Row> {
        let Some(b) = &self.board else {
            return Vec::new();
        };
        let Some(c) = b.columns.get(col) else {
            return Vec::new();
        };
        c.rows
            .iter()
            .filter(|r| self.row_matches_filter(r))
            .collect()
    }

    pub fn row_matches_filter(&self, r: &Row) -> bool {
        // Active saved tab: the daemon-side filter's doc-id set gates first.
        if let Some(docs) = &self.tab_docs {
            if !docs.contains(r.doc_id.as_str()) {
                return false;
            }
        }
        if self.filter_text.is_empty() {
            return true;
        }
        let needle = self.filter_text.to_lowercase();
        r.title.to_lowercase().contains(&needle)
            || r.reff.to_lowercase().contains(&needle)
            || r.key_alias
                .as_deref()
                .is_some_and(|a| a.to_lowercase().contains(&needle))
    }

    pub fn focused_row(&self) -> Option<Row> {
        self.column_rows(self.col_idx)
            .get(self.row_idx)
            .map(|r| (*r).clone())
    }

    /// The overlay-aware field reads (U§4.3): prediction wins until a doorbell
    /// clears it.
    pub fn effective_title(&self, r: &Row) -> String {
        self.overlay
            .get(r.doc_id.as_str(), "title")
            .map(str::to_string)
            .unwrap_or_else(|| r.title.clone())
    }
    pub fn effective_status(&self, r: &Row) -> String {
        self.overlay
            .get(r.doc_id.as_str(), "status")
            .map(str::to_string)
            .unwrap_or_else(|| r.status.clone())
    }

    pub fn clamp_selection(&mut self) {
        let ncols = self.board.as_ref().map(|b| b.columns.len()).unwrap_or(0);
        if ncols == 0 {
            self.col_idx = 0;
            self.row_idx = 0;
            return;
        }
        self.col_idx = self.col_idx.min(ncols - 1);
        let nrows = self.column_rows(self.col_idx).len();
        self.row_idx = if nrows == 0 {
            0
        } else {
            self.row_idx.min(nrows - 1)
        };
    }

    // ---- daemon round-trips ----

    pub async fn req(&self, req: Request) -> Result<Response> {
        request(&self.home, &req).await
    }

    pub async fn reload_projects(&mut self) -> Result<()> {
        if let Response::Projects { projects } = self.req(Request::ProjectList).await? {
            self.projects = projects;
            if self.project_idx >= self.projects.len() {
                self.project_idx = 0;
            }
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

    pub async fn reload_board(&mut self) -> Result<()> {
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
                self.refresh_tab_docs().await;
                self.clamp_selection();
            }
            Response::Error { message, .. } => self.status.error(message),
            _ => {}
        }
        Ok(())
    }

    /// Re-derive the active tab's doc-id set (board rows ∩ List results).
    async fn refresh_tab_docs(&mut self) {
        let Some(tab) = self.active_tab.and_then(|i| self.tabs.get(i)).cloned() else {
            self.tab_docs = None;
            return;
        };
        let project = self.current_project().map(|p| p.key.clone());
        match self
            .req(Request::List {
                project,
                filter: tab.filter.clone(),
            })
            .await
        {
            Ok(Response::List { rows }) => {
                self.tab_docs = Some(
                    rows.into_iter()
                        .map(|r| r.doc_id.as_str().to_string())
                        .collect(),
                );
            }
            _ => {
                // A failed fetch must not silently show everything under a
                // named tab — drop back to no tab, loudly.
                self.active_tab = None;
                self.tab_docs = None;
                self.status.error("tab filter fetch failed — tab cleared");
            }
        }
    }

    /// Re-fetch the peek's issue (its doc went dirty, or an edit landed).
    pub async fn refresh_peek(&mut self) -> Result<()> {
        let Some(reff) = self.peek.as_ref().map(|p| p.view.reff.clone()) else {
            return Ok(());
        };
        if let Response::Issue(v) = self.req(Request::IssueView { reff: reff.clone() }).await? {
            if let Some(p) = &mut self.peek {
                p.view = *v;
            }
        }
        let history = self.fetch_history(&reff).await;
        if let Some(p) = &mut self.peek {
            p.history = history;
        }
        Ok(())
    }

    /// The issue's derived timeline — best-effort (an empty history renders
    /// as nothing, never an error).
    async fn fetch_history(&self, reff: &str) -> Vec<ActivityEvent> {
        match self
            .req(Request::History {
                reff: reff.to_string(),
            })
            .await
        {
            Ok(Response::Activity { events, .. }) => events,
            _ => Vec::new(),
        }
    }

    pub async fn refresh_inbox_count(&mut self) {
        if let Ok(Response::Inbox { unread, .. }) = self.req(Request::Inbox { clear: false }).await
        {
            self.inbox_unread = unread;
        }
    }

    /// The full inbox (newest-first; the first `unread` entries are past the
    /// read watermark). `clear` stamps the watermark after listing.
    pub async fn reload_inbox(&mut self, clear: bool) -> Result<()> {
        if let Response::Inbox { entries, unread } = self.req(Request::Inbox { clear }).await? {
            self.inbox_entries = entries;
            self.inbox_unread = if clear { 0 } else { unread };
        }
        Ok(())
    }

    pub async fn reload_activity(&mut self) -> Result<()> {
        if let Response::Activity { events, .. } = self.req(Request::Activity { since: 0 }).await? {
            self.activity = events;
        }
        Ok(())
    }

    /// Roster + pending requests. Members are authoritative; a request-list
    /// failure (non-admin, transient) degrades to empty like members_ui.
    pub async fn reload_members(&mut self) -> Result<()> {
        match self.req(Request::Members).await? {
            Response::Members { members } => self.members = members,
            Response::Error { message, .. } => {
                self.status.error(message);
                return Ok(());
            }
            _ => {}
        }
        self.member_requests = match self.req(Request::MemberRequests).await {
            Ok(Response::JoinRequests { requests }) => requests,
            _ => Vec::new(),
        };
        Ok(())
    }

    /// The local space registry — pure file read, no daemon.
    pub fn reload_spaces(&mut self) {
        self.spaces = workspaces::list();
    }

    pub async fn reload_diagnosis(&mut self) -> Result<()> {
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

    pub async fn refresh_status_info(&mut self) {
        if let Ok(Response::Status(s)) = self.req(Request::Status).await {
            self.peers_online = s.online_peers;
        }
    }

    /// Refresh whatever the current screen shows (used on doorbell + `r`).
    pub async fn refresh_current(&mut self) -> Result<()> {
        match self.screen {
            Screen::Board => self.reload_board().await?,
            Screen::Inbox => self.reload_inbox(false).await?,
            Screen::Activity => self.reload_activity().await?,
            Screen::Members => self.reload_members().await?,
            Screen::Spaces => self.reload_spaces(),
            Screen::Doctor => self.reload_diagnosis().await?,
            Screen::ConfigPanel => self.reload_config(),
            Screen::Remotes => self.reload_seeds().await?,
            Screen::Log => self.reload_log().await?,
        }
        Ok(())
    }

    pub async fn reload_seeds(&mut self) -> Result<()> {
        match self.req(Request::SeedList).await? {
            Response::Seeds { seeds } => self.seeds = seeds,
            Response::Error { message, .. } => self.status.error(message),
            _ => {}
        }
        Ok(())
    }

    pub async fn reload_log(&mut self) -> Result<()> {
        if let Response::Events { events, .. } = self.req(Request::Log { since: 0 }).await? {
            self.log_events = events;
        }
        Ok(())
    }

    /// Effective settings, layered: every known key with value + origin, plus
    /// any set open-prefix keys (`tui.key.*`) the static table can't list.
    pub fn reload_config(&mut self) {
        let settings = crate::config::Settings::load(Some(&self.home));
        let mut rows: Vec<ConfigRow> = Vec::new();
        for spec in crate::config::KEYS {
            let (value, origin) = match (
                settings.store.get(spec.name),
                settings.global.get(spec.name),
            ) {
                (Some(v), _) => (v.to_string(), "store"),
                (None, Some(v)) => (v.to_string(), "global"),
                (None, None) => match (spec.built_in)() {
                    Some(v) => (v, "default"),
                    None => ("(unset)".to_string(), "default"),
                },
            };
            rows.push(ConfigRow {
                key: spec.name.to_string(),
                value,
                origin,
                help: spec.help,
            });
        }
        for (layer, origin) in [(&settings.store, "store"), (&settings.global, "global")] {
            let mut extras: Vec<(String, String)> = layer
                .0
                .iter()
                .filter(|(k, _)| k.starts_with("tui.key."))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            extras.sort();
            for (k, v) in extras {
                if !rows.iter().any(|r| r.key == k) {
                    rows.push(ConfigRow {
                        key: k,
                        value: v,
                        origin,
                        help: "TUI keybinding override.",
                    });
                }
            }
        }
        self.config_rows = rows;
    }

    /// Doorbell routing (U§4.2): every dirty scope refreshes exactly the
    /// panels that render it. Doorbells are dirty-notices — re-read, never
    /// patch.
    pub async fn on_doorbell(&mut self, db: Doorbell) -> Result<()> {
        if db.reset {
            self.overlay = Overlay::default();
            self.reload_projects().await?;
            self.refresh_current().await?;
            self.refresh_peek().await?;
            self.refresh_inbox_count().await;
            return Ok(());
        }
        let current_project = self
            .current_project()
            .map(|p| p.id.as_str().to_string())
            .unwrap_or_default();
        let mut board_dirty = false;
        let mut peek_dirty = false;
        let peek_doc = self
            .peek
            .as_ref()
            .map(|p| p.view.doc_id.as_str().to_string());
        for (proj, docs) in &db.dirty_by_project {
            for d in docs {
                self.overlay.clear_doc(d);
                if Some(d.as_str()) == peek_doc.as_deref() {
                    peek_dirty = true;
                }
            }
            if *proj == current_project {
                board_dirty = true;
            }
        }
        for scope in &db.dirty_catalog {
            match scope {
                CatalogScope::Projects => self.reload_projects().await?,
                CatalogScope::Workflow => board_dirty = true,
                CatalogScope::Boards { project } if *project == current_project => {
                    board_dirty = true
                }
                CatalogScope::Acl if self.screen == Screen::Members => {
                    self.reload_members().await?
                }
                _ => {}
            }
        }
        if board_dirty && self.screen == Screen::Board {
            self.reload_board().await?;
        }
        if peek_dirty {
            self.refresh_peek().await?;
        }
        if db.activity_advanced {
            self.refresh_inbox_count().await;
            match self.screen {
                Screen::Inbox => self.reload_inbox(false).await?,
                Screen::Activity => self.reload_activity().await?,
                _ => {}
            }
        }
        if db.presence_advanced {
            self.refresh_status_info().await;
            // Join requests are derived from presence announcements.
            match self.screen {
                Screen::Members => self.reload_members().await?,
                Screen::Remotes => self.reload_seeds().await?,
                Screen::Log => self.reload_log().await?,
                _ => {}
            }
        }
        Ok(())
    }

    // ---- action execution ----

    pub async fn apply(&mut self, action: Action) -> Result<()> {
        use Action::*;
        match action {
            Quit => self.quit = true,
            Back => {
                if self.stack.pop().is_some() {
                } else if self.peek.is_some() {
                    self.peek = None;
                } else if self.screen != Screen::Board {
                    self.screen = Screen::Board;
                } else {
                    self.quit = true;
                }
            }
            Help => self.stack.push(OverlayLayer::Help),
            Refresh => {
                self.refresh_current().await?;
                self.refresh_peek().await?;
            }
            Goto(s) => {
                self.screen = s;
                self.peek = None;
                self.refresh_current().await?;
            }
            NextProject | PrevProject => {
                if !self.projects.is_empty() {
                    let n = self.projects.len();
                    self.project_idx = if action == NextProject {
                        (self.project_idx + 1) % n
                    } else {
                        (self.project_idx + n - 1) % n
                    };
                    self.peek = None;
                    self.reload_board().await?;
                }
            }
            Up | Down | Left | Right | Top | Bottom => self.motion(action),
            OpenPeek => match self.screen {
                Screen::Board => self.open_peek().await?,
                Screen::Inbox => {
                    let sel = self.cursor_of(Screen::Inbox);
                    if let Some(reff) = self.inbox_entries.get(sel).map(|e| e.reff.clone()) {
                        self.open_peek_for(&reff).await?;
                    }
                }
                Screen::Activity => {
                    // The panel renders newest-first: index into the reversed feed.
                    let sel = self.cursor_of(Screen::Activity);
                    if let Some(reff) = self
                        .activity
                        .iter()
                        .rev()
                        .nth(sel)
                        .map(|e| e.reff.clone())
                        .filter(|r| !r.is_empty())
                    {
                        self.open_peek_for(&reff).await?;
                    }
                }
                Screen::ConfigPanel => {
                    let sel = self.cursor_of(Screen::ConfigPanel);
                    if let Some(row) = self.config_rows.get(sel).cloned() {
                        let initial = if row.value == "(unset)" {
                            String::new()
                        } else {
                            row.value.clone()
                        };
                        self.push_editor(EditorState::new(
                            EditorIntent::ConfigSet {
                                key: row.key.clone(),
                            },
                            format!("{}  (empty unsets · store layer)", row.key),
                            &initial,
                        ));
                    }
                }
                _ => {}
            },
            TogglePeekFocus => {
                if let Some(p) = &mut self.peek {
                    p.focused = !p.focused;
                }
            }
            ExpandPeek => {
                if let Some(p) = &mut self.peek {
                    p.expanded = !p.expanded;
                    p.focused = true;
                }
            }
            StatusPrev | StatusNext => self.status_move(action == StatusNext).await?,
            Create => self.push_editor(EditorState::new(
                EditorIntent::Create,
                "new issue   (title words, then -p KEY -P prio -l label -a who)",
                "",
            )),
            EditTitle => {
                if let Some(t) = self.target_reff() {
                    let initial = self.target_title();
                    self.push_editor(EditorState::new(
                        EditorIntent::EditTitle { reff: t },
                        "edit title",
                        &initial,
                    ));
                }
            }
            EditDescription => {
                if let Some(t) = self.target_reff() {
                    // Description lives on the full IssueView — the peek holds it.
                    let initial = self
                        .peek
                        .as_ref()
                        .map(|p| p.view.description.clone())
                        .unwrap_or_default();
                    self.push_editor(EditorState::new(
                        EditorIntent::EditDescription { reff: t },
                        "edit description",
                        &initial,
                    ));
                }
            }
            Comment => {
                if let Some(t) = self.target_reff() {
                    self.push_editor(EditorState::new(
                        EditorIntent::Comment { reff: t },
                        "comment",
                        "",
                    ));
                }
            }
            StartIssue | DoneIssue | StopIssue => {
                let targets = self.bulk_targets();
                if targets.len() > 1 {
                    let reqs: Vec<Request> = targets
                        .into_iter()
                        .map(|reff| match action {
                            StartIssue => Request::IssueStart { reff },
                            DoneIssue => Request::IssueDone { reff },
                            _ => Request::IssueStop { reff },
                        })
                        .collect();
                    self.run_bulk(reqs).await?;
                } else if let Some(reff) = targets.into_iter().next() {
                    let req = match action {
                        StartIssue => Request::IssueStart { reff },
                        DoneIssue => Request::IssueDone { reff },
                        _ => Request::IssueStop { reff },
                    };
                    match self.req(req).await? {
                        Response::Issue(v) => {
                            self.status.info(format!(
                                "{}  {}",
                                v.key_alias.as_deref().unwrap_or(&v.reff),
                                v.status
                            ));
                            if let Some(p) = &mut self.peek {
                                if p.view.doc_id == v.doc_id {
                                    p.view = *v;
                                }
                            }
                            self.reload_board().await?;
                        }
                        Response::Error { message, .. } => self.status.error(message),
                        _ => {}
                    }
                }
            }
            YankRef => {
                if let Some(reff) = self.target_reff() {
                    if crate::cli::copy_to_clipboard(&reff) {
                        self.status.info(format!("yanked {reff}"));
                    } else {
                        self.status.error("clipboard unavailable");
                    }
                }
            }
            Submit => {
                // Help overlay's "run action" lands in mod.rs (needs the
                // highlighted row); other Submits are handled by their layers.
            }
            OpenPalette => self
                .stack
                .push(OverlayLayer::Palette(Box::new(PaletteState::new()))),
            OpenFilter => self.stack.push(OverlayLayer::Filter {
                prev: self.filter_text.clone(),
            }),
            PickAssign => self.open_assign_picker().await?,
            PickLabel => self.open_label_picker().await?,
            PickPriority => self.open_priority_picker(),
            PickStatus => self.open_status_picker(),
            PickMoveProject => self.open_move_picker(),
            ToggleSelect => self.toggle_select(),
            ClearSelection => {
                self.selection.clear();
            }
            ReorderUp | ReorderDown => self.reorder(action == ReorderDown).await?,
            Delete if self.screen == Screen::Remotes => {
                let sel = self.cursor_of(Screen::Remotes);
                if let Some(s) = self.seeds.get(sel) {
                    let label = if s.nick.is_empty() {
                        s.id.chars().take(12).collect()
                    } else {
                        s.nick.clone()
                    };
                    self.stack.push(OverlayLayer::Confirm(ConfirmState {
                        title: "unpin seed".into(),
                        body: format!("Unpin {label}? It stops being dialed on startup."),
                        intent: ConfirmIntent::RemoveSeed { who: s.id.clone() },
                    }));
                }
            }
            Delete => {
                let targets = self.bulk_targets();
                if !targets.is_empty() {
                    let what = if targets.len() == 1 {
                        targets[0].clone()
                    } else {
                        format!("{} issues", targets.len())
                    };
                    self.stack.push(OverlayLayer::Confirm(ConfirmState {
                        title: "delete".into(),
                        body: format!("Delete {what}? This tombstones — history survives."),
                        intent: ConfirmIntent::DeleteIssues { targets },
                    }));
                }
            }
            InboxClear => {
                self.reload_inbox(true).await?;
                self.status.info("inbox cleared — watermark stamped");
            }
            MemberApprove => {
                if !self.is_admin() {
                    self.status.error("approving needs an admin key");
                } else if let Some(MemberItem::Request(r)) = self.selected_member_item() {
                    self.push_editor(EditorState::new(
                        EditorIntent::ApproveMember { key: r.key.clone() },
                        format!(
                            "approve {}…  — local name (optional)",
                            &r.key[..12.min(r.key.len())]
                        ),
                        "",
                    ));
                }
            }
            MemberDismiss => {
                if let Some(MemberItem::Request(r)) = self.selected_member_item() {
                    self.dismissed_requests.insert(r.key);
                    self.status
                        .info("dismissed from this view (the request lingers until it ages out)");
                }
            }
            MemberRename => {
                if let Some(item) = self.selected_member_item() {
                    let (key, current) = match item {
                        MemberItem::Request(r) => (r.key, String::new()),
                        MemberItem::Member(m) => (m.key.as_str().to_string(), m.alias),
                    };
                    self.push_editor(EditorState::new(
                        EditorIntent::RenameMember { key },
                        "local name (empty clears · never synced)",
                        &current,
                    ));
                }
            }
            MemberRemove => {
                if !self.is_admin() {
                    self.status.error("removing needs an admin key");
                } else if let Some(MemberItem::Member(m)) = self.selected_member_item() {
                    let label = if m.alias.is_empty() {
                        m.key.short()
                    } else {
                        m.alias.clone()
                    };
                    self.stack.push(OverlayLayer::Confirm(ConfirmState {
                        title: "remove member".into(),
                        body: format!("Remove {label}? This rotates the space key."),
                        intent: ConfirmIntent::RemoveMember {
                            key: m.key.as_str().to_string(),
                        },
                    }));
                }
            }
            MemberInvite => self.mint_invite().await,
            SpaceSwitch => self.space_switch().await?,
            SpaceForget => {
                if let Some(e) = self.selected_space() {
                    let label = if e.name.is_empty() {
                        e.workspace.clone()
                    } else {
                        e.name.clone()
                    };
                    self.stack.push(OverlayLayer::Confirm(ConfirmState {
                        title: "forget space".into(),
                        body: format!("Forget {label}? The store stays on disk — only the registry entry goes."),
                        intent: ConfirmIntent::ForgetSpace { sel: e.path.clone() },
                    }));
                }
            }
            SpacePrune => {
                let missing = self
                    .spaces
                    .iter()
                    .filter(|e| workspaces::presence(e) == workspaces::StorePresence::Missing)
                    .count();
                if missing == 0 {
                    self.status
                        .info("nothing to prune — every store is present");
                } else {
                    self.stack.push(OverlayLayer::Confirm(ConfirmState {
                        title: "prune spaces".into(),
                        body: format!(
                            "Drop {missing} registry entr{} whose store is gone?",
                            if missing == 1 { "y" } else { "ies" }
                        ),
                        intent: ConfirmIntent::PruneSpaces,
                    }));
                }
            }
            PinFilterAsTab => {
                if self.filter_text.is_empty() {
                    self.status.info("nothing to pin — type a `/` filter first");
                } else {
                    self.push_editor(EditorState::new(
                        EditorIntent::NameTab,
                        "name this tab",
                        &self.filter_text.clone(),
                    ));
                }
            }
            TabNext | TabPrev => {
                if self.tabs.is_empty() {
                    self.status
                        .info("no saved tabs — `/` filter then P pins one");
                } else {
                    // Cycle: none → 0 → 1 … → none (the plain board).
                    let n = self.tabs.len();
                    let next = match (self.active_tab, action == TabNext) {
                        (None, true) => Some(0),
                        (Some(i), true) if i + 1 < n => Some(i + 1),
                        (Some(_), true) => None,
                        (None, false) => Some(n - 1),
                        (Some(0), false) => None,
                        (Some(i), false) => Some(i - 1),
                    };
                    self.activate_tab(next).await?;
                }
            }
            Cancel => {}
        }
        Ok(())
    }

    /// Switch the active saved tab (None = the plain board): apply its text
    /// filter + project, then re-derive the doc-id gate.
    pub async fn activate_tab(&mut self, idx: Option<usize>) -> Result<()> {
        self.active_tab = idx;
        match idx.and_then(|i| self.tabs.get(i)).cloned() {
            Some(tab) => {
                self.filter_text = tab.text.clone().unwrap_or_default();
                if let Some(pk) = &tab.project {
                    if let Some(i) = self
                        .projects
                        .iter()
                        .position(|p| p.key.eq_ignore_ascii_case(pk))
                    {
                        self.project_idx = i;
                    }
                }
                self.status.info(format!("tab: {}", tab.name));
            }
            None => {
                self.filter_text.clear();
                self.tab_docs = None;
                self.status.info("tab: (all)");
            }
        }
        self.reload_board().await?;
        Ok(())
    }

    /// Parse the store-layer `tui.tabs` JSON into the tab list (bad JSON warns,
    /// never gates).
    pub fn load_tabs(&mut self, settings: &crate::config::Settings) {
        self.tabs = match settings.get("tui.tabs") {
            Some(json) => match serde_json::from_str::<Vec<SavedTab>>(json) {
                Ok(tabs) => tabs,
                Err(e) => {
                    self.status.error(format!("tui.tabs: bad JSON ({e})"));
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        self.active_tab = None;
        self.tab_docs = None;
    }

    /// Persist the tab list to the store-layer config (atomic ConfigMap write).
    fn save_tabs(&mut self) {
        let json = serde_json::to_string(&self.tabs).unwrap_or_else(|_| "[]".into());
        let path = crate::config::store_config_path(&self.home);
        let mut cfg = crate::config::ConfigMap::load(&path);
        cfg.set("tui.tabs", &json);
        if let Err(e) = cfg.save(&path) {
            self.status.error(format!("saving tabs failed: {e:#}"));
        }
    }

    fn motion(&mut self, action: Action) {
        use Action::*;
        // Help overlay on top: j/k move its selection.
        if matches!(self.stack.last(), Some(OverlayLayer::Help)) {
            match action {
                Down => self.help_sel = self.help_sel.saturating_add(1),
                Up => self.help_sel = self.help_sel.saturating_sub(1),
                Top => self.help_sel = 0,
                _ => {}
            }
            return;
        }
        // Peek-focused (or a peek over a list screen): j/k scroll the detail.
        let peek_owns_motion = self.screen != Screen::Board;
        if let Some(p) = &mut self.peek {
            if p.focused || peek_owns_motion {
                match action {
                    Down => p.scroll = p.scroll.saturating_add(1),
                    Up => p.scroll = p.scroll.saturating_sub(1),
                    Top => p.scroll = 0,
                    _ => {}
                }
                return;
            }
        }
        match self.screen {
            Screen::Board => {
                let ncols = self.board.as_ref().map(|b| b.columns.len()).unwrap_or(0);
                match action {
                    Down => self.row_idx = self.row_idx.saturating_add(1),
                    Up => self.row_idx = self.row_idx.saturating_sub(1),
                    Right if ncols > 0 => {
                        self.col_idx = (self.col_idx + 1).min(ncols - 1);
                    }
                    Left => self.col_idx = self.col_idx.saturating_sub(1),
                    Top => self.row_idx = 0,
                    Bottom => self.row_idx = usize::MAX, // clamped below
                    _ => {}
                }
                self.clamp_selection();
            }
            s => {
                let cur = self.list_cursors.entry(s).or_default();
                match action {
                    Down => cur.sel = cur.sel.saturating_add(1),
                    Up => cur.sel = cur.sel.saturating_sub(1),
                    Top => cur.sel = 0,
                    Bottom => cur.sel = usize::MAX,
                    _ => {}
                }
            }
        }
    }

    async fn open_peek(&mut self) -> Result<()> {
        let Some(row) = self.focused_row() else {
            return Ok(());
        };
        let reff = row.reff.clone();
        self.open_peek_for(&reff).await
    }

    /// Open the detail peek on any ref (board row, inbox entry, activity row).
    async fn open_peek_for(&mut self, reff: &str) -> Result<()> {
        match self
            .req(Request::IssueView {
                reff: reff.to_string(),
            })
            .await?
        {
            Response::Issue(v) => {
                let history = self.fetch_history(&v.reff).await;
                self.peek = Some(PeekState {
                    view: *v,
                    history,
                    scroll: 0,
                    expanded: false,
                    focused: false,
                });
            }
            Response::Error { message, .. } => self.status.error(message),
            _ => {}
        }
        Ok(())
    }

    /// The issue an action targets: the focused peek's issue when peek has
    /// focus, else the focused board row.
    pub fn target_reff(&self) -> Option<String> {
        if let Some(p) = &self.peek {
            if p.focused || self.screen != Screen::Board {
                return Some(p.view.reff.clone());
            }
        }
        self.focused_row().map(|r| r.reff)
    }

    fn target_title(&self) -> String {
        if let Some(p) = &self.peek {
            if p.focused {
                return p.view.title.clone();
            }
        }
        self.focused_row()
            .map(|r| self.effective_title(&r))
            .unwrap_or_default()
    }

    /// Move the focused issue to the prev/next workflow column (H/L):
    /// optimistic status overlay + `IssueEdit`, rolled back on error.
    async fn status_move(&mut self, next: bool) -> Result<()> {
        let Some(b) = &self.board else {
            return Ok(());
        };
        let states: Vec<String> = b.columns.iter().map(|c| c.state.id.clone()).collect();
        let Some(row) = self.focused_row() else {
            return Ok(());
        };
        let cur_status = self.effective_status(&row);
        let Some(pos) = states.iter().position(|s| *s == cur_status) else {
            return Ok(());
        };
        let target = if next {
            if pos + 1 >= states.len() {
                return Ok(());
            }
            states[pos + 1].clone()
        } else {
            if pos == 0 {
                return Ok(());
            }
            states[pos - 1].clone()
        };
        self.overlay.set(row.doc_id.as_str(), "status", &target);
        let resp = self
            .req(Request::IssueEdit {
                reff: row.reff.clone(),
                title: None,
                status: Some(target),
                priority: None,
                description: None,
            })
            .await?;
        if let Response::Error { message, .. } = resp {
            self.overlay.clear_doc(row.doc_id.as_str());
            self.status.error(message);
        }
        Ok(())
    }

    // ---- multi-select / bulk ----

    /// The issues a verb applies to: the multi-select set when non-empty,
    /// else the focused issue.
    pub fn bulk_targets(&self) -> Vec<String> {
        if !self.selection.is_empty() {
            return self.selection.clone();
        }
        self.target_reff().into_iter().collect()
    }

    fn toggle_select(&mut self) {
        let Some(row) = self.focused_row() else {
            return;
        };
        if let Some(pos) = self.selection.iter().position(|r| *r == row.reff) {
            self.selection.remove(pos);
        } else {
            self.selection.push(row.reff);
        }
        // Advance like a checkbox list.
        self.motion(Action::Down);
    }

    /// Route N requests: a single one goes through [`Self::dispatch_request`]
    /// (Candidates handling); a set runs sequentially with an ok/failed tally.
    async fn run_requests(&mut self, reqs: Vec<Request>) -> Result<()> {
        if reqs.len() == 1 && self.selection.is_empty() {
            let req = reqs.into_iter().next().unwrap();
            return self.dispatch_request(req).await;
        }
        self.run_bulk(reqs).await
    }

    /// One Request per issue, sequential (each is its own commit / activity
    /// row, S§7.1); summary like `7 ok · 1 failed`. Full success clears the
    /// selection; partial failure keeps it for a retry.
    async fn run_bulk(&mut self, reqs: Vec<Request>) -> Result<()> {
        let total = reqs.len();
        let mut ok = 0usize;
        let mut first_err: Option<String> = None;
        for r in reqs {
            match self.req(r).await {
                Ok(Response::Error { message, .. }) => {
                    if first_err.is_none() {
                        first_err = Some(message);
                    }
                }
                Ok(_) => ok += 1,
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(format!("{e:#}"));
                    }
                }
            }
        }
        let failed = total - ok;
        if failed == 0 {
            self.status.info(format!("{ok} ok"));
            self.selection.clear();
        } else {
            self.status.error(format!(
                "{ok} ok · {failed} failed — {}",
                first_err.unwrap_or_default()
            ));
        }
        self.reload_board().await?;
        self.refresh_peek().await?;
        self.refresh_inbox_count().await;
        Ok(())
    }

    // ---- the `:` palette (one grammar, two entry points — U tenet 4) ----

    /// Dispatch a palette line through the CLI grammar. A parse error reopens
    /// the palette with the line intact and the error inline.
    pub async fn run_palette(&mut self, line: String) -> Result<()> {
        let tokens = super::palette::tokenize(&line);
        if tokens.is_empty() {
            return Ok(());
        }
        let mut argv = vec!["lait".to_string()];
        argv.extend(tokens);
        let argv_ref: Vec<&str> = argv.iter().map(String::as_str).collect();
        match crate::cmdspec::parse_to_dispatch(&argv_ref) {
            Ok(crate::cmdspec::ParsedCommand::Request(r)) => self.dispatch_request(r).await?,
            Ok(crate::cmdspec::ParsedCommand::Special {
                which,
                name,
                matches,
            }) => {
                self.run_special(which, name, &matches, &argv_ref).await?;
            }
            Err(e) => {
                let first = e
                    .to_string()
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("parse error")
                    .to_string();
                self.stack
                    .push(OverlayLayer::Palette(Box::new(PaletteState::with_content(
                        &line,
                        Some(first),
                    ))));
            }
        }
        Ok(())
    }

    /// The palette's `Special` table (see cmdspec): work verbs run natively
    /// (no git-branch step in the TUI), spaces/config/invite/watch route to
    /// their native surfaces, everything process-level is honestly CLI-only.
    async fn run_special(
        &mut self,
        which: Special,
        name: &str,
        matches: &clap::ArgMatches,
        argv: &[&str],
    ) -> Result<()> {
        let opt = |id: &str| matches.try_get_one::<String>(id).ok().flatten().cloned();
        match which {
            Special::Start | Special::Done | Special::Stop => {
                // The optional positional ref is the first non-flag token
                // after the verb; flags like --no-branch are meaningless in
                // the TUI (no git step) and ignored.
                let reff = argv
                    .iter()
                    .skip(2)
                    .find(|a| !a.starts_with('-'))
                    .map(|s| s.to_string())
                    .or_else(|| self.target_reff());
                let Some(reff) = reff else {
                    self.status.error("no issue focused (or pass a ref)");
                    return Ok(());
                };
                let req = match which {
                    Special::Start => Request::IssueStart { reff },
                    Special::Done => Request::IssueDone { reff },
                    _ => Request::IssueStop { reff },
                };
                self.dispatch_request(req).await?;
            }
            Special::Id => self.dispatch_request(Request::Id).await?,
            Special::Tui => self.status.info("you're already here"),
            Special::Invite => {
                let require_approval = matches.get_flag("require_approval");
                let reusable = matches.get_flag("reusable");
                let ttl = opt("ttl_hours").and_then(|v| v.parse::<u64>().ok());
                self.mint_invite_with(require_approval, reusable, ttl).await;
            }
            Special::Watch => {
                self.screen = Screen::Log;
                self.peek = None;
                self.reload_log().await?;
            }
            Special::Workspaces => {
                self.screen = Screen::Spaces;
                self.peek = None;
                self.reload_spaces();
            }
            Special::WorkspacesForget => {
                let sel = opt("sel").unwrap_or_default();
                self.screen = Screen::Spaces;
                self.reload_spaces();
                self.stack.push(OverlayLayer::Confirm(ConfirmState {
                    title: "forget space".into(),
                    body: format!(
                        "Forget '{sel}'? The store stays on disk — only the registry entry goes."
                    ),
                    intent: ConfirmIntent::ForgetSpace { sel },
                }));
            }
            Special::WorkspacesPrune => {
                self.screen = Screen::Spaces;
                self.reload_spaces();
                self.apply(Action::SpacePrune).await?;
            }
            Special::ConfigList => {
                self.screen = Screen::ConfigPanel;
                self.peek = None;
                self.reload_config();
            }
            Special::ConfigGet => {
                let key = opt("key").unwrap_or_default();
                let settings = crate::config::Settings::load(Some(&self.home));
                match settings.get(&key) {
                    Some(v) => self.status.info(format!("{key} = {v}")),
                    None => match crate::config::key_spec(&key) {
                        Ok(spec) => match (spec.built_in)() {
                            Some(v) => self.status.info(format!("{key} = {v} (default)")),
                            None => self.status.info(format!("'{key}' is unset")),
                        },
                        Err(e) => self.status.error(e.to_string()),
                    },
                }
            }
            Special::ConfigSet => {
                let key = opt("key").unwrap_or_default();
                let value = opt("value").unwrap_or_default();
                self.config_set_store(key, Some(value)).await;
            }
            Special::ConfigUnset => {
                let key = opt("key").unwrap_or_default();
                self.config_set_store(key, None).await;
            }
            _ => self
                .status
                .error(format!("`{name}` is CLI-only — run it in a shell")),
        }
        Ok(())
    }

    /// Send a request and route the outcome: `Candidates` opens a
    /// disambiguation picker that retries with the chosen ref (UI.md §3.2);
    /// success lands a one-line summary and refreshes.
    pub async fn dispatch_request(&mut self, req: Request) -> Result<()> {
        let resp = self.req(req.clone()).await?;
        match resp {
            Response::Candidates { candidates } => {
                let items: Vec<PickItem> = candidates
                    .iter()
                    .map(|c| PickItem {
                        label: format!(
                            "{}  {}",
                            c.key_alias.clone().unwrap_or_else(|| c.reff.clone()),
                            c.title
                        ),
                        value: c.reff.clone(),
                    })
                    .collect();
                self.stack
                    .push(OverlayLayer::Picker(Box::new(PickerState::new(
                        "which issue?",
                        items,
                        PickIntent::Disambiguate {
                            retry: Box::new(req),
                        },
                        false,
                        HashSet::new(),
                    ))));
            }
            Response::Error { message, .. } => self.status.error(message),
            other => {
                self.status.info(summarize_response(&other));
                self.reload_board().await?;
                self.refresh_peek().await?;
                self.refresh_inbox_count().await;
            }
        }
        Ok(())
    }

    // ---- pickers ----

    /// The full issue view for a target — the peek's copy when it matches,
    /// else a fetch (pre-checks must reflect current truth, not a guess).
    async fn target_issue_view(&self, reff: &str) -> Option<IssueView> {
        if let Some(p) = &self.peek {
            if p.view.reff == reff {
                return Some(p.view.clone());
            }
        }
        match self
            .req(Request::IssueView {
                reff: reff.to_string(),
            })
            .await
        {
            Ok(Response::Issue(v)) => Some(*v),
            _ => None,
        }
    }

    fn picker_title(&self, verb: &str, targets: &[String]) -> String {
        if targets.len() == 1 {
            format!("{verb} {}", targets[0])
        } else {
            format!("{verb} {} issues", targets.len())
        }
    }

    async fn open_assign_picker(&mut self) -> Result<()> {
        let targets = self.bulk_targets();
        if targets.is_empty() {
            return Ok(());
        }
        let members = match self.req(Request::Members).await? {
            Response::Members { members } => members,
            Response::Error { message, .. } => {
                self.status.error(message);
                return Ok(());
            }
            _ => Vec::new(),
        };
        let items: Vec<PickItem> = members
            .iter()
            .map(|mb| {
                let name = if mb.alias.is_empty() {
                    mb.key.short()
                } else {
                    mb.alias.clone()
                };
                PickItem {
                    label: format!("{name}{}", if mb.me { "  (you)" } else { "" }),
                    value: mb.key.as_str().to_string(),
                }
            })
            .collect();
        let mut precheck = HashSet::new();
        if targets.len() == 1 {
            if let Some(v) = self.target_issue_view(&targets[0]).await {
                precheck = v.assignees.iter().map(|u| u.as_str().to_string()).collect();
            }
        }
        let title = self.picker_title("assign", &targets);
        self.stack
            .push(OverlayLayer::Picker(Box::new(PickerState::new(
                title,
                items,
                PickIntent::Assign { targets },
                true,
                precheck,
            ))));
        Ok(())
    }

    async fn open_label_picker(&mut self) -> Result<()> {
        let targets = self.bulk_targets();
        if targets.is_empty() {
            return Ok(());
        }
        let labels = match self.req(Request::LabelList).await? {
            Response::Labels { labels } => labels,
            Response::Error { message, .. } => {
                self.status.error(message);
                return Ok(());
            }
            _ => Vec::new(),
        };
        if labels.is_empty() {
            self.status
                .info("no labels yet — create one via `:` (label REF +name)");
            return Ok(());
        }
        let items: Vec<PickItem> = labels
            .iter()
            .map(|l| PickItem {
                label: l.name.clone(),
                value: l.name.clone(),
            })
            .collect();
        let mut precheck = HashSet::new();
        if targets.len() == 1 {
            if let Some(v) = self.target_issue_view(&targets[0]).await {
                precheck = v.label_names.iter().cloned().collect();
            }
        }
        let title = self.picker_title("label", &targets);
        self.stack
            .push(OverlayLayer::Picker(Box::new(PickerState::new(
                title,
                items,
                PickIntent::Label { targets },
                true,
                precheck,
            ))));
        Ok(())
    }

    fn open_status_picker(&mut self) {
        let targets = self.bulk_targets();
        let Some(b) = &self.board else {
            return;
        };
        if targets.is_empty() {
            return;
        }
        let items: Vec<PickItem> = b
            .columns
            .iter()
            .map(|c| PickItem {
                label: c.state.name.clone(),
                value: c.state.id.clone(),
            })
            .collect();
        let title = self.picker_title("status", &targets);
        self.stack
            .push(OverlayLayer::Picker(Box::new(PickerState::new(
                title,
                items,
                PickIntent::Status { targets },
                false,
                HashSet::new(),
            ))));
    }

    fn open_priority_picker(&mut self) {
        let targets = self.bulk_targets();
        if targets.is_empty() {
            return;
        }
        let items: Vec<PickItem> = [
            Priority::None,
            Priority::Low,
            Priority::Medium,
            Priority::High,
            Priority::Urgent,
        ]
        .iter()
        .map(|p| PickItem {
            label: p.as_str().to_string(),
            value: p.as_str().to_string(),
        })
        .collect();
        let title = self.picker_title("priority", &targets);
        self.stack
            .push(OverlayLayer::Picker(Box::new(PickerState::new(
                title,
                items,
                PickIntent::Priority { targets },
                false,
                HashSet::new(),
            ))));
    }

    fn open_move_picker(&mut self) {
        let targets = self.bulk_targets();
        if targets.is_empty() || self.projects.is_empty() {
            return;
        }
        let items: Vec<PickItem> = self
            .projects
            .iter()
            .map(|p| PickItem {
                label: format!("{}  {}", p.key, p.name),
                value: p.key.clone(),
            })
            .collect();
        let title = self.picker_title("move", &targets);
        self.stack
            .push(OverlayLayer::Picker(Box::new(PickerState::new(
                title,
                items,
                PickIntent::MoveProject { targets },
                false,
                HashSet::new(),
            ))));
    }

    /// Execute a submitted picker (the layer is already popped).
    pub async fn submit_picker(&mut self, p: PickerState) -> Result<()> {
        match p.intent.clone() {
            PickIntent::Disambiguate { retry } => {
                if let Some(it) = p.selected() {
                    let req = substitute_reff(*retry, &it.value);
                    self.dispatch_request(req).await?;
                }
            }
            PickIntent::Status { targets } => {
                let Some(value) = p.selected().map(|i| i.value.clone()) else {
                    return Ok(());
                };
                let mut reqs = Vec::new();
                for reff in &targets {
                    if let Some(doc) = self.doc_id_for_reff(reff) {
                        self.overlay.set(&doc, "status", &value);
                    }
                    reqs.push(Request::IssueEdit {
                        reff: reff.clone(),
                        title: None,
                        status: Some(value.clone()),
                        priority: None,
                        description: None,
                    });
                }
                self.run_requests(reqs).await?;
            }
            PickIntent::Priority { targets } => {
                let Some(value) = p.selected().map(|i| i.value.clone()) else {
                    return Ok(());
                };
                let reqs = targets
                    .iter()
                    .map(|reff| Request::IssueEdit {
                        reff: reff.clone(),
                        title: None,
                        status: None,
                        priority: Some(value.clone()),
                        description: None,
                    })
                    .collect();
                self.run_requests(reqs).await?;
            }
            PickIntent::MoveProject { targets } => {
                let Some(value) = p.selected().map(|i| i.value.clone()) else {
                    return Ok(());
                };
                let reqs = targets
                    .iter()
                    .map(|reff| Request::IssueMove {
                        reff: reff.clone(),
                        project: Some(value.clone()),
                        pos: None,
                    })
                    .collect();
                self.run_requests(reqs).await?;
            }
            PickIntent::Assign { targets } => {
                let added: Vec<String> = p.checked.difference(&p.precheck).cloned().collect();
                let removed: Vec<String> = p.precheck.difference(&p.checked).cloned().collect();
                let mut reqs = Vec::new();
                if targets.len() == 1 {
                    if !added.is_empty() {
                        reqs.push(Request::Assign {
                            reff: targets[0].clone(),
                            who: added,
                            add: true,
                        });
                    }
                    if !removed.is_empty() {
                        reqs.push(Request::Assign {
                            reff: targets[0].clone(),
                            who: removed,
                            add: false,
                        });
                    }
                } else {
                    // Bulk assign is add-only: removing from N issues you
                    // can't see the current assignees of would be a guess.
                    let who: Vec<String> = p.checked.iter().cloned().collect();
                    if !who.is_empty() {
                        for reff in &targets {
                            reqs.push(Request::Assign {
                                reff: reff.clone(),
                                who: who.clone(),
                                add: true,
                            });
                        }
                    }
                }
                if reqs.is_empty() {
                    self.status.info("no changes");
                    return Ok(());
                }
                self.run_requests(reqs).await?;
            }
            PickIntent::Label { targets } => {
                let added: Vec<String> = p.checked.difference(&p.precheck).cloned().collect();
                let removed: Vec<String> = p.precheck.difference(&p.checked).cloned().collect();
                let mut reqs = Vec::new();
                if targets.len() == 1 {
                    if !added.is_empty() || !removed.is_empty() {
                        reqs.push(Request::Label {
                            reff: targets[0].clone(),
                            add: added,
                            remove: removed,
                        });
                    }
                } else {
                    let add: Vec<String> = p.checked.iter().cloned().collect();
                    if !add.is_empty() {
                        for reff in &targets {
                            reqs.push(Request::Label {
                                reff: reff.clone(),
                                add: add.clone(),
                                remove: Vec::new(),
                            });
                        }
                    }
                }
                if reqs.is_empty() {
                    self.status.info("no changes");
                    return Ok(());
                }
                self.run_requests(reqs).await?;
            }
        }
        Ok(())
    }

    /// Execute a confirmed destructive action (the layer is already popped).
    pub async fn run_confirm(&mut self, intent: ConfirmIntent) -> Result<()> {
        match intent {
            ConfirmIntent::DeleteIssues { targets } => {
                if self
                    .peek
                    .as_ref()
                    .is_some_and(|pk| targets.contains(&pk.view.reff))
                {
                    self.peek = None;
                }
                let reqs: Vec<Request> = targets
                    .into_iter()
                    .map(|reff| Request::IssueDelete { reff })
                    .collect();
                self.run_requests(reqs).await?;
            }
            ConfirmIntent::RemoveMember { key } => {
                match self.req(Request::MemberRemove { who: key }).await? {
                    Response::Error { message, .. } => self.status.error(message),
                    _ => {
                        self.status.info("removed — space key rotated");
                        self.reload_members().await?;
                    }
                }
            }
            ConfirmIntent::ForgetSpace { sel } => match workspaces::forget(&sel) {
                Ok(removed) => {
                    self.status.info(format!(
                        "forgot {} entr{} (stores stay on disk)",
                        removed.len(),
                        if removed.len() == 1 { "y" } else { "ies" }
                    ));
                    self.reload_spaces();
                }
                Err(e) => self.status.error(format!("forget failed: {e:#}")),
            },
            ConfirmIntent::RemoveSeed { who } => {
                match self.req(Request::SeedRemove { who }).await? {
                    Response::Error { message, .. } => self.status.error(message),
                    _ => {
                        self.status.info("seed unpinned");
                        self.reload_seeds().await?;
                    }
                }
            }
            ConfirmIntent::PruneSpaces => match workspaces::prune() {
                Ok(removed) => {
                    self.status.info(format!(
                        "pruned {} dead entr{}",
                        removed.len(),
                        if removed.len() == 1 { "y" } else { "ies" }
                    ));
                    self.reload_spaces();
                }
                Err(e) => self.status.error(format!("prune failed: {e:#}")),
            },
        }
        Ok(())
    }

    // ---- members / spaces (Stage 3 screens) ----

    /// The current list cursor for a screen (0 when never moved).
    pub fn cursor_of(&self, s: Screen) -> usize {
        self.list_cursors.get(&s).map(|c| c.sel).unwrap_or(0)
    }

    /// Flattened, dismissal-filtered Members rows: requests first.
    pub fn member_items(&self) -> Vec<MemberItem> {
        let mut items = Vec::new();
        for r in &self.member_requests {
            if !self.dismissed_requests.contains(&r.key) {
                items.push(MemberItem::Request(r.clone()));
            }
        }
        for m in &self.members {
            items.push(MemberItem::Member(m.clone()));
        }
        items
    }

    pub fn selected_member_item(&self) -> Option<MemberItem> {
        let items = self.member_items();
        let sel = self
            .cursor_of(Screen::Members)
            .min(items.len().saturating_sub(1));
        items.into_iter().nth(sel)
    }

    /// Whether this node holds an admin key — gates approve/remove/invite so
    /// a plain member isn't offered chores the ACL will reject.
    pub fn is_admin(&self) -> bool {
        self.members.iter().any(|m| m.me && m.role == "admin")
    }

    /// Mint an invite (default = Pattern A: single-use, auto-admit, 7-day),
    /// copy the link, and pop the QR overlay — the TUI `lait invite`.
    async fn mint_invite(&mut self) {
        self.mint_invite_with(false, false, None).await;
    }

    async fn mint_invite_with(
        &mut self,
        require_approval: bool,
        reusable: bool,
        ttl_hours: Option<u64>,
    ) {
        if !self.is_admin() && !self.members.is_empty() {
            self.status.error("inviting needs an admin key");
            return;
        }
        let req = Request::Invite {
            require_approval,
            reusable,
            ttl_hours,
        };
        match self.req(req).await {
            Ok(Response::Text { text }) => {
                let token = text.trim().to_string();
                let link = token
                    .parse::<crate::proto::WorkspaceTicket>()
                    .map(|t| t.link())
                    .unwrap_or_else(|_| token.clone());
                let copied = crate::cli::copy_to_clipboard(&link);
                let qr = crate::cli::render_qr(&link).ok();
                self.stack.push(OverlayLayer::Invite { link, qr });
                self.status.info(if copied {
                    "invite link copied — any key closes"
                } else {
                    "invite minted (clipboard unavailable) — any key closes"
                });
            }
            Ok(Response::Error { message, .. }) => {
                self.status.error(format!("invite failed: {message}"))
            }
            Ok(_) => self.status.error("invite failed: unexpected response"),
            Err(e) => self.status.error(format!("invite failed: {e:#}")),
        }
    }

    /// Write (or, with `None`, unset) a key in the store-layer config file,
    /// then make it real: ConfigReload for daemon-read keys, live theme /
    /// keymap / tabs re-application for `tui.*` keys.
    pub async fn config_set_store(&mut self, key: String, value: Option<String>) {
        let spec = match crate::config::key_spec(&key) {
            Ok(s) => s,
            Err(e) => {
                self.status.error(e.to_string());
                return;
            }
        };
        let path = crate::config::store_config_path(&self.home);
        let mut cfg = crate::config::ConfigMap::load(&path);
        let message = match &value {
            Some(v) => {
                cfg.set(&key, v);
                format!("{key} = {v}")
            }
            None => {
                if !cfg.unset(&key) {
                    self.status
                        .error(format!("'{key}' was not set in the store layer"));
                    return;
                }
                format!("unset {key}")
            }
        };
        if let Err(e) = cfg.save(&path) {
            self.status.error(format!("config write failed: {e:#}"));
            return;
        }
        if spec.daemon_read {
            let _ = self.req(Request::ConfigReload).await;
        }
        if key.starts_with("tui.") {
            // Live re-application — a TUI setting must never wait for restart.
            let settings = crate::config::Settings::load(Some(&self.home));
            self.theme = Theme::load(&settings);
            let mut km = Keymap::defaults();
            for w in km.apply_overrides(&settings) {
                self.status.error(w);
            }
            self.keymap = km;
            self.load_tabs(&settings);
        }
        self.reload_config();
        self.status.info(message);
    }

    pub fn selected_space(&self) -> Option<&WorkspaceEntry> {
        let sel = self
            .cursor_of(Screen::Spaces)
            .min(self.spaces.len().saturating_sub(1));
        self.spaces.get(sel)
    }

    /// Live space switch, commit-last: nothing of the current session is torn
    /// down until the new daemon is up and answering `Status`. On success the
    /// app rebinds (DTOs cleared, settings/theme reloaded from the new store)
    /// and the run loop re-subscribes.
    async fn space_switch(&mut self) -> Result<()> {
        let Some(e) = self.selected_space().cloned() else {
            return Ok(());
        };
        let new_home = PathBuf::from(&e.path);
        if new_home == self.home {
            self.status.info("already in this space");
            return Ok(());
        }
        if workspaces::presence(&e) == workspaces::StorePresence::Missing {
            self.status
                .error("that store is gone from disk — `P` prunes dead entries");
            return Ok(());
        }
        self.status.info("connecting…");
        if let Err(err) = crate::cli::ensure_daemon(&new_home).await {
            self.status
                .error(format!("switch aborted — daemon didn't start: {err:#}"));
            return Ok(());
        }
        match request(&new_home, &Request::Status).await {
            Ok(Response::Status(_)) => {}
            Ok(Response::Error { message, .. }) => {
                self.status.error(format!("switch aborted — {message}"));
                return Ok(());
            }
            Ok(_) | Err(_) => {
                self.status
                    .error("switch aborted — the new daemon isn't answering");
                return Ok(());
            }
        }
        // Committed: rebind everything to the new store.
        let label = if e.name.is_empty() {
            e.workspace.clone()
        } else {
            e.name.clone()
        };
        self.rebind(new_home).await?;
        self.status.info(format!("switched to {label}"));
        Ok(())
    }

    /// Point the app at a new store: wipe session state, reload settings
    /// (theme + keymap overrides come from the NEW store), re-pull everything,
    /// and flag the run loop to re-subscribe (first frame is a Reset — U§4.1).
    async fn rebind(&mut self, new_home: PathBuf) -> Result<()> {
        self.home = new_home;
        let settings = crate::config::Settings::load(Some(&self.home));
        self.theme = Theme::load(&settings);
        let mut km = Keymap::defaults();
        let warnings = km.apply_overrides(&settings);
        self.keymap = km;
        for w in warnings {
            self.status.error(w);
        }
        self.load_tabs(&settings);
        self.projects.clear();
        self.project_idx = 0;
        self.applied_default_project = false;
        self.board = None;
        self.activity.clear();
        self.inbox_entries.clear();
        self.inbox_unread = 0;
        self.members.clear();
        self.member_requests.clear();
        self.dismissed_requests.clear();
        self.diagnosis = None;
        self.overlay = Overlay::default();
        self.peek = None;
        self.stack.clear();
        self.selection.clear();
        self.filter_text.clear();
        self.list_cursors.clear();
        self.col_idx = 0;
        self.row_idx = 0;
        self.screen = Screen::Board;
        self.needs_resubscribe = true;
        self.reload_projects().await?;
        self.reload_board().await?;
        self.refresh_inbox_count().await;
        self.refresh_status_info().await;
        self.reload_spaces();
        Ok(())
    }

    // ---- reorder (J/K, UI.md §5.1) ----

    /// Swap the focused card with its column neighbor: optimistic local swap,
    /// then `IssueMove` anchored on the neighbor; an error reloads.
    async fn reorder(&mut self, down: bool) -> Result<()> {
        let (reff, anchor, my_doc, other_doc, other_idx) = {
            let rows = self.column_rows(self.col_idx);
            let n = rows.len();
            if n < 2 {
                return Ok(());
            }
            let cur = self.row_idx.min(n - 1);
            if (down && cur + 1 >= n) || (!down && cur == 0) {
                return Ok(());
            }
            let other = if down { cur + 1 } else { cur - 1 };
            (
                rows[cur].reff.clone(),
                rows[other].reff.clone(),
                rows[cur].doc_id.clone(),
                rows[other].doc_id.clone(),
                other,
            )
        };
        if let Some(b) = &mut self.board {
            if let Some(col) = b.columns.get_mut(self.col_idx) {
                let i = col.rows.iter().position(|x| x.doc_id == my_doc);
                let j = col.rows.iter().position(|x| x.doc_id == other_doc);
                if let (Some(i), Some(j)) = (i, j) {
                    col.rows.swap(i, j);
                }
            }
        }
        self.row_idx = other_idx;
        let pos = if down {
            BoardPos::After { reff: anchor }
        } else {
            BoardPos::Before { reff: anchor }
        };
        let resp = self
            .req(Request::IssueMove {
                reff,
                project: None,
                pos: Some(pos),
            })
            .await?;
        if let Response::Error { message, .. } = resp {
            self.status.error(message);
            self.reload_board().await?;
        }
        Ok(())
    }

    fn doc_id_for_reff(&self, reff: &str) -> Option<String> {
        if let Some(b) = &self.board {
            for c in &b.columns {
                for r in &c.rows {
                    if r.reff == reff {
                        return Some(r.doc_id.as_str().to_string());
                    }
                }
            }
        }
        if let Some(p) = &self.peek {
            if p.view.reff == reff {
                return Some(p.view.doc_id.as_str().to_string());
            }
        }
        None
    }

    /// Submit an editor layer's content (the intent→Request mapping carried
    /// over from the old modal, plus quick-create through the CLI grammar).
    pub async fn submit_editor(&mut self, intent: EditorIntent, content: String) -> Result<()> {
        let content_trimmed = content.trim();
        // Non-issue intents complete here (their refresh isn't the board).
        match &intent {
            EditorIntent::NameTab => {
                if content_trimmed.is_empty() {
                    return Ok(());
                }
                let tab = SavedTab {
                    name: content_trimmed.to_string(),
                    filter: Filter::default(),
                    text: Some(self.filter_text.clone()).filter(|t| !t.is_empty()),
                    project: self.current_project().map(|p| p.key.clone()),
                };
                self.tabs.push(tab);
                self.save_tabs();
                let idx = self.tabs.len() - 1;
                self.activate_tab(Some(idx)).await?;
                self.status
                    .info(format!("pinned '{content_trimmed}' — [ ] cycles tabs"));
                return Ok(());
            }
            EditorIntent::ConfigSet { key } => {
                let value = Some(content_trimmed.to_string()).filter(|v| !v.is_empty());
                self.config_set_store(key.clone(), value).await;
                return Ok(());
            }
            EditorIntent::ApproveMember { key } => {
                let as_name = Some(content_trimmed.to_string()).filter(|s| !s.is_empty());
                let req = Request::MemberApprove {
                    who: key.clone(),
                    as_name,
                };
                match self.req(req).await? {
                    Response::Error { message, .. } => self.status.error(message),
                    _ => {
                        self.status.info("approved — space key sealed to them");
                        self.reload_members().await?;
                    }
                }
                return Ok(());
            }
            EditorIntent::RenameMember { key } => {
                let cleared = content_trimmed.is_empty();
                let req = Request::MemberAlias {
                    who: key.clone(),
                    name: content_trimmed.to_string(),
                };
                match self.req(req).await? {
                    Response::Error { message, .. } => self.status.error(message),
                    _ => {
                        self.status.info(if cleared {
                            "local name cleared"
                        } else {
                            "renamed"
                        });
                        self.reload_members().await?;
                    }
                }
                return Ok(());
            }
            _ => {}
        }
        let req = match &intent {
            EditorIntent::Create => {
                if content_trimmed.is_empty() {
                    return Ok(());
                }
                // The quick-create line IS `new`'s grammar (U§6): tokenize and
                // parse through cmdspec so -p/-a/-P/-l/-b mean exactly what
                // they mean in a shell.
                let mut argv: Vec<String> = vec!["lait".to_string(), "new".to_string()];
                let tokens = super::palette::tokenize(content_trimmed);
                // Bare leading words are the title; collect until the first
                // flag token, then pass the rest through.
                let mut title_words = Vec::new();
                let mut rest = Vec::new();
                let mut in_flags = false;
                for t in tokens {
                    if t.starts_with('-') {
                        in_flags = true;
                    }
                    if in_flags {
                        rest.push(t);
                    } else {
                        title_words.push(t);
                    }
                }
                argv.push(title_words.join(" "));
                argv.extend(rest);
                let argv_ref: Vec<&str> = argv.iter().map(String::as_str).collect();
                match crate::cmdspec::parse_to_dispatch(&argv_ref) {
                    Ok(crate::cmdspec::ParsedCommand::Request(r)) => r,
                    Ok(_) => return Ok(()),
                    Err(e) => {
                        // Reopen the editor with the content intact and the
                        // clap error inline — a typo must never eat the line.
                        let mut ed = EditorState::new(
                            EditorIntent::Create,
                            "new issue   (title words, then -p KEY -P prio -l label -a who)",
                            content_trimmed,
                        );
                        ed.error = Some(e.to_string().lines().next().unwrap_or("").to_string());
                        self.push_editor(ed);
                        return Ok(());
                    }
                }
            }
            EditorIntent::EditTitle { reff } => {
                if content_trimmed.is_empty() {
                    return Ok(());
                }
                if let Some(row) = self.focused_row() {
                    self.overlay
                        .set(row.doc_id.as_str(), "title", content_trimmed);
                }
                Request::IssueEdit {
                    reff: reff.clone(),
                    title: Some(content_trimmed.to_string()),
                    status: None,
                    priority: None,
                    description: None,
                }
            }
            EditorIntent::EditDescription { reff } => Request::IssueEdit {
                reff: reff.clone(),
                title: None,
                status: None,
                priority: None,
                description: Some(content.trim_end().to_string()),
            },
            EditorIntent::Comment { reff } => {
                if content_trimmed.is_empty() {
                    return Ok(());
                }
                Request::Comment {
                    reff: reff.clone(),
                    body: content.trim_end().to_string(),
                }
            }
            // Handled in the pre-pass above (non-issue paths).
            EditorIntent::NameTab
            | EditorIntent::ConfigSet { .. }
            | EditorIntent::ApproveMember { .. }
            | EditorIntent::RenameMember { .. } => return Ok(()),
        };
        match self.req(req).await? {
            Response::Ref { reff } => {
                self.status.info(reff);
                self.reload_board().await?;
                self.refresh_peek().await?;
            }
            Response::Error { message, .. } => {
                self.status.error(message);
                // Roll back any optimistic prediction for the edited doc.
                if let Some(row) = self.focused_row() {
                    self.overlay.clear_doc(row.doc_id.as_str());
                }
            }
            _ => {
                self.reload_board().await?;
                self.refresh_peek().await?;
            }
        }
        Ok(())
    }

    /// Feed a key to the top editor layer. Returns `Some((intent, content))`
    /// on submit (the layer is popped); `None` while typing or on cancel.
    pub fn handle_editor_key(
        &mut self,
        ev: crossterm::event::KeyEvent,
    ) -> Option<(EditorIntent, String)> {
        let outcome = match self.stack.last_mut() {
            Some(OverlayLayer::Editor(e)) => e.handle_key(ev),
            _ => return None,
        };
        match outcome {
            EditorOutcome::Consumed => None,
            EditorOutcome::Cancel => {
                self.stack.pop();
                None
            }
            EditorOutcome::Submit(content) => match self.stack.pop() {
                Some(OverlayLayer::Editor(e)) => Some((e.intent, content)),
                _ => None,
            },
        }
    }

    /// Feed a key to the top palette layer; `Some(line)` on submit (popped).
    pub fn handle_palette_key(&mut self, ev: crossterm::event::KeyEvent) -> Option<String> {
        use super::palette::PaletteOutcome;
        let outcome = match self.stack.last_mut() {
            Some(OverlayLayer::Palette(p)) => p.handle_key(ev),
            _ => return None,
        };
        match outcome {
            PaletteOutcome::Consumed => None,
            PaletteOutcome::Cancel => {
                self.stack.pop();
                None
            }
            PaletteOutcome::Submit(line) => {
                self.stack.pop();
                Some(line)
            }
        }
    }

    /// Feed a key to the top picker layer; `Some(state)` on submit (popped).
    pub fn handle_picker_key(&mut self, ev: crossterm::event::KeyEvent) -> Option<PickerState> {
        use super::widgets::picker::PickerOutcome;
        let outcome = match self.stack.last_mut() {
            Some(OverlayLayer::Picker(p)) => p.handle_key(ev),
            _ => return None,
        };
        match outcome {
            PickerOutcome::Consumed => None,
            PickerOutcome::Cancel => {
                self.stack.pop();
                None
            }
            PickerOutcome::Submit => match self.stack.pop() {
                Some(OverlayLayer::Picker(p)) => Some(*p),
                _ => None,
            },
        }
    }

    /// Feed a key to the top confirm layer; `Some(intent)` on yes (popped).
    pub fn handle_confirm_key(&mut self, ev: crossterm::event::KeyEvent) -> Option<ConfirmIntent> {
        use super::widgets::confirm::ConfirmOutcome;
        let outcome = match self.stack.last_mut() {
            Some(OverlayLayer::Confirm(c)) => c.handle_key(ev),
            _ => return None,
        };
        match outcome {
            ConfirmOutcome::Consumed => None,
            ConfirmOutcome::No => {
                self.stack.pop();
                None
            }
            ConfirmOutcome::Yes => match self.stack.pop() {
                Some(OverlayLayer::Confirm(c)) => Some(c.intent),
                _ => None,
            },
        }
    }

    /// The `/` filter edits `filter_text` live; Enter keeps it, Esc restores.
    pub fn handle_filter_key(&mut self, ev: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match ev.code {
            KeyCode::Esc => {
                if let Some(OverlayLayer::Filter { prev }) = self.stack.pop() {
                    self.filter_text = prev;
                }
                self.clamp_selection();
            }
            KeyCode::Enter => {
                self.stack.pop();
            }
            KeyCode::Backspace => {
                self.filter_text.pop();
                self.clamp_selection();
            }
            KeyCode::Char(c) => {
                self.filter_text.push(c);
                self.clamp_selection();
            }
            _ => {}
        }
    }
}

/// Rebuild a request with its ref swapped for the disambiguated canonical one
/// (retry path of `Response::Candidates`). Requests without a ref pass through.
pub fn substitute_reff(req: Request, new: &str) -> Request {
    let reff = new.to_string();
    match req {
        Request::IssueEdit {
            title,
            status,
            priority,
            description,
            ..
        } => Request::IssueEdit {
            reff,
            title,
            status,
            priority,
            description,
        },
        Request::IssueMove { project, pos, .. } => Request::IssueMove { reff, project, pos },
        Request::Assign { who, add, .. } => Request::Assign { reff, who, add },
        Request::Label { add, remove, .. } => Request::Label { reff, add, remove },
        Request::Comment { body, .. } => Request::Comment { reff, body },
        Request::IssueDelete { .. } => Request::IssueDelete { reff },
        Request::IssueStart { .. } => Request::IssueStart { reff },
        Request::IssueDone { .. } => Request::IssueDone { reff },
        Request::IssueStop { .. } => Request::IssueStop { reff },
        Request::IssueView { .. } => Request::IssueView { reff },
        Request::History { .. } => Request::History { reff },
        other => other,
    }
}

/// One status-line summary per response shape (the palette's success line).
pub fn summarize_response(resp: &Response) -> String {
    match resp {
        Response::Ok { message } => message.clone().unwrap_or_else(|| "ok".into()),
        Response::Ref { reff } => format!("✓ {reff}"),
        Response::Issue(v) => format!(
            "{}  {}",
            v.key_alias.as_deref().unwrap_or(&v.reff),
            v.status
        ),
        Response::List { rows } => format!("{} issue(s)", rows.len()),
        Response::Board(b) => format!(
            "{}: {} issue(s)",
            b.project.key,
            b.columns.iter().map(|c| c.rows.len()).sum::<usize>()
        ),
        Response::Activity { events, .. } => format!("{} event(s)", events.len()),
        Response::Inbox { unread, .. } => format!("{unread} unread"),
        Response::Projects { projects } => format!("{} project(s)", projects.len()),
        Response::Labels { labels } => format!("{} label(s)", labels.len()),
        Response::Members { members } => format!("{} member(s)", members.len()),
        Response::JoinRequests { requests } => format!("{} pending request(s)", requests.len()),
        Response::Seeds { seeds } => format!("{} seed(s)", seeds.len()),
        Response::Status(s) => format!("{} peer(s) online", s.online_peers),
        Response::Diagnosis(d) => d.summary.clone(),
        Response::Text { text } => text.lines().next().unwrap_or("").to_string(),
        Response::Events { events, .. } => format!("{} event(s)", events.len()),
        Response::Who { peers } => format!("{} peer(s)", peers.len()),
        Response::Candidates { .. } | Response::Error { .. } => String::new(),
    }
}
