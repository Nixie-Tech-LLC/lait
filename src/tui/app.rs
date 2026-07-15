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
use crate::control::{request, BoardPos, CatalogScope, Doorbell, Request, Response};
use crate::diagnose::DiagnosisView;
use crate::dto::{ActivityEvent, BoardView, IssueView, Priority, ProjectDto, Row};

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
    #[allow(dead_code)] // the Activity screen renders these in Stage 3
    pub activity: Vec<ActivityEvent>,
    pub inbox_unread: u64,
    pub diagnosis: Option<DiagnosisView>,
    pub peers_online: usize,
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
            diagnosis: None,
            peers_online: 0,
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
                self.clamp_selection();
            }
            Response::Error { message, .. } => self.status.error(message),
            _ => {}
        }
        Ok(())
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
            Screen::Doctor => self.reload_diagnosis().await?,
            // Later-stage screens refresh once they hold data.
            _ => {}
        }
        Ok(())
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
        }
        if db.presence_advanced {
            self.refresh_status_info().await;
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
            OpenPeek => self.open_peek().await?,
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
            // Stage 3/4 actions — visible in help, honest about arrival.
            InboxClear | SpaceSwitch | PinFilterAsTab | TabNext | TabPrev | Cancel => {
                self.status.info(format!(
                    "'{}' lands later in this branch (stage 3+)",
                    action.id()
                ));
            }
        }
        Ok(())
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
        // Peek-focused: j/k scroll the detail.
        if let Some(p) = &mut self.peek {
            if p.focused {
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
        match self
            .req(Request::IssueView {
                reff: row.reff.clone(),
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
            Ok(crate::cmdspec::ParsedCommand::Special { which, name, .. }) => {
                self.run_special(which, name, &argv_ref).await?;
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
    /// (no git-branch step in the TUI), screens that exist route, everything
    /// process-level is honestly CLI-only.
    async fn run_special(&mut self, which: Special, name: &str, argv: &[&str]) -> Result<()> {
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
            Special::Invite => self
                .status
                .error("the invite panel lands in stage 4 — run `lait invite` in a shell"),
            Special::Watch => self
                .status
                .error("the log screen lands in stage 4 — run `lait watch` in a shell"),
            Special::Workspaces | Special::WorkspacesForget | Special::WorkspacesPrune => self
                .status
                .error("the spaces screen lands in stage 3 — run `lait spaces` in a shell"),
            Special::ConfigGet
            | Special::ConfigSet
            | Special::ConfigUnset
            | Special::ConfigList => self
                .status
                .error("the config panel lands in stage 4 — run `lait config` in a shell"),
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
        }
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
            EditorIntent::NameTab => return Ok(()), // Stage 4
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
