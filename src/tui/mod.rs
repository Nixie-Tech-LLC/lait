//! The `lait tui` full-screen client (U§4–§6): board-centric with a right-side
//! detail peek, a semantic action system (keys, mouse, legend, and the
//! actionable `?` help all project from the same keymap tables), theme-driven
//! styling, and doorbell-routed live refresh. A thin Layer-B client — the
//! daemon owns the docs; this renders `Response` snapshots and reacts to
//! `Doorbell` dirty-notices (never patches from them).

mod action;
mod app;
mod event;
pub mod keymap;
mod palette;
mod panels;
mod theme;
mod util;
pub(crate) mod widgets;

use std::io::Stdout;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event as CEvent, EventStream,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use n0_future::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};

use crate::cli::ensure_daemon;
use crate::control::Subscription;

use app::{App, HitRegion, HitTarget, OverlayLayer, Screen};
use keymap::{FocusKind, Keymap};
use theme::Theme;

/// Restore the terminal exactly once, from wherever teardown happens first —
/// the RAII guard, the panic hook, or both racing a crash.
static RESTORED: AtomicBool = AtomicBool::new(false);

fn restore_terminal_once() {
    if RESTORED.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = disable_raw_mode();
    let _ = execute!(
        std::io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    );
}

/// RAII terminal lifecycle. A panic inside raw mode used to wreck the shell;
/// the hook restores BEFORE the default hook prints, so the message is
/// readable and the terminal usable.
struct TerminalGuard;

impl TerminalGuard {
    fn init() -> Result<Terminal<CrosstermBackend<Stdout>>> {
        RESTORED.store(false, Ordering::SeqCst);
        enable_raw_mode()?;
        // Mouse/paste capture are progressive enhancements: a console that
        // rejects them still gets the full keyboard client.
        let _ = execute!(
            std::io::stdout(),
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableBracketedPaste
        );
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_terminal_once();
            hook(info);
        }));
        Ok(Terminal::new(CrosstermBackend::new(std::io::stdout()))?)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal_once();
    }
}

/// Launch the TUI. Auto-spawns the daemon like the CLI.
pub async fn run(home: &Path) -> Result<()> {
    ensure_daemon(home).await?;

    let settings = crate::config::Settings::load(Some(home));
    let theme = Theme::load(&settings);
    let mut km = Keymap::defaults();
    let warnings = km.apply_overrides(&settings);

    let mut app = App::new(home.to_path_buf(), theme, km);
    for w in warnings {
        app.status.error(w);
    }
    app.reload_projects().await?;
    app.reload_board().await?;
    app.refresh_inbox_count().await;
    app.refresh_status_info().await;

    let guard = TerminalGuard;
    let mut terminal = TerminalGuard::init()?;
    let mut sub = crate::control::subscribe(home, 0).await.ok();
    let mut events = EventStream::new();
    let res = run_loop(&mut terminal, &mut app, &mut sub, &mut events).await;
    drop(guard);
    res
}

async fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    sub: &mut Option<Subscription>,
    events: &mut EventStream,
) -> Result<()> {
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    loop {
        terminal.draw(|f| draw(f, app))?;
        if app.quit {
            return Ok(());
        }
        tokio::select! {
            _ = tick.tick() => {
                app.refresh_status_info().await;
                app.status.tick();
            }
            ev = events.next() => match ev {
                Some(Ok(CEvent::Key(k))) => event::dispatch_key(app, k).await?,
                Some(Ok(CEvent::Mouse(m))) => event::dispatch_mouse(app, m).await?,
                Some(Ok(CEvent::Paste(s))) => {
                    if let Some(ed) = app.editor_mut() {
                        ed.handle_paste(&s);
                    }
                }
                Some(Ok(_)) => {}          // resize redraws on the next loop
                Some(Err(_)) | None => return Ok(()),
            },
            db = next_doorbell(sub) => {
                match db {
                    Some(db) => app.on_doorbell(db).await?,
                    None => {
                        // stream ended (daemon restart) — re-subscribe with
                        // backoff; the first frame is a Reset, which
                        // rebaselines everything (U§4.1).
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        *sub = crate::control::subscribe(&app.home, 0).await.ok();
                    }
                }
            }
        }
    }
}

async fn next_doorbell(sub: &mut Option<Subscription>) -> Option<crate::control::Doorbell> {
    match sub {
        Some(s) => s.next().await.ok().flatten(),
        // No subscription: park forever so the select's other arms drive.
        None => std::future::pending().await,
    }
}

fn draw(f: &mut Frame, app: &mut App) {
    app.regions.clear();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header: project tabs · screen · badges
            Constraint::Min(1),    // body
            Constraint::Length(1), // legend / status
        ])
        .split(f.area());

    draw_header(f, app, chunks[0]);
    draw_body(f, app, chunks[1]);

    let ctx = match app.focus() {
        FocusKind::Help => event::underlying_ctx(app),
        other => other,
    };
    widgets::statusbar::draw(f, app, chunks[2], ctx);

    // Overlay stack renders in order (later layers' regions are pushed last,
    // so the backwards hit-scan gives them clicks first). The stack is taken
    // out so layer draw fns can borrow `app` for theme + regions.
    let body = chunks[1];
    let mut stack = std::mem::take(&mut app.stack);
    for layer in &mut stack {
        match layer {
            OverlayLayer::Help => {
                let hctx = event::underlying_ctx(app);
                panels::help::draw(f, app, body, hctx);
            }
            OverlayLayer::Editor(ed) => {
                let theme = app.theme;
                ed.draw(f, body, &theme);
            }
            OverlayLayer::Palette(p) => p.draw(f, app, body),
            OverlayLayer::Picker(p) => p.draw(f, app, body),
            OverlayLayer::Confirm(c) => c.draw(f, app, body),
            OverlayLayer::Filter { .. } => {} // rendered by the status bar
        }
    }
    app.stack = stack;
}

fn draw_header(f: &mut Frame, app: &mut App, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    let mut x = area.x;
    // Project tabs — each a hit region; the active one tinted by its color.
    for (i, p) in app.projects.iter().enumerate() {
        let label = format!(" {} ", p.key);
        let w = label.chars().count() as u16;
        let active = i == app.project_idx;
        let style = if active {
            let accent = theme::parse_color(&p.color).unwrap_or(app.theme.accent);
            ratatui::style::Style::default()
                .fg(accent)
                .add_modifier(ratatui::style::Modifier::BOLD | ratatui::style::Modifier::REVERSED)
        } else {
            app.theme.dim_style()
        };
        spans.push(Span::styled(label, style));
        x += w;
    }
    // Regions pushed separately (spans built above borrow app.projects).
    let mut rx = area.x;
    let widths: Vec<u16> = app
        .projects
        .iter()
        .map(|p| format!(" {} ", p.key).chars().count() as u16)
        .collect();
    for (i, w) in widths.into_iter().enumerate() {
        app.regions.push(HitRegion {
            rect: Rect {
                x: rx,
                y: area.y,
                width: w,
                height: 1,
            },
            target: HitTarget::ProjectTab(i),
        });
        rx += w;
    }
    let _ = x;
    // Right side: screen name, sync, inbox badge.
    let screen = match app.screen {
        Screen::Board => "board",
        Screen::Inbox => "inbox",
        Screen::Activity => "activity",
        Screen::Members => "members",
        Screen::Spaces => "spaces",
        Screen::ConfigPanel => "config",
        Screen::Doctor => "doctor",
        Screen::Remotes => "remotes",
        Screen::Log => "log",
    };
    spans.push(Span::styled(format!("  [{screen}]"), app.theme.dim_style()));
    let sync = if app.peers_online > 0 {
        Span::styled(
            format!("  ⇅ {} peer(s)", app.peers_online),
            ratatui::style::Style::default().fg(app.theme.ok),
        )
    } else {
        Span::styled("  ○ offline".to_string(), app.theme.dim_style())
    };
    spans.push(sync);
    if app.inbox_unread > 0 {
        spans.push(Span::styled(
            format!("  inbox {}", app.inbox_unread),
            app.theme.accent_style(),
        ));
    }
    if !app.selection.is_empty() {
        spans.push(Span::styled(
            format!("  ▣ {} selected", app.selection.len()),
            app.theme.accent_style(),
        ));
    }
    if !app.filter_text.is_empty() {
        spans.push(Span::styled(
            format!("  /{}", app.filter_text),
            app.theme.accent_style(),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_body(f: &mut Frame, app: &mut App, area: Rect) {
    match app.screen {
        Screen::Board => {
            let peek_open = app.peek.is_some();
            let expanded = app.peek.as_ref().is_some_and(|p| p.expanded);
            if peek_open && expanded {
                panels::peek::draw(f, app, area);
            } else if peek_open && area.width >= 70 {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
                    .split(area);
                let board_focused = !app.peek.as_ref().is_some_and(|p| p.focused);
                panels::board::draw(f, app, chunks[0], board_focused);
                panels::peek::draw(f, app, chunks[1]);
            } else if peek_open {
                // Narrow terminal: peek takes over; Esc returns to the board.
                panels::peek::draw(f, app, area);
            } else {
                panels::board::draw(f, app, area, true);
            }
        }
        Screen::Doctor => panels::doctor::draw(f, app, area),
        s => {
            // Later-stage screens: honest stubs, never dead-ends.
            let name = format!("{s:?}").to_lowercase();
            f.render_widget(
                Paragraph::new(format!(
                    "({name} arrives later on this branch — esc returns to the board)"
                ))
                .style(app.theme.dim_style()),
                area,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{BoardColumn, BoardView, Priority, Row, WorkflowState, SCHEMA_VERSION};
    use crate::ids::{DocId, ProjectId, SystemUlidSource};
    use ratatui::backend::TestBackend;

    fn row(title: &str, status: &str, alias: &str) -> Row {
        Row {
            reff: format!("iss_{alias}"),
            key_alias: Some(alias.to_string()),
            doc_id: DocId::mint(&SystemUlidSource),
            project_id: ProjectId::mint(&SystemUlidSource),
            title: title.to_string(),
            status: status.to_string(),
            priority: Priority::High,
            assignee_summary: "you".into(),
            tombstone: false,
            provisional: false,
        }
    }

    fn fixture() -> App {
        let mut app = App::new(
            std::path::PathBuf::from("."),
            Theme::dark(),
            Keymap::defaults(),
        );
        app.projects = vec![crate::dto::ProjectDto {
            id: ProjectId::mint(&SystemUlidSource),
            name: "Demo".into(),
            key: "DEMO".into(),
            color: "blue".into(),
        }];
        app.board = Some(BoardView {
            schema_version: SCHEMA_VERSION,
            project: app.projects[0].clone(),
            columns: vec![
                BoardColumn {
                    state: WorkflowState {
                        id: "backlog".into(),
                        name: "Backlog".into(),
                        category: crate::dto::StatusCategory::Backlog,
                        color: "gray".into(),
                    },
                    rows: vec![row("fix login race", "backlog", "DEMO-1")],
                },
                BoardColumn {
                    state: WorkflowState {
                        id: "in_progress".into(),
                        name: "In Progress".into(),
                        category: crate::dto::StatusCategory::Active,
                        color: "blue".into(),
                    },
                    rows: vec![row("flaky reconnect", "in_progress", "DEMO-2")],
                },
            ],
        });
        app
    }

    fn rendered(app: &mut App) -> String {
        let mut term = Terminal::new(TestBackend::new(140, 40)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        term.backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn board_renders_columns_cards_and_legend() {
        let mut app = fixture();
        let out = rendered(&mut app);
        assert!(out.contains("Backlog (1)"), "column title with count");
        assert!(out.contains("DEMO-1"), "card handle");
        assert!(out.contains("fix login race"), "card title");
        assert!(out.contains("[c] new"), "legend projects from the keymap");
        assert!(out.contains("DEMO"), "project tab");
    }

    #[test]
    fn peek_co_renders_beside_the_board() {
        let mut app = fixture();
        app.peek = Some(app::PeekState {
            view: crate::dto::IssueView {
                schema_version: SCHEMA_VERSION,
                reff: "iss_DEMO-2".into(),
                doc_id: DocId::mint(&SystemUlidSource),
                workspace_id: crate::ids::WorkspaceId::mint(&SystemUlidSource),
                project_id: app.projects[0].id.clone(),
                project_key: Some("DEMO".into()),
                key_alias: Some("DEMO-2".into()),
                title: "flaky reconnect".into(),
                description: "reconnect storm when the laptop sleeps".into(),
                status: "in_progress".into(),
                priority: Priority::High,
                assignees: vec![],
                labels: vec![],
                label_names: vec!["net".into()],
                comments: vec![],
                created_by: crate::ids::UserId::from_key_string("a".repeat(64)),
                created_at: 0,
                provisional: false,
            },
            history: Vec::new(),
            scroll: 0,
            expanded: false,
            focused: false,
        });
        let out = rendered(&mut app);
        assert!(out.contains("Backlog (1)"), "board still visible");
        assert!(
            out.contains("reconnect storm when the laptop sleeps"),
            "peek shows the description"
        );
        assert!(out.contains(" net "), "label chip");
    }

    #[test]
    fn optimistic_overlay_marks_and_wins() {
        let mut app = fixture();
        let doc = app.board.as_ref().unwrap().columns[0].rows[0]
            .doc_id
            .as_str()
            .to_string();
        app.overlay.set(&doc, "title", "predicted title");
        let out = rendered(&mut app);
        assert!(out.contains("predicted title"), "overlay title wins");
        assert!(out.contains("▲"), "optimistic badge renders");
    }

    #[test]
    fn filter_hides_non_matching_rows() {
        let mut app = fixture();
        app.filter_text = "reconnect".into();
        let out = rendered(&mut app);
        assert!(out.contains("flaky reconnect"));
        assert!(!out.contains("fix login race"));
        assert!(out.contains("Backlog (0)"), "counts reflect the filter");
    }

    #[test]
    fn help_overlay_lists_actionable_bindings() {
        let mut app = fixture();
        app.stack.push(OverlayLayer::Help);
        let out = rendered(&mut app);
        assert!(out.contains("enter runs the highlighted action"));
        assert!(out.contains("start"), "work-state verbs discoverable");
    }

    #[test]
    fn palette_overlay_renders_suggestions() {
        let mut app = fixture();
        app.stack.push(OverlayLayer::Palette(
            Box::new(palette::PaletteState::new()),
        ));
        let out = rendered(&mut app);
        assert!(out.contains(": command"), "palette title");
        assert!(out.contains("tab complete"), "hint line");
        assert!(out.contains("board"), "top-level verbs listed");
    }

    #[test]
    fn picker_overlay_renders_marks_and_filter() {
        use widgets::picker::{PickIntent, PickItem, PickerState};
        let mut app = fixture();
        let mut checked = std::collections::HashSet::new();
        checked.insert("k1".to_string());
        app.stack
            .push(OverlayLayer::Picker(Box::new(PickerState::new(
                "assign DEMO-1",
                vec![
                    PickItem {
                        label: "alice".into(),
                        value: "k1".into(),
                    },
                    PickItem {
                        label: "bob".into(),
                        value: "k2".into(),
                    },
                ],
                PickIntent::Assign {
                    targets: vec!["iss_DEMO-1".into()],
                },
                true,
                checked,
            ))));
        let out = rendered(&mut app);
        assert!(out.contains("assign DEMO-1"));
        assert!(out.contains("▣ alice"), "pre-checked assignee");
        assert!(out.contains("☐ bob"), "unchecked member");
        assert!(out.contains("space toggle"));
    }

    #[test]
    fn selection_marks_cards_and_header_badge() {
        let mut app = fixture();
        futures_lite_block_on(async {
            app.apply(action::Action::ToggleSelect).await.unwrap();
        });
        assert_eq!(app.selection, vec!["iss_DEMO-1".to_string()]);
        assert_eq!(app.bulk_targets(), vec!["iss_DEMO-1".to_string()]);
        let out = rendered(&mut app);
        assert!(out.contains("▣ DEMO-1"), "card carries the mark");
        assert!(out.contains("1 selected"), "header badge");
    }

    #[test]
    fn filter_layer_takes_over_the_statusbar() {
        let mut app = fixture();
        app.stack.push(OverlayLayer::Filter {
            prev: String::new(),
        });
        app.filter_text = "rec".into();
        let out = rendered(&mut app);
        assert!(out.contains("enter keep"), "filter input hint");
        assert!(!out.contains("[c] new"), "legend hidden while editing");
    }

    #[test]
    fn delete_asks_for_confirmation() {
        let mut app = fixture();
        futures_lite_block_on(async {
            app.apply(action::Action::Delete).await.unwrap();
        });
        let out = rendered(&mut app);
        assert!(out.contains("Delete iss_DEMO-1?"), "{out}");
        assert!(out.contains("y confirm"));
    }

    #[test]
    fn substitute_reff_swaps_only_the_ref() {
        use crate::control::Request;
        let req = Request::Label {
            reff: "amb".into(),
            add: vec!["bug".into()],
            remove: vec![],
        };
        match app::substitute_reff(req, "iss_9") {
            Request::Label { reff, add, .. } => {
                assert_eq!(reff, "iss_9");
                assert_eq!(add, vec!["bug".to_string()]);
            }
            _ => panic!("variant preserved"),
        }
        match app::substitute_reff(Request::ProjectList, "iss_9") {
            Request::ProjectList => {}
            _ => panic!("ref-less requests pass through"),
        }
    }

    #[test]
    fn peek_history_section_renders() {
        let mut app = fixture();
        app.peek = Some(app::PeekState {
            view: crate::dto::IssueView {
                schema_version: SCHEMA_VERSION,
                reff: "iss_DEMO-1".into(),
                doc_id: DocId::mint(&SystemUlidSource),
                workspace_id: crate::ids::WorkspaceId::mint(&SystemUlidSource),
                project_id: app.projects[0].id.clone(),
                project_key: Some("DEMO".into()),
                key_alias: Some("DEMO-1".into()),
                title: "fix login race".into(),
                description: String::new(),
                status: "backlog".into(),
                priority: Priority::High,
                assignees: vec![],
                labels: vec![],
                label_names: vec![],
                comments: vec![],
                created_by: crate::ids::UserId::from_key_string("a".repeat(64)),
                created_at: 0,
                provisional: false,
            },
            history: vec![crate::dto::ActivityEvent {
                seq: 1,
                doc_id: None,
                reff: "iss_DEMO-1".into(),
                kind: "edit".into(),
                changes: vec![],
                actor: None,
                actor_nick: "mira".into(),
                text: "status backlog → in_progress".into(),
                ts: 0,
                collision: true,
            }],
            scroll: 0,
            expanded: false,
            focused: false,
        });
        let out = rendered(&mut app);
        assert!(out.contains("history"), "timeline section title");
        assert!(out.contains("status backlog → in_progress"));
        assert!(out.contains("mira"));
        assert!(out.contains("⚠"), "collision marker");
    }

    #[test]
    fn quit_via_action_and_esc_pops_layers_in_order() {
        let mut app = fixture();
        app.stack.push(OverlayLayer::Help);
        futures_lite_block_on(async {
            app.apply(action::Action::Back).await.unwrap();
            assert!(app.stack.is_empty(), "esc pops the overlay first");
            app.apply(action::Action::Back).await.unwrap();
            assert!(app.quit, "esc at the board root quits");
        });
    }

    /// Minimal executor for the couple of async App methods tests poke that
    /// never actually await IO on these paths.
    fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }
}
