//! crossterm events → semantic [`Action`]s. Input-consuming layers (editor,
//! palette, picker, confirm, filter) eat raw keys before the keymap;
//! everything else resolves through the per-context binding tables. Mouse
//! lands on the render-time hit regions (overlays win): tabs, column headers,
//! rows (double-click peeks), legend chips; the wheel scrolls the panel under
//! the cursor.

use anyhow::Result;
use crossterm::event::{KeyEvent, KeyEventKind, MouseEvent, MouseEventKind};

use super::action::Action;
use super::app::{App, HitTarget, OverlayLayer};
use super::keymap::FocusKind;
use super::panels::help;

pub async fn dispatch_key(app: &mut App, ev: KeyEvent) -> Result<()> {
    if ev.kind != KeyEventKind::Press {
        return Ok(());
    }
    // Input layers consume raw keys before the keymap (top of stack owns
    // input); each handler pops on submit and returns what to execute.
    match app.stack.last() {
        Some(OverlayLayer::Editor(_)) => {
            if let Some((intent, content)) = app.handle_editor_key(ev) {
                app.submit_editor(intent, content).await?;
            }
            return Ok(());
        }
        Some(OverlayLayer::Palette(_)) => {
            if let Some(line) = app.handle_palette_key(ev) {
                app.run_palette(line).await?;
            }
            return Ok(());
        }
        Some(OverlayLayer::Picker(_)) => {
            if let Some(p) = app.handle_picker_key(ev) {
                app.submit_picker(p).await?;
            }
            return Ok(());
        }
        Some(OverlayLayer::Confirm(_)) => {
            if let Some(intent) = app.handle_confirm_key(ev) {
                app.run_confirm(intent).await?;
            }
            return Ok(());
        }
        Some(OverlayLayer::Filter { .. }) => {
            app.handle_filter_key(ev);
            return Ok(());
        }
        Some(OverlayLayer::Invite { .. }) => {
            app.stack.pop();
            return Ok(());
        }
        Some(OverlayLayer::Help) | None => {}
    }
    let ctx = app.focus();
    let Some(action) = app.keymap.resolve(ctx, &ev) else {
        return Ok(());
    };
    // The help overlay's Enter runs the highlighted action in the underlying
    // context (actionable help): pop, then apply.
    if ctx == FocusKind::Help && action == Action::Submit {
        let rows = help::entries(app, underlying_ctx(app));
        let sel = app.help_sel.min(rows.len().saturating_sub(1));
        if let Some((_, _, chosen)) = rows.get(sel) {
            let chosen = *chosen;
            app.stack.pop();
            app.help_sel = 0;
            return Box::pin(app.apply(chosen)).await;
        }
        return Ok(());
    }
    app.apply(action).await
}

/// The context the help overlay describes (what's under it).
pub fn underlying_ctx(app: &App) -> FocusKind {
    use super::app::Screen;
    match (app.screen, &app.peek) {
        (Screen::Board, Some(p)) if p.focused => FocusKind::Peek,
        (Screen::Board, _) => FocusKind::Board,
        (_, Some(_)) => FocusKind::Peek,
        (Screen::Inbox, _) => FocusKind::Inbox,
        (Screen::Members, _) => FocusKind::Members,
        (Screen::Spaces, _) => FocusKind::Spaces,
        (Screen::ConfigPanel, _) => FocusKind::Config,
        (Screen::Remotes, _) => FocusKind::Remotes,
        _ => FocusKind::List,
    }
}

pub async fn dispatch_mouse(app: &mut App, ev: MouseEvent) -> Result<()> {
    match ev.kind {
        MouseEventKind::Down(_) => {
            let target = app
                .regions
                .iter()
                .rev()
                .find(|r| contains(r.rect, ev.column, ev.row))
                .map(|r| r.target);
            // Modal layers eat clicks: rows act, everything else is inert.
            match app.stack.last_mut() {
                Some(OverlayLayer::Palette(p)) => {
                    if let Some(HitTarget::ListRow(i)) = target {
                        p.sel = i;
                        p.complete();
                    }
                    return Ok(());
                }
                Some(OverlayLayer::Picker(p)) => {
                    if let Some(HitTarget::ListRow(i)) = target {
                        p.sel = i;
                        if p.multi {
                            p.toggle_selected();
                        } else if let Some(OverlayLayer::Picker(p)) = app.stack.pop() {
                            // Single-select: a click IS the pick.
                            Box::pin(app.submit_picker(*p)).await?;
                        }
                    }
                    return Ok(());
                }
                Some(OverlayLayer::Editor(_)) | Some(OverlayLayer::Confirm(_)) => {
                    return Ok(());
                }
                Some(OverlayLayer::Invite { .. }) => {
                    app.stack.pop();
                    return Ok(());
                }
                _ => {}
            }
            // Double-click detection (400ms, same target).
            let now = std::time::Instant::now();
            let double = matches!(
                (app.last_click, target),
                (Some((t, prev)), Some(cur))
                    if prev == cur && now.duration_since(t).as_millis() <= 400
            );
            app.last_click = target.map(|t| (now, t));
            match target {
                Some(HitTarget::ProjectTab(i)) => {
                    if i != app.project_idx && i < app.projects.len() {
                        app.project_idx = i;
                        app.peek = None;
                        app.reload_board().await?;
                    }
                }
                Some(HitTarget::ColumnHeader(c)) => {
                    app.col_idx = c;
                    app.clamp_selection();
                }
                Some(HitTarget::SavedTab(i)) => {
                    // Click toggles: active tab clicked again = back to (all).
                    let next = if app.active_tab == Some(i) {
                        None
                    } else {
                        Some(i)
                    };
                    app.activate_tab(next).await?;
                }
                Some(HitTarget::BoardRow { col, row }) => {
                    app.col_idx = col;
                    app.row_idx = row;
                    app.clamp_selection();
                    if let Some(p) = &mut app.peek {
                        p.focused = false;
                    }
                    if double {
                        Box::pin(app.apply(Action::OpenPeek)).await?;
                    }
                }
                Some(HitTarget::Peek) => {
                    if let Some(p) = &mut app.peek {
                        p.focused = true;
                    }
                }
                Some(HitTarget::LegendAction(a)) => Box::pin(app.apply(a)).await?,
                Some(HitTarget::ListRow(i)) => {
                    if matches!(app.stack.last(), Some(OverlayLayer::Help)) {
                        app.help_sel = i;
                    } else {
                        let s = app.screen;
                        app.list_cursors.entry(s).or_default().sel = i;
                        if double {
                            Box::pin(app.apply(Action::OpenPeek)).await?;
                        }
                    }
                }
                None => {}
            }
        }
        MouseEventKind::ScrollDown | MouseEventKind::ScrollUp => {
            let down = ev.kind == MouseEventKind::ScrollDown;
            // A picker on top: the wheel moves its selection.
            if let Some(OverlayLayer::Picker(p)) = app.stack.last_mut() {
                let n = p.filtered().len();
                if down {
                    if n > 0 && p.sel + 1 < n {
                        p.sel += 1;
                    }
                } else {
                    p.sel = p.sel.saturating_sub(1);
                }
                return Ok(());
            }
            // Scroll the panel UNDER the cursor: peek if hit, else the board.
            let over_peek = app
                .regions
                .iter()
                .rev()
                .find(|r| contains(r.rect, ev.column, ev.row))
                .is_some_and(|r| r.target == HitTarget::Peek);
            if over_peek {
                if let Some(p) = &mut app.peek {
                    p.scroll = if down {
                        p.scroll.saturating_add(2)
                    } else {
                        p.scroll.saturating_sub(2)
                    };
                }
            } else {
                app.apply(if down { Action::Down } else { Action::Up })
                    .await?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn contains(rect: ratatui::layout::Rect, x: u16, y: u16) -> bool {
    x >= rect.x && x < rect.x + rect.width && y >= rect.y && y < rect.y + rect.height
}
