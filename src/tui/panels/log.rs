//! The log screen — the daemon's presence/system event ring (`Request::Log`),
//! newest first, tailed live off `presence_advanced` doorbells. The TUI's
//! `lait watch`.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::super::app::{App, Screen};
use super::super::util::ago;
use crate::control::EventKind;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let n = app.log_events.len();
    let sel = app.cursor_of(Screen::Log).min(n.saturating_sub(1));
    if let Some(c) = app.list_cursors.get_mut(&Screen::Log) {
        c.sel = sel;
    }

    let mut lines: Vec<Line> = Vec::new();
    if n == 0 {
        lines.push(Line::styled(
            "  (no events yet — joins and presence changes land here live)",
            app.theme.dim_style(),
        ));
    }
    let visible = area.height.saturating_sub(2) as usize;
    let start = sel.saturating_sub(visible.saturating_sub(1));
    for (i, e) in app
        .log_events
        .iter()
        .rev()
        .enumerate()
        .skip(start)
        .take(visible)
    {
        let base = if i == sel {
            app.theme.selection()
        } else {
            ratatui::style::Style::default()
        };
        let (glyph, color) = match e.kind {
            EventKind::Join => ("⇥", app.theme.accent),
            EventKind::Presence => ("◉", app.theme.ok),
            EventKind::System => ("⚙", app.theme.dim),
        };
        let who = if e.nick.is_empty() {
            e.id.chars().take(12).collect()
        } else {
            e.nick.clone()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<9} ", ago(e.ts)), app.theme.dim_style()),
            Span::styled(
                format!("{glyph} "),
                ratatui::style::Style::default().fg(color),
            ),
            Span::styled(format!("{who:<16} "), app.theme.accent_style()),
            Span::styled(e.text.clone(), base),
        ]));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(" log — presence & system events, newest first ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}
