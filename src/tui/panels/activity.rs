//! The workspace-wide activity feed (`Request::Activity`) — everything, not
//! just what's addressed to you (that's the inbox). LWW collision notes (A§9)
//! surface as ⚠; `Enter` peeks the issue.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget, Screen};
use super::super::util::ago;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    // Newest first for reading; the DTO arrives oldest-first by seq.
    let n = app.activity.len();
    let sel = app.cursor_of(Screen::Activity).min(n.saturating_sub(1));
    if let Some(c) = app.list_cursors.get_mut(&Screen::Activity) {
        c.sel = sel;
    }

    let mut lines: Vec<Line> = Vec::new();
    if n == 0 {
        lines.push(Line::styled("  (no activity yet)", app.theme.dim_style()));
    }
    let visible = area.height.saturating_sub(2) as usize;
    let start = sel.saturating_sub(visible.saturating_sub(1));
    struct RowSrc {
        idx: usize,
        when: String,
        actor: String,
        reff: String,
        text: String,
        collision: bool,
    }
    let rows: Vec<RowSrc> = app
        .activity
        .iter()
        .rev()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, e)| RowSrc {
            idx: i,
            when: ago(e.ts),
            actor: e.actor_nick.clone(),
            reff: e.reff.clone(),
            text: e.text.clone(),
            collision: e.collision,
        })
        .collect();
    for r in rows {
        app.regions.push(HitRegion {
            rect: Rect {
                x: area.x + 1,
                y: area.y + 1 + (lines.len() as u16),
                width: area.width.saturating_sub(2),
                height: 1,
            },
            target: HitTarget::ListRow(r.idx),
        });
        let base = if r.idx == sel {
            app.theme.selection()
        } else {
            ratatui::style::Style::default()
        };
        let mut spans = vec![Span::styled(
            format!("  {:<9} ", r.when),
            app.theme.dim_style(),
        )];
        if r.collision {
            spans.push(Span::styled(
                "⚠ ",
                ratatui::style::Style::default().fg(app.theme.warn),
            ));
        }
        if !r.actor.is_empty() {
            spans.push(Span::styled(
                format!("{} ", r.actor),
                app.theme.accent_style(),
            ));
        }
        spans.push(Span::styled(
            format!("{}  ", r.reff),
            app.theme.accent_style(),
        ));
        spans.push(Span::styled(r.text, base));
        lines.push(Line::from(spans));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(" activity — the whole space, newest first ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}
