//! The inbox (S§8.1) — remote changes **addressed to you**, newest-first.
//! The first `unread` entries sit past the read watermark and render accented;
//! `C` clears (stamps the watermark), `Enter` peeks the issue.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget, Screen};
use super::super::util::ago;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let n = app.inbox_entries.len();
    let sel = app.cursor_of(Screen::Inbox).min(n.saturating_sub(1));
    if let Some(c) = app.list_cursors.get_mut(&Screen::Inbox) {
        c.sel = sel;
    }
    let unread = app.inbox_unread as usize;

    let mut lines: Vec<Line> = Vec::new();
    if n == 0 {
        lines.push(Line::styled(
            "  (inbox zero — nothing addressed to you)",
            app.theme.dim_style(),
        ));
    }
    let visible = area.height.saturating_sub(2) as usize;
    let start = sel.saturating_sub(visible.saturating_sub(1));
    // Rows are materialized before regions (immutable borrow of entries).
    struct RowSrc {
        idx: usize,
        when: String,
        kind: String,
        head: String,
        detail: String,
        is_unread: bool,
    }
    let rows: Vec<RowSrc> = app
        .inbox_entries
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, e)| {
            let who = e.actor_nick.clone().filter(|s| !s.is_empty());
            let kind = match (e.kind.as_str(), who) {
                ("comment", Some(w)) => format!("{w} commented"),
                (k, _) => k.to_string(),
            };
            RowSrc {
                idx: i,
                when: ago(e.ts),
                kind,
                head: format!("{}  {}", e.reff, e.title),
                detail: e.detail.clone(),
                is_unread: i < unread,
            }
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
        } else if r.is_unread {
            app.theme.accent_style()
        } else {
            app.theme.dim_style()
        };
        let marker = if r.is_unread { "● " } else { "  " };
        lines.push(Line::from(vec![
            Span::styled(format!("{marker}{:<9} ", r.when), base),
            Span::styled(format!("{:<18} ", r.kind), base),
            Span::styled(r.head, base),
            Span::styled(format!("  — {}", r.detail), app.theme.dim_style()),
        ]));
    }
    let title = if unread > 0 {
        format!(" inbox — {unread} unread ")
    } else {
        " inbox ".to_string()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(title);
    f.render_widget(Paragraph::new(lines).block(block), area);
}
