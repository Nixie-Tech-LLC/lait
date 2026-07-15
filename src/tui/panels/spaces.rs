//! The Spaces screen — the machine-wide registry (`workspaces.json`),
//! newest-opened first. `Enter` switches live (commit-last: nothing is torn
//! down until the new daemon answers), `f` forgets an entry, `P` prunes
//! entries whose store is gone.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget, Screen};
use super::super::util::ago;
use crate::workspaces::{presence, StorePresence};

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let n = app.spaces.len();
    let sel = app.cursor_of(Screen::Spaces).min(n.saturating_sub(1));
    if let Some(c) = app.list_cursors.get_mut(&Screen::Spaces) {
        c.sel = sel;
    }

    let mut lines: Vec<Line> = Vec::new();
    if n == 0 {
        lines.push(Line::styled(
            "  (no spaces registered — `lait init` or `lait join <link>`)",
            app.theme.dim_style(),
        ));
    }
    let visible = area.height.saturating_sub(2) as usize;
    let start = sel.saturating_sub(visible.saturating_sub(1));
    struct RowSrc {
        idx: usize,
        current: bool,
        missing: bool,
        name: String,
        origin: String,
        opened: String,
        path: String,
        projects: String,
    }
    let home = app.home.clone();
    let rows: Vec<RowSrc> = app
        .spaces
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, e)| RowSrc {
            idx: i,
            current: std::path::Path::new(&e.path) == home,
            missing: presence(e) == StorePresence::Missing,
            name: if e.name.is_empty() {
                e.workspace.clone()
            } else {
                e.name.clone()
            },
            origin: e.origin.to_string(),
            opened: ago(e.last_opened),
            path: e.path.clone(),
            projects: e
                .projects
                .iter()
                .map(|p| p.key.clone())
                .collect::<Vec<_>>()
                .join(" "),
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
        } else if r.missing {
            app.theme.dim_style()
        } else {
            ratatui::style::Style::default()
        };
        let marker = if r.current {
            Span::styled("● ", ratatui::style::Style::default().fg(app.theme.ok))
        } else if r.missing {
            Span::styled("✗ ", ratatui::style::Style::default().fg(app.theme.err))
        } else {
            Span::raw("  ")
        };
        lines.push(Line::from(vec![
            marker,
            Span::styled(format!("{:<24} ", r.name), base),
            Span::styled(format!("{:<8} ", r.origin), app.theme.dim_style()),
            Span::styled(format!("{:<10} ", r.opened), app.theme.dim_style()),
            Span::styled(format!("{:<14} ", r.projects), app.theme.accent_style()),
            Span::styled(r.path, app.theme.dim_style()),
        ]));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(" spaces — ● current · ✗ store missing ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}
