//! The remotes screen — pinned always-on seed peers (A§10) and their live
//! reachability. `d` unpins (confirmed); pin new ones via `:` (`seed add`).

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget, Screen};

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let n = app.seeds.len();
    let sel = app.cursor_of(Screen::Remotes).min(n.saturating_sub(1));
    if let Some(c) = app.list_cursors.get_mut(&Screen::Remotes) {
        c.sel = sel;
    }

    let mut lines: Vec<Line> = Vec::new();
    if n == 0 {
        lines.push(Line::styled(
            "  (no pinned seeds — `: seed add <ticket|id>` pins an always-on peer)",
            app.theme.dim_style(),
        ));
    }
    let rows: Vec<(usize, String, String, String, bool)> = app
        .seeds
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let name = if s.nick.is_empty() {
                s.id.chars().take(12).collect()
            } else {
                s.nick.clone()
            };
            (i, name, s.state.clone(), s.workspace.clone(), s.online)
        })
        .collect();
    for (i, name, state, workspace, online) in rows {
        app.regions.push(HitRegion {
            rect: Rect {
                x: area.x + 1,
                y: area.y + 1 + (lines.len() as u16),
                width: area.width.saturating_sub(2),
                height: 1,
            },
            target: HitTarget::ListRow(i),
        });
        let base = if i == sel {
            app.theme.selection()
        } else {
            ratatui::style::Style::default()
        };
        let dot = if online {
            Span::styled("● ", ratatui::style::Style::default().fg(app.theme.ok))
        } else {
            Span::styled("○ ", app.theme.dim_style())
        };
        lines.push(Line::from(vec![
            Span::raw("  "),
            dot,
            Span::styled(format!("{name:<20} "), base),
            Span::styled(format!("{state:<9} "), app.theme.dim_style()),
            Span::styled(workspace, app.theme.dim_style()),
        ]));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(" remotes — pinned seed peers ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}
