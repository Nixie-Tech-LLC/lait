//! The config panel — every known key with its effective value and origin
//! layer (store > global > default), plus any set `tui.key.*` overrides.
//! `Enter` edits into the store layer; an empty submit unsets. Daemon-read
//! keys ConfigReload live; `tui.*` keys re-theme/re-bind on the spot.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget, Screen};

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let n = app.config_rows.len();
    let sel = app.cursor_of(Screen::ConfigPanel).min(n.saturating_sub(1));
    if let Some(c) = app.list_cursors.get_mut(&Screen::ConfigPanel) {
        c.sel = sel;
    }

    let mut lines: Vec<Line> = Vec::new();
    if n == 0 {
        lines.push(Line::styled("  (loading…)", app.theme.dim_style()));
    }
    let visible = area.height.saturating_sub(2) as usize;
    let start = sel.saturating_sub(visible.saturating_sub(1));
    let rows: Vec<(usize, String, String, &'static str, &'static str)> = app
        .config_rows
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, r)| (i, r.key.clone(), r.value.clone(), r.origin, r.help))
        .collect();
    for (i, key, value, origin, help) in rows {
        app.regions.push(HitRegion {
            rect: Rect {
                x: area.x + 1,
                y: area.y + 1 + (lines.len() as u16),
                width: area.width.saturating_sub(2),
                height: 1,
            },
            target: HitTarget::ListRow(i),
        });
        let key_style = if i == sel {
            app.theme.selection()
        } else {
            app.theme.accent_style()
        };
        let origin_style = match origin {
            "store" => app.theme.accent_style(),
            "global" => ratatui::style::Style::default().fg(app.theme.warn),
            _ => app.theme.dim_style(),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {key:<22} "), key_style),
            Span::raw(format!("{value:<28} ")),
            Span::styled(format!("({origin:<7}) "), origin_style),
            Span::styled(help.to_string(), app.theme.dim_style()),
        ]));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(" config — enter edits the store layer (empty unsets) ");
    f.render_widget(Paragraph::new(lines).block(block), area);
}
