//! The `?` overlay — an ACTIONABLE projection of the keymap tables
//! (lazygit-style): `j/k` moves, `Enter` runs the highlighted action in the
//! underlying context. Single source of truth with the bottom legend.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::super::action::Action;
use super::super::app::{App, HitRegion, HitTarget};
use super::super::keymap::FocusKind;

/// The flattened, selectable rows for the current context (used by both the
/// renderer and the Enter-to-run dispatch in mod.rs).
pub fn entries(app: &App, ctx: FocusKind) -> Vec<(String, &'static str, Action)> {
    let mut out = Vec::new();
    for (_, bindings) in app.keymap.help_sections(ctx) {
        for b in bindings {
            out.push((b.key.display(), b.desc, b.action));
        }
    }
    out
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect, ctx: FocusKind) {
    let rows = entries(app, ctx);
    let sel = app.help_sel.min(rows.len().saturating_sub(1));

    let w = 60.min(area.width.saturating_sub(4));
    let h = (rows.len() as u16 + 4).min(area.height.saturating_sub(2));
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + 1,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let visible = rect.height.saturating_sub(2) as usize;
    let start = sel.saturating_sub(visible.saturating_sub(1));
    let mut lines: Vec<Line> = Vec::new();
    for (i, (key, desc, _)) in rows.iter().enumerate().skip(start).take(visible) {
        let style = if i == sel {
            app.theme.selection()
        } else {
            ratatui::style::Style::default()
        };
        app.regions.push(HitRegion {
            rect: Rect {
                x: rect.x + 1,
                y: rect.y + 1 + (lines.len() as u16),
                width: rect.width.saturating_sub(2),
                height: 1,
            },
            target: HitTarget::ListRow(i),
        });
        lines.push(Line::from(vec![
            Span::styled(format!(" {key:>8}  "), app.theme.accent_style()),
            Span::styled(format!("{desc:<40}"), style),
        ]));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(" keys — enter runs the highlighted action ")
        .title_bottom(" j/k move · enter run · esc close ");
    f.render_widget(Paragraph::new(lines).block(block), rect);
}
