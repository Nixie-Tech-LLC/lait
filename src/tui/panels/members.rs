//! The Members screen (UI.md §8) — the members_ui domain merged into the
//! full TUI: pending join requests on top (approvable, key-first), the ACL
//! roster below, and a detail strip for the highlighted row so the full key
//! is always available for out-of-band verification.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget, MemberItem, Screen};
use super::super::util::ago;
use super::super::widgets::list_picker::{row_line, window, Cell};

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let items = app.member_items();
    let sel = app
        .cursor_of(Screen::Members)
        .min(items.len().saturating_sub(1));
    if let Some(c) = app.list_cursors.get_mut(&Screen::Members) {
        c.sel = sel;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(5)])
        .split(area);

    // ---- the roster list ----
    let n_req = items
        .iter()
        .filter(|i| matches!(i, MemberItem::Request(_)))
        .count();
    let mut cells: Vec<Cell> = Vec::new();
    if n_req > 0 {
        cells.push(Cell::Header("PENDING JOIN REQUESTS"));
        for (i, item) in items.iter().enumerate().take(n_req) {
            cells.push(Cell::Row {
                idx: i,
                text: item_text(item),
            });
        }
        cells.push(Cell::Blank);
    }
    cells.push(Cell::Header("MEMBERS"));
    for (i, item) in items.iter().enumerate().skip(n_req) {
        cells.push(Cell::Row {
            idx: i,
            text: item_text(item),
        });
    }
    let budget = chunks[0].height.saturating_sub(2) as usize;
    let windowed = window(&cells, sel, budget);
    let mut lines: Vec<Line> = Vec::new();
    let mut regions: Vec<HitRegion> = Vec::new();
    for c in windowed {
        match c {
            Cell::Header(h) => lines.push(Line::styled(h.to_string(), app.theme.dim_style())),
            Cell::Blank => lines.push(Line::from("")),
            Cell::Row { idx, text } => {
                regions.push(HitRegion {
                    rect: Rect {
                        x: chunks[0].x + 1,
                        y: chunks[0].y + 1 + (lines.len() as u16),
                        width: chunks[0].width.saturating_sub(2),
                        height: 1,
                    },
                    target: HitTarget::ListRow(*idx),
                });
                lines.push(row_line(
                    *idx == sel,
                    text,
                    chunks[0].width.saturating_sub(2) as usize,
                    app.theme.selection(),
                ));
            }
        }
    }
    if items.is_empty() {
        lines.push(Line::styled("  (no members)", app.theme.dim_style()));
    }
    app.regions.extend(regions);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(" members ");
    f.render_widget(Paragraph::new(lines).block(block), chunks[0]);

    // ---- detail strip: the full key, always visible for verification ----
    let mut detail: Vec<Line> = Vec::new();
    match items.get(sel) {
        Some(MemberItem::Request(r)) => {
            detail.push(Line::from(vec![
                Span::styled("full key  ", app.theme.dim_style()),
                Span::raw(r.key.clone()),
            ]));
            detail.push(Line::from(vec![
                Span::styled("claims    ", app.theme.dim_style()),
                Span::raw(if r.nick.is_empty() {
                    "(none)".to_string()
                } else {
                    format!("\"{}\"", r.nick)
                }),
                Span::styled(format!("   seen {}", ago(r.ts)), app.theme.dim_style()),
            ]));
            detail.push(Line::styled(
                "⚠ confirm this key out-of-band before approving.",
                ratatui::style::Style::default().fg(app.theme.warn),
            ));
        }
        Some(MemberItem::Member(m)) => {
            detail.push(Line::from(vec![
                Span::styled("full key  ", app.theme.dim_style()),
                Span::raw(m.key.as_str().to_string()),
            ]));
            detail.push(Line::from(vec![
                Span::styled("role      ", app.theme.dim_style()),
                Span::raw(m.role.clone()),
                Span::styled("   local name  ", app.theme.dim_style()),
                Span::raw(if m.alias.is_empty() {
                    "(none)".to_string()
                } else {
                    m.alias.clone()
                }),
                Span::raw(if m.me { "   (you)" } else { "" }),
            ]));
        }
        None => {}
    }
    let dblock = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(false))
        .title(" detail ");
    f.render_widget(Paragraph::new(detail).block(dblock), chunks[1]);
}

fn item_text(item: &MemberItem) -> String {
    match item {
        MemberItem::Request(r) => {
            let short: String = r.key.chars().take(12).collect();
            let claim = if r.nick.is_empty() {
                String::new()
            } else {
                format!("   claims \"{}\"", r.nick)
            };
            format!("● {short}{claim}")
        }
        MemberItem::Member(m) => {
            let name = if m.alias.is_empty() {
                String::new()
            } else {
                format!("   {}", m.alias)
            };
            let you = if m.me { "   (you)" } else { "" };
            format!("{:<6} {}{}{}", m.role, m.key.short(), name, you)
        }
    }
}
