//! The board — the root panel (U§5.1). Columns are the workflow states in
//! order; rows render as two-line cards with overlay-aware fields (U§4.3),
//! workflow colors tinting column chrome, and the `/` filter applied live.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget};
use super::super::theme::parse_color;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect, focused: bool) {
    let Some(board) = &app.board else {
        f.render_widget(
            Paragraph::new(
                "(no projects visible yet — still syncing, or create one: `lait projects add KEY`)",
            )
            .style(app.theme.dim_style()),
            area,
        );
        return;
    };
    let ncols = board.columns.len().max(1);
    let min_col = 22u16;
    let fit = (area.width / min_col).max(1) as usize;
    let visible = ncols.min(fit);
    // Keep the focused column on screen: scroll the column window.
    let first = app.col_idx.saturating_sub(visible.saturating_sub(1));
    let constraints: Vec<Constraint> = (0..visible)
        .map(|_| Constraint::Ratio(1, visible as u32))
        .collect();
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(area);

    // Collect render data up front (immutable), then mutate regions after.
    struct Card {
        line1: Line<'static>,
        line2: Line<'static>,
        selected: bool,
    }
    struct Col {
        title: String,
        color: Option<ratatui::style::Color>,
        cards: Vec<Card>,
        col_index: usize,
        is_focused: bool,
    }
    let mut cols: Vec<Col> = Vec::new();
    for (offset, chunk_i) in (first..first + visible).zip(0..visible) {
        let Some(column) = board.columns.get(offset) else {
            break;
        };
        let _ = chunk_i;
        let rows = app.column_rows(offset);
        let is_focused = focused && offset == app.col_idx;
        let mut cards = Vec::new();
        for (ri, row) in rows.iter().enumerate() {
            let selected = is_focused && ri == app.row_idx;
            let marked = app.selection.contains(&row.reff);
            let mark = if marked { "▣ " } else { "" };
            let handle = row.key_alias.clone().unwrap_or_else(|| row.reff.clone());
            let optimistic = if app.overlay.has(row.doc_id.as_str()) {
                " ▲"
            } else {
                ""
            };
            let pri = row.priority.as_str();
            let pri_badge = if pri == "none" {
                String::new()
            } else {
                format!(
                    " ·{}·",
                    pri.chars().next().unwrap_or('-').to_ascii_uppercase()
                )
            };
            let assigned = if row.assignee_summary.is_empty() {
                String::new()
            } else {
                format!("  {}", row.assignee_summary)
            };
            let meta_style = if row.provisional {
                app.theme.dim_style()
            } else if selected {
                app.theme.selection()
            } else {
                app.theme.accent_style()
            };
            let title_style = if row.provisional {
                app.theme.dim_style()
            } else if selected {
                app.theme.selection()
            } else {
                ratatui::style::Style::default()
            };
            let title = app.effective_title(row);
            cards.push(Card {
                line1: Line::from(vec![Span::styled(
                    format!("{mark}{handle}{pri_badge}{assigned}{optimistic}"),
                    meta_style,
                )]),
                line2: Line::from(vec![Span::styled(format!("  {title}"), title_style)]),
                selected,
            });
        }
        cols.push(Col {
            title: format!(" {} ({}) ", column.state.name, rows.len()),
            color: parse_color(&column.state.color),
            cards,
            col_index: offset,
            is_focused,
        });
    }

    for (ci, col) in cols.into_iter().enumerate() {
        let rect = chunks[ci];
        // Column header + rows are hit-targets.
        app.regions.push(HitRegion {
            rect: Rect { height: 1, ..rect },
            target: HitTarget::ColumnHeader(col.col_index),
        });
        let mut lines: Vec<Line> = Vec::new();
        let inner_h = rect.height.saturating_sub(2) as usize;
        // Scroll so the selection stays visible (2 lines per card + blank).
        let per_card = 3usize;
        let visible_cards = (inner_h / per_card).max(1);
        let sel = col.cards.iter().position(|c| c.selected).unwrap_or(0);
        let start = sel.saturating_sub(visible_cards.saturating_sub(1));
        for (i, card) in col.cards.iter().enumerate().skip(start).take(visible_cards) {
            app.regions.push(HitRegion {
                rect: Rect {
                    x: rect.x + 1,
                    y: rect.y + 1 + (lines.len() as u16),
                    width: rect.width.saturating_sub(2),
                    height: 2,
                },
                target: HitTarget::BoardRow {
                    col: col.col_index,
                    row: i,
                },
            });
            lines.push(card.line1.clone());
            lines.push(card.line2.clone());
            lines.push(Line::from(""));
        }
        if col.cards.is_empty() {
            lines.push(Line::styled("  (empty)", app.theme.dim_style()));
        }
        let border_style = if col.is_focused {
            app.theme.border(true)
        } else if let Some(c) = col.color {
            ratatui::style::Style::default().fg(c)
        } else {
            app.theme.border(false)
        };
        let title_style = match col.color {
            Some(c) if !col.is_focused => ratatui::style::Style::default().fg(c),
            _ => app.theme.border(col.is_focused),
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(Span::styled(col.title, title_style));
        f.render_widget(Paragraph::new(lines).block(block), rect);
    }
}
