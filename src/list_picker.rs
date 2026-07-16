//! List-rendering machinery for the inline `lait members` picker: windowing
//! (keep the selection visible) plus row styling.
//!
//! Originally extracted *from* `members_ui` so it could be shared with the TUI's
//! pickers and list screens. The TUI is gone; `members_ui` is the only caller
//! again, and this stays a separate module purely because its windowing is worth
//! testing on its own — not because anything else needs it.

use ratatui::style::Style;
use ratatui::text::Line;

/// A visual row of a list: a section header, a spacer, or a selectable item.
/// `idx` is the item's *selection* index (headers and blanks have none), so
/// windowing can keep the selected item visible regardless of decoration.
pub enum Cell {
    Header(&'static str),
    Blank,
    Row { idx: usize, text: String },
}

/// Slice `cells` to at most `budget` entries, keeping the selected item visible.
pub fn window(cells: &[Cell], sel: usize, budget: usize) -> Vec<&Cell> {
    if budget == 0 || cells.len() <= budget {
        return cells.iter().collect();
    }
    let sel_pos = cells
        .iter()
        .position(|c| matches!(c, Cell::Row { idx, .. } if *idx == sel))
        .unwrap_or(0);
    let mut start = sel_pos.saturating_sub(budget / 2);
    if start + budget > cells.len() {
        start = cells.len() - budget;
    }
    cells[start..start + budget].iter().collect()
}

/// One item row: a full-width `sel_style` bar when selected, else a plain
/// indented line. Padding to `w` makes the highlight span the whole row.
pub fn row_line(selected: bool, text: &str, w: usize, sel_style: Style) -> Line<'static> {
    if selected {
        let mut s = format!("> {text}");
        let len = s.chars().count();
        if len < w {
            s.push_str(&" ".repeat(w - len));
        }
        Line::styled(s, sel_style)
    } else {
        Line::from(format!("  {text}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_keeps_selection_visible() {
        let cells: Vec<Cell> = (0..20)
            .map(|i| Cell::Row {
                idx: i,
                text: format!("row{i}"),
            })
            .collect();
        let win = window(&cells, 18, 5);
        assert_eq!(win.len(), 5);
        assert!(
            win.iter().any(|c| matches!(c, Cell::Row { idx: 18, .. })),
            "selected row 18 must be in the window"
        );
    }

    #[test]
    fn window_handles_headers_and_small_lists() {
        let cells = vec![
            Cell::Header("H"),
            Cell::Row {
                idx: 0,
                text: "a".into(),
            },
            Cell::Blank,
        ];
        assert_eq!(window(&cells, 0, 10).len(), 3, "small lists pass through");
        assert_eq!(window(&cells, 0, 2).len(), 2);
    }
}
