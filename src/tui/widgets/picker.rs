//! The picker modal (U§5.4): one component for assign / label / status /
//! priority / move-project / ref-disambiguation. Single-select picks on
//! Enter; multi-select toggles with Space and commits the whole set on
//! Enter. Typing filters (fuzzy); the intent says what submit means.

use std::collections::HashSet;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget};
use super::super::palette::fuzzy_score;
use crate::control::Request;

/// What a submitted pick means — carried through so `App::submit_picker`
/// knows which Request(s) to build. `targets` are canonical reffs captured
/// at open time (the multi-select set, else the focused issue).
#[derive(Debug, Clone)]
pub enum PickIntent {
    /// Multi: checked = desired assignee set (single target diffs against
    /// `precheck`; bulk targets add-only).
    Assign { targets: Vec<String> },
    /// Multi: same diff semantics over labels.
    Label { targets: Vec<String> },
    /// Single: a workflow state id.
    Status { targets: Vec<String> },
    /// Single: a priority name.
    Priority { targets: Vec<String> },
    /// Single: a project key.
    MoveProject { targets: Vec<String> },
    /// Single: a candidate reff — substitute into `retry` and resend
    /// (`Response::Candidates` is a first-class outcome, UI.md §3.2).
    Disambiguate { retry: Box<Request> },
}

#[derive(Debug, Clone)]
pub struct PickItem {
    pub label: String,
    pub value: String,
}

pub struct PickerState {
    pub title: String,
    pub items: Vec<PickItem>,
    pub intent: PickIntent,
    pub multi: bool,
    /// Checked values (multi mode). Pre-seeded from the issue's current
    /// state for single-target pickers so the diff is honest.
    pub checked: HashSet<String>,
    /// What was checked at open time — submit diffs against this.
    pub precheck: HashSet<String>,
    pub filter: String,
    pub sel: usize,
}

pub enum PickerOutcome {
    Consumed,
    Submit,
    Cancel,
}

impl PickerState {
    pub fn new(
        title: impl Into<String>,
        items: Vec<PickItem>,
        intent: PickIntent,
        multi: bool,
        precheck: HashSet<String>,
    ) -> Self {
        PickerState {
            title: title.into(),
            items,
            intent,
            multi,
            checked: precheck.clone(),
            precheck,
            filter: String::new(),
            sel: 0,
        }
    }

    /// Items surviving the fuzzy filter, best-first, with their original index.
    pub fn filtered(&self) -> Vec<(usize, &PickItem)> {
        if self.filter.is_empty() {
            return self.items.iter().enumerate().collect();
        }
        let mut scored: Vec<(i32, usize, &PickItem)> = self
            .items
            .iter()
            .enumerate()
            .filter_map(|(i, it)| fuzzy_score(&self.filter, &it.label).map(|s| (s, i, it)))
            .collect();
        scored.sort_by_key(|x| std::cmp::Reverse(x.0));
        scored.into_iter().map(|(_, i, it)| (i, it)).collect()
    }

    /// The highlighted item (post-filter).
    pub fn selected(&self) -> Option<&PickItem> {
        let f = self.filtered();
        f.get(self.sel.min(f.len().saturating_sub(1)))
            .map(|(_, it)| *it)
    }

    pub fn toggle_selected(&mut self) {
        let Some(v) = self.selected().map(|it| it.value.clone()) else {
            return;
        };
        if !self.checked.insert(v.clone()) {
            self.checked.remove(&v);
        }
    }

    pub fn handle_key(&mut self, ev: KeyEvent) -> PickerOutcome {
        match ev.code {
            KeyCode::Esc => PickerOutcome::Cancel,
            KeyCode::Enter => PickerOutcome::Submit,
            KeyCode::Down => {
                let n = self.filtered().len();
                if n > 0 && self.sel + 1 < n {
                    self.sel += 1;
                }
                PickerOutcome::Consumed
            }
            KeyCode::Up => {
                self.sel = self.sel.saturating_sub(1);
                PickerOutcome::Consumed
            }
            KeyCode::Char(' ') if self.multi => {
                self.toggle_selected();
                PickerOutcome::Consumed
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.sel = 0;
                PickerOutcome::Consumed
            }
            KeyCode::Char(c) => {
                self.filter.push(c);
                self.sel = 0;
                PickerOutcome::Consumed
            }
            _ => PickerOutcome::Consumed,
        }
    }

    pub fn draw(&mut self, f: &mut Frame, app: &mut App, area: Rect) {
        let rows = self.filtered();
        let sel = self.sel.min(rows.len().saturating_sub(1));
        // Materialize display strings before touching app.regions (borrows).
        let lines_src: Vec<(usize, String, bool)> = rows
            .iter()
            .enumerate()
            .map(|(di, (_, it))| {
                let mark = if !self.multi {
                    String::new()
                } else if self.checked.contains(&it.value) {
                    "▣ ".to_string()
                } else {
                    "☐ ".to_string()
                };
                (di, format!("{mark}{}", it.label), di == sel)
            })
            .collect();

        let w = area.width.saturating_sub(8).clamp(30, 70);
        let h = ((lines_src.len() as u16) + 3)
            .min(area.height.saturating_sub(2))
            .max(4);
        let rect = Rect {
            x: area.x + (area.width.saturating_sub(w)) / 2,
            y: area.y + 1,
            width: w,
            height: h,
        };
        f.render_widget(Clear, rect);

        let visible = rect.height.saturating_sub(3) as usize;
        let start = sel.saturating_sub(visible.saturating_sub(1));
        let mut lines: Vec<Line> = vec![Line::from(vec![
            Span::styled(" > ", app.theme.accent_style()),
            Span::raw(self.filter.clone()),
            Span::styled("_", app.theme.dim_style()),
        ])];
        for (di, text, is_sel) in lines_src.iter().skip(start).take(visible) {
            app.regions.push(HitRegion {
                rect: Rect {
                    x: rect.x + 1,
                    y: rect.y + 1 + (lines.len() as u16),
                    width: rect.width.saturating_sub(2),
                    height: 1,
                },
                target: HitTarget::ListRow(*di),
            });
            let style = if *is_sel {
                app.theme.selection()
            } else {
                ratatui::style::Style::default()
            };
            lines.push(Line::styled(format!(" {text}"), style));
        }
        if lines_src.is_empty() {
            lines.push(Line::styled("  (no matches)", app.theme.dim_style()));
        }
        let hint = if self.multi {
            " type filter · space toggle · enter apply · esc cancel "
        } else {
            " type filter · enter pick · esc cancel "
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(app.theme.border(true))
            .title(format!(" {} ", self.title))
            .title_bottom(hint);
        f.render_widget(Paragraph::new(lines).block(block), rect);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn picker(multi: bool) -> PickerState {
        PickerState::new(
            "assign",
            vec![
                PickItem {
                    label: "alice".into(),
                    value: "k1".into(),
                },
                PickItem {
                    label: "bob".into(),
                    value: "k2".into(),
                },
                PickItem {
                    label: "carol".into(),
                    value: "k3".into(),
                },
            ],
            PickIntent::Assign {
                targets: vec!["iss_1".into()],
            },
            multi,
            HashSet::new(),
        )
    }

    #[test]
    fn filter_narrows_and_space_toggles() {
        let mut p = picker(true);
        for c in "car".chars() {
            p.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let f = p.filtered();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1.label, "carol");
        p.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(p.checked.contains("k3"));
        p.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(!p.checked.contains("k3"));
    }

    #[test]
    fn single_select_space_is_a_filter_char() {
        let mut p = picker(false);
        p.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(p.checked.is_empty());
        assert_eq!(p.filter, " ");
    }

    #[test]
    fn precheck_seeds_checked_for_honest_diffs() {
        let pre: HashSet<String> = ["k2".to_string()].into_iter().collect();
        let p = PickerState::new(
            "assign",
            vec![],
            PickIntent::Assign { targets: vec![] },
            true,
            pre.clone(),
        );
        assert_eq!(p.checked, pre);
        assert_eq!(p.precheck, pre);
    }
}
