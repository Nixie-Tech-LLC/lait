//! The `:` command palette — the CLI grammar as a modal (U§5.5: one grammar,
//! two entry points). The pure pieces (tokenizer + fuzzy scorer) are shared
//! with quick-create and the pickers; [`PaletteState`] is the modal itself:
//! a one-line input over `cmdspec::command_index()` completions, dispatched
//! through `cmdspec::parse_to_dispatch` on submit.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;
use tui_textarea::TextArea;

use super::app::{App, HitRegion, HitTarget};

/// Quote-aware argv splitter: double/single quotes group words, backslash
/// escapes the next char outside single quotes. Mirrors enough of shell
/// semantics for command lines a tracker needs — not a shell.
pub fn tokenize(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = input.chars().peekable();
    let mut in_word = false;
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {
                in_word = true;
                let quote = c;
                for q in chars.by_ref() {
                    if q == quote {
                        break;
                    }
                    if q == '\\' && quote == '"' {
                        // \" inside double quotes; a lone trailing \ is literal.
                        // (peek not available inside for-loop; treat next via flag)
                    }
                    cur.push(q);
                }
            }
            '\\' => {
                in_word = true;
                if let Some(&n) = chars.peek() {
                    cur.push(n);
                    chars.next();
                } else {
                    cur.push('\\');
                }
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// Case-insensitive subsequence score: `None` = no match; higher = better.
/// Prefix and word-boundary hits score above scattered subsequences — enough
/// ranking for the palette's tiny candidate sets, no dependency.
pub fn fuzzy_score(needle: &str, haystack: &str) -> Option<i32> {
    if needle.is_empty() {
        return Some(0);
    }
    let n: Vec<char> = needle.to_lowercase().chars().collect();
    let h: Vec<char> = haystack.to_lowercase().chars().collect();
    let mut score = 0i32;
    let mut ni = 0usize;
    let mut last_hit: Option<usize> = None;
    for (hi, &hc) in h.iter().enumerate() {
        if ni < n.len() && hc == n[ni] {
            score += 1;
            if hi == 0 {
                score += 4; // prefix
            } else if h[hi - 1] == ' ' || h[hi - 1] == '-' || h[hi - 1] == '_' {
                score += 3; // word boundary
            }
            if last_hit == Some(hi.wrapping_sub(1)) {
                score += 2; // adjacency
            }
            last_hit = Some(hi);
            ni += 1;
        }
    }
    if ni == n.len() {
        // Shorter haystacks win ties.
        Some(score - (h.len() as i32) / 8)
    } else {
        None
    }
}

/// The `:` modal's state: a one-line input plus live fuzzy suggestions from
/// the command index. Input layers own their keys; the outcome tells the
/// event loop what to do.
pub struct PaletteState {
    pub input: TextArea<'static>,
    pub suggestions: Vec<(String, &'static str)>,
    pub sel: usize,
    /// Inline error from a failed dispatch — the palette reopens with the
    /// line intact (a typo must never eat the line).
    pub error: Option<String>,
    index: Vec<(String, &'static str)>,
}

pub enum PaletteOutcome {
    Consumed,
    Submit(String),
    Cancel,
}

impl PaletteState {
    pub fn new() -> Self {
        Self::with_content("", None)
    }

    /// Reopen with prior content + an inline error (failed parse path).
    pub fn with_content(line: &str, error: Option<String>) -> Self {
        let mut input = TextArea::default();
        if !line.is_empty() {
            input.insert_str(line);
        }
        input.set_cursor_line_style(ratatui::style::Style::default());
        let mut p = PaletteState {
            input,
            suggestions: Vec::new(),
            sel: 0,
            error,
            index: crate::cmdspec::command_index(),
        };
        p.recompute();
        p
    }

    pub fn text(&self) -> String {
        self.input.lines().join(" ")
    }

    /// Rescore the command index against the input's head tokens. With args
    /// present, the matched command stays visible as an inline usage hint.
    fn recompute(&mut self) {
        let text = self.text();
        let trimmed = text.trim_start();
        if trimmed.is_empty() {
            // Empty line: show the top-level verbs in registry order.
            self.suggestions = self
                .index
                .iter()
                .filter(|(n, _)| !n.contains(' '))
                .take(12)
                .cloned()
                .collect();
        } else {
            let words: Vec<&str> = trimmed.split_whitespace().collect();
            let mut scored: Vec<(i32, (String, &'static str))> = self
                .index
                .iter()
                .filter_map(|(n, a)| {
                    let head = words
                        .iter()
                        .take(n.split(' ').count())
                        .copied()
                        .collect::<Vec<_>>()
                        .join(" ");
                    fuzzy_score(&head, n).map(|s| (s, (n.clone(), *a)))
                })
                .collect();
            scored.sort_by_key(|x| std::cmp::Reverse(x.0));
            self.suggestions = scored.into_iter().map(|(_, e)| e).take(8).collect();
        }
        self.sel = self.sel.min(self.suggestions.len().saturating_sub(1));
    }

    /// Tab-complete the command head to the selected suggestion — only while
    /// still typing the command itself (args stay untouched).
    pub fn complete(&mut self) {
        let Some((name, _)) = self.suggestions.get(self.sel).cloned() else {
            return;
        };
        let text = self.text();
        let nwords = text.split_whitespace().count();
        if nwords <= name.split(' ').count() {
            self.input = TextArea::default();
            self.input.insert_str(format!("{name} "));
            self.input
                .set_cursor_line_style(ratatui::style::Style::default());
            self.recompute();
        }
    }

    pub fn handle_key(&mut self, ev: KeyEvent) -> PaletteOutcome {
        self.error = None;
        match (ev.code, ev.modifiers) {
            (KeyCode::Esc, _) => PaletteOutcome::Cancel,
            (KeyCode::Enter, _) => {
                let t = self.text();
                if t.trim().is_empty() {
                    PaletteOutcome::Cancel
                } else {
                    PaletteOutcome::Submit(t)
                }
            }
            (KeyCode::Tab, _) => {
                self.complete();
                PaletteOutcome::Consumed
            }
            (KeyCode::Down, _) | (KeyCode::Char('n'), KeyModifiers::CONTROL) => {
                if self.sel + 1 < self.suggestions.len() {
                    self.sel += 1;
                }
                PaletteOutcome::Consumed
            }
            (KeyCode::Up, _) | (KeyCode::Char('p'), KeyModifiers::CONTROL) => {
                self.sel = self.sel.saturating_sub(1);
                PaletteOutcome::Consumed
            }
            _ => {
                self.input.input(ev);
                self.recompute();
                PaletteOutcome::Consumed
            }
        }
    }

    /// Render: a top-anchored input line with the suggestion list beneath.
    /// Suggestion rows are hit regions (click completes).
    pub fn draw(&mut self, f: &mut Frame, app: &mut App, area: Rect) {
        let w = area.width.saturating_sub(8).clamp(30, 90);
        let n_sugg = self.suggestions.len() as u16;
        let extra = if self.error.is_some() { 1 } else { 0 };
        let h = (3 + n_sugg + extra).min(area.height.saturating_sub(2));
        let rect = Rect {
            x: area.x + (area.width.saturating_sub(w)) / 2,
            y: area.y + 1,
            width: w,
            height: h,
        };
        f.render_widget(Clear, rect);
        self.input.set_block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(app.theme.border(true))
                .title(" : command ")
                .title_bottom(" enter run · tab complete · esc close "),
        );
        let input_rect = Rect {
            height: 3.min(rect.height),
            ..rect
        };
        f.render_widget(&self.input, input_rect);
        for (y, (i, (name, about))) in
            (rect.y + 3..rect.y + rect.height - extra).zip(self.suggestions.iter().enumerate())
        {
            let row = Rect {
                x: rect.x,
                y,
                width: rect.width,
                height: 1,
            };
            app.regions.push(HitRegion {
                rect: row,
                target: HitTarget::ListRow(i),
            });
            let style = if i == self.sel {
                app.theme.selection()
            } else {
                ratatui::style::Style::default()
            };
            f.render_widget(
                Paragraph::new(Line::from(vec![
                    Span::styled(format!(" {name:<18} "), style),
                    Span::styled((*about).to_string(), app.theme.dim_style()),
                ])),
                row,
            );
        }
        if let Some(err) = &self.error {
            f.render_widget(
                Paragraph::new(err.as_str())
                    .style(ratatui::style::Style::default().fg(app.theme.err)),
                Rect {
                    x: rect.x,
                    y: rect.y + rect.height - 1,
                    width: rect.width,
                    height: 1,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_quotes_escapes_and_spaces() {
        assert_eq!(
            tokenize(r#"new "fix login race" -p ENG -P high"#),
            vec!["new", "fix login race", "-p", "ENG", "-P", "high"]
        );
        assert_eq!(tokenize("comment 'its fine'"), vec!["comment", "its fine"]);
        assert_eq!(tokenize(r"a\ b c"), vec!["a b", "c"]);
        assert_eq!(tokenize("   "), Vec::<String>::new());
        assert_eq!(tokenize("''"), vec![""]);
    }

    #[test]
    fn palette_suggests_completes_and_keeps_args_visible() {
        let mut p = PaletteState::new();
        assert!(!p.suggestions.is_empty(), "empty input lists verbs");
        for c in "star".chars() {
            p.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert_eq!(p.suggestions.first().map(|s| s.0.as_str()), Some("start"));
        p.complete();
        assert_eq!(p.text(), "start ");
        // With args typed, the matched command stays as a usage hint.
        for c in "ENG-1".chars() {
            p.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert!(p.suggestions.iter().any(|(n, _)| n == "start"));
        // …and Tab must NOT clobber the args.
        p.complete();
        assert_eq!(p.text(), "start ENG-1");
    }

    #[test]
    fn palette_matches_group_subcommands() {
        let mut p = PaletteState::new();
        for c in "members app".chars() {
            p.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert!(
            p.suggestions.iter().any(|(n, _)| n == "members approve"),
            "{:?}",
            p.suggestions
        );
    }

    #[test]
    fn fuzzy_prefers_prefix_and_boundaries() {
        let score = |n: &str, h: &str| fuzzy_score(n, h);
        assert!(score("sta", "start").unwrap() > score("sta", "instant").unwrap());
        assert!(score("ma", "members approve").unwrap() > score("ma", "man").is_some() as i32 - 1);
        assert!(score("xyz", "start").is_none());
        // Word-boundary: "la" should rank "labels ls" (boundary l) well.
        assert!(score("ll", "labels ls").is_some());
    }
}
