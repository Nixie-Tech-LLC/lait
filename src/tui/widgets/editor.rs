//! The one text-input widget (U§5.3): a `tui-textarea` wrapper used for every
//! input surface — quick-create, title, multi-line description/comment, and
//! (later) filter/palette lines. Replaces the old append-only Modal: real
//! cursor movement, selection, bracketed paste, unicode.
//!
//! Submit: `Enter` in single-line mode, `Ctrl+S` in multi-line (Enter inserts
//! a newline there; Ctrl+Enter is unreliable across Windows terminals).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;
use tui_textarea::TextArea;

use super::super::theme::Theme;

/// What the editor's content is FOR — carried through so submit knows which
/// Request(s) to build (the reusable mapping lives in `action.rs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditorIntent {
    /// Quick-create: the line is `new`'s grammar (`title words -p KEY -P high
    /// -l bug…`), parsed via `cmdspec::parse_to_dispatch`.
    Create,
    EditTitle {
        reff: String,
    },
    EditDescription {
        reff: String,
    },
    Comment {
        reff: String,
    },
    /// Approve a pending join request, optionally attaching a local petname
    /// (the buffer; empty = none) as we seal them in.
    ApproveMember {
        key: String,
    },
    /// Set (empty buffer clears) a local petname on a member key.
    RenameMember {
        key: String,
    },
    /// Set (empty buffer unsets) a store-layer config key.
    ConfigSet {
        key: String,
    },
    /// Name a pinned tab.
    NameTab,
}

pub struct EditorState {
    pub textarea: TextArea<'static>,
    pub intent: EditorIntent,
    pub title: String,
    pub single_line: bool,
    /// Inline error from a failed submit (e.g. quick-create parse error) —
    /// shown under the input; cleared on next keystroke.
    pub error: Option<String>,
}

/// What a key did to the editor.
pub enum EditorOutcome {
    Consumed,
    Submit(String),
    Cancel,
}

impl EditorState {
    pub fn new(intent: EditorIntent, title: impl Into<String>, initial: &str) -> Self {
        let single_line = matches!(
            intent,
            EditorIntent::Create
                | EditorIntent::EditTitle { .. }
                | EditorIntent::ApproveMember { .. }
                | EditorIntent::RenameMember { .. }
                | EditorIntent::ConfigSet { .. }
                | EditorIntent::NameTab
        );
        let mut textarea = if initial.is_empty() {
            TextArea::default()
        } else {
            TextArea::from(initial.lines().map(str::to_string).collect::<Vec<_>>())
        };
        textarea.move_cursor(tui_textarea::CursorMove::Bottom);
        textarea.move_cursor(tui_textarea::CursorMove::End);
        EditorState {
            textarea,
            intent,
            title: title.into(),
            single_line,
            error: None,
        }
    }

    /// The full buffer as one string (lines joined by `\n`).
    pub fn content(&self) -> String {
        self.textarea.lines().join("\n")
    }

    pub fn handle_key(&mut self, ev: KeyEvent) -> EditorOutcome {
        self.error = None;
        match (ev.code, ev.modifiers) {
            (KeyCode::Esc, _) => EditorOutcome::Cancel,
            (KeyCode::Enter, m) if self.single_line && !m.contains(KeyModifiers::SHIFT) => {
                EditorOutcome::Submit(self.content())
            }
            (KeyCode::Char('s'), KeyModifiers::CONTROL) if !self.single_line => {
                EditorOutcome::Submit(self.content())
            }
            _ => {
                self.textarea.input(ev);
                EditorOutcome::Consumed
            }
        }
    }

    /// Bracketed paste lands whole (multi-line pastes into a single-line field
    /// flatten newlines to spaces — a title is one line).
    pub fn handle_paste(&mut self, text: &str) {
        if self.single_line {
            self.textarea.insert_str(text.replace(['\n', '\r'], " "));
        } else {
            self.textarea.insert_str(text);
        }
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect, theme: &Theme) {
        let input_h = if self.single_line { 3 } else { 10 };
        let extra = if self.error.is_some() { 1 } else { 0 };
        let h = (input_h + extra).min(area.height.saturating_sub(2));
        let w = area.width.saturating_sub(8).clamp(30, 90);
        let rect = Rect {
            x: area.x + (area.width.saturating_sub(w)) / 2,
            y: area.y + area.height / 4,
            width: w,
            height: h,
        };
        f.render_widget(Clear, rect);
        let hint = if self.single_line {
            "enter save · esc cancel"
        } else {
            "ctrl+s save · esc cancel"
        };
        self.textarea.set_block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.border(true))
                .title(format!(" {} ", self.title))
                .title_bottom(format!(" {hint} ")),
        );
        self.textarea
            .set_cursor_line_style(ratatui::style::Style::default());
        let input_rect = Rect {
            height: rect.height - extra,
            ..rect
        };
        f.render_widget(&self.textarea, input_rect);
        if let Some(err) = &self.error {
            let err_rect = Rect {
                y: rect.y + rect.height - 1,
                height: 1,
                x: rect.x,
                width: rect.width,
            };
            f.render_widget(
                Paragraph::new(err.as_str()).style(ratatui::style::Style::default().fg(theme.err)),
                err_rect,
            );
        }
    }
}
