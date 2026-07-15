//! A small y/n confirmation modal for destructive actions (delete now;
//! space forget/prune in Stage 3).

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::super::app::App;

#[derive(Debug, Clone)]
pub enum ConfirmIntent {
    DeleteIssues {
        targets: Vec<String>,
    },
    /// Remove a member (rotates the space key).
    RemoveMember {
        key: String,
    },
    /// Drop a registry entry (`workspaces::forget`; the store stays on disk).
    ForgetSpace {
        sel: String,
    },
    /// Drop every registry entry whose store is gone (`workspaces::prune`).
    PruneSpaces,
    /// Unpin an always-on seed peer.
    RemoveSeed {
        who: String,
    },
}

pub struct ConfirmState {
    pub title: String,
    pub body: String,
    pub intent: ConfirmIntent,
}

pub enum ConfirmOutcome {
    Consumed,
    Yes,
    No,
}

impl ConfirmState {
    pub fn handle_key(&mut self, ev: KeyEvent) -> ConfirmOutcome {
        match ev.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => ConfirmOutcome::Yes,
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ConfirmOutcome::No,
            _ => ConfirmOutcome::Consumed,
        }
    }

    pub fn draw(&self, f: &mut Frame, app: &App, area: Rect) {
        let w = area.width.saturating_sub(8).clamp(30, 70);
        let rect = Rect {
            x: area.x + (area.width.saturating_sub(w)) / 2,
            y: area.y + area.height / 3,
            width: w,
            height: 4.min(area.height),
        };
        f.render_widget(Clear, rect);
        let lines = vec![
            Line::styled(
                self.body.clone(),
                ratatui::style::Style::default().fg(app.theme.warn),
            ),
            Line::styled("y confirm · n cancel", app.theme.title()),
        ];
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(ratatui::style::Style::default().fg(app.theme.warn))
            .title(format!(" {} ", self.title));
        f.render_widget(Paragraph::new(lines).block(block), rect);
    }
}
