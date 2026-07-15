//! Bottom bar: the context legend (a projection of the keymap tables — every
//! chip is also a mouse hit-region) plus a transient status/toast line.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::super::app::{App, HitTarget, OverlayLayer};
use super::super::keymap::FocusKind;

/// A transient message with severity; expires after a few frames of ticks.
#[derive(Debug, Default)]
pub struct StatusLine {
    pub text: String,
    pub is_error: bool,
    /// Remaining 3s-ticks before the message fades (see mod.rs tick arm).
    pub ttl: u8,
}

impl StatusLine {
    pub fn info(&mut self, text: impl Into<String>) {
        self.text = text.into();
        self.is_error = false;
        self.ttl = 3;
    }
    pub fn error(&mut self, text: impl Into<String>) {
        self.text = text.into();
        self.is_error = true;
        self.ttl = 5;
    }
    pub fn tick(&mut self) {
        if self.ttl > 0 {
            self.ttl -= 1;
            if self.ttl == 0 {
                self.text.clear();
            }
        }
    }
}

pub fn draw(f: &mut Frame, app: &mut App, area: Rect, ctx: FocusKind) {
    // Live `/` filter input takes over the bar while editing.
    if matches!(app.stack.last(), Some(OverlayLayer::Filter { .. })) {
        let line = Line::from(vec![
            Span::styled(" / ", app.theme.accent_style()),
            Span::raw(app.filter_text.clone()),
            Span::styled("_", app.theme.accent_style()),
            Span::styled("   enter keep · esc restore", app.theme.dim_style()),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    // Status message takes priority over the legend while alive.
    if !app.status.text.is_empty() {
        let style = if app.status.is_error {
            ratatui::style::Style::default().fg(app.theme.err)
        } else {
            app.theme.accent_style()
        };
        f.render_widget(Paragraph::new(app.status.text.as_str()).style(style), area);
        return;
    }
    let legend: Vec<(String, &'static str, crate::tui::action::Action)> = app
        .keymap
        .legend(ctx)
        .into_iter()
        .map(|b| (b.key.display(), b.desc, b.action))
        .collect();
    let mut spans: Vec<Span> = Vec::new();
    let mut x = area.x;
    for (key, desc, action) in legend {
        let chip = format!(" [{key}] {desc} ");
        let w = chip.chars().count() as u16;
        if x + w > area.x + area.width {
            break;
        }
        // Each chip is clickable (runs its Action) — register the region.
        app.regions.push(super::super::app::HitRegion {
            rect: Rect {
                x,
                y: area.y,
                width: w,
                height: 1,
            },
            target: HitTarget::LegendAction(action),
        });
        spans.push(Span::styled(format!("[{key}]"), app.theme.accent_style()));
        spans.push(Span::styled(format!(" {desc}  "), app.theme.dim_style()));
        x += w;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
