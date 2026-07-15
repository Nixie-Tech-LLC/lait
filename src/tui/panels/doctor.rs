//! The guided-join verifier readout (GUIDED-JOIN.md) — gate list + summary,
//! straight from the `DiagnosisView` DTO (ported from the old client).

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::super::app::App;
use crate::diagnose::GateState;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match &app.diagnosis {
        None => lines.push(Line::styled("(running diagnosis…)", app.theme.dim_style())),
        Some(v) => {
            for g in &v.gates {
                let color = match g.state {
                    GateState::Pass => app.theme.ok,
                    GateState::Wait => app.theme.warn,
                    GateState::Fail => app.theme.err,
                    GateState::Skip => app.theme.dim,
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{} ", g.state.glyph()),
                        ratatui::style::Style::default().fg(color),
                    ),
                    Span::styled(format!("{:<11} ", g.label), app.theme.title()),
                    Span::raw(g.detail.clone()),
                ]));
            }
            lines.push(Line::from(""));
            let color = if v.blocked_on.is_some() {
                app.theme.warn
            } else {
                app.theme.ok
            };
            lines.push(Line::styled(
                v.summary.clone(),
                ratatui::style::Style::default().fg(color),
            ));
        }
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(true))
        .title(" doctor — the onboarding gates ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}
