//! The detail peek (U§5.3) — a right-side panel co-visible with the board;
//! `Enter`/`o` expands it to full width. Renders the lazily-loaded IssueView:
//! title, metadata, description, comments (timeline lands with Stage 2).

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use super::super::app::{App, HitRegion, HitTarget};
use super::super::theme::parse_color;

pub fn draw(f: &mut Frame, app: &mut App, area: Rect) {
    let Some(peek) = &app.peek else {
        return;
    };
    let v = &peek.view;
    let theme = &app.theme;

    let mut lines: Vec<Line> = Vec::new();
    let handle = v.key_alias.clone().unwrap_or_else(|| v.reff.clone());
    lines.push(Line::from(vec![
        Span::styled(format!("{handle}  "), theme.accent_style()),
        Span::styled(v.title.clone(), theme.title()),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("status ", theme.dim_style()),
        Span::raw(v.status.clone()),
        Span::styled("   priority ", theme.dim_style()),
        Span::raw(v.priority.as_str().to_string()),
        Span::styled("   project ", theme.dim_style()),
        Span::raw(v.project_key.clone().unwrap_or_default()),
    ]));
    if !v.assignees.is_empty() {
        let who: Vec<String> = v.assignees.iter().map(|u| u.short()).collect();
        lines.push(Line::from(vec![
            Span::styled("assignees ", theme.dim_style()),
            Span::raw(who.join(", ")),
        ]));
    }
    if !v.label_names.is_empty() {
        let mut spans = vec![Span::styled("labels ", theme.dim_style())];
        for name in &v.label_names {
            let color = parse_color("gray").unwrap_or(theme.dim);
            spans.push(Span::styled(
                format!(" {name} "),
                ratatui::style::Style::default().fg(theme.chip_fg).bg(color),
            ));
            spans.push(Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    if !v.description.trim().is_empty() {
        for l in v.description.lines() {
            lines.push(Line::raw(l.to_string()));
        }
        lines.push(Line::from(""));
    }
    if !v.comments.is_empty() {
        lines.push(Line::styled(
            format!("comments ({})", v.comments.len()),
            theme.title(),
        ));
        for c in &v.comments {
            let who = c.author_nick.clone().unwrap_or_else(|| c.author.short());
            lines.push(Line::from(vec![
                Span::styled(format!("── {who}: "), theme.dim_style()),
                Span::raw(c.body.clone()),
            ]));
        }
    }
    // The derived activity timeline (Request::History) — chronological, with
    // the non-blocking LWW collision note surfaced as ⚠ (A§9).
    if !peek.history.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled("history", theme.title()));
        for e in &peek.history {
            let mut spans = vec![Span::styled(
                format!("{:<9} ", super::super::util::ago(e.ts)),
                theme.dim_style(),
            )];
            if e.collision {
                spans.push(Span::styled(
                    "⚠ ",
                    ratatui::style::Style::default().fg(theme.warn),
                ));
            }
            if !e.actor_nick.is_empty() {
                spans.push(Span::styled(
                    format!("{} ", e.actor_nick),
                    theme.accent_style(),
                ));
            }
            spans.push(Span::raw(e.text.clone()));
            lines.push(Line::from(spans));
        }
    }

    let focused = peek.focused;
    let scroll = peek.scroll;
    app.regions.push(HitRegion {
        rect: area,
        target: HitTarget::Peek,
    });
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(app.theme.border(focused))
        .title(format!(" {handle} "))
        .title_bottom(if focused {
            " enter expand · tab board · d desc · C comment · esc close "
        } else {
            " tab focus "
        });
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}
