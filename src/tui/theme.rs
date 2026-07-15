//! The TUI's one palette (U§4). Every renderer takes styles from here — no
//! literal `Color::` anywhere else — so `tui.theme = dark | light | auto`
//! restyles the whole client, and the DTO-carried color strings
//! (`WorkflowState.color`, `ProjectDto.color`, `LabelDto.color`) map through
//! [`parse_color`] into accents (column tints, tab accents, label chips).
//!
//! `auto` is the zero-dependency `COLORFGBG` heuristic (else dark): an OSC-11
//! background query would race the raw-mode `EventStream` (the reply arrives
//! as input) and is flaky on Windows consoles — a dep and a hazard for a value
//! the user can set once.

use ratatui::style::{Color, Modifier, Style};

use crate::config::Settings;

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    #[allow(dead_code)] // used once chips/spans need explicit fg (Stage 2 pickers)
    pub fg: Color,
    pub dim: Color,
    pub accent: Color,
    pub ok: Color,
    pub warn: Color,
    pub err: Color,
    pub sel_fg: Color,
    pub sel_bg: Color,
    pub border_focus: Color,
    pub border_unfocus: Color,
    /// Label-chip text drawn over the label's own color.
    pub chip_fg: Color,
}

impl Theme {
    pub fn dark() -> Self {
        Theme {
            fg: Color::Reset,
            dim: Color::DarkGray,
            accent: Color::Cyan,
            ok: Color::Green,
            warn: Color::Yellow,
            err: Color::Red,
            sel_fg: Color::Black,
            sel_bg: Color::Cyan,
            border_focus: Color::Cyan,
            border_unfocus: Color::DarkGray,
            chip_fg: Color::Black,
        }
    }

    pub fn light() -> Self {
        Theme {
            fg: Color::Reset,
            dim: Color::Gray,
            accent: Color::Blue,
            ok: Color::Green,
            warn: Color::Rgb(0xb0, 0x80, 0x00),
            err: Color::Red,
            sel_fg: Color::White,
            sel_bg: Color::Blue,
            border_focus: Color::Blue,
            border_unfocus: Color::Gray,
            chip_fg: Color::White,
        }
    }

    /// Resolve from settings: `tui.theme` = dark (default) | light | auto.
    pub fn load(settings: &Settings) -> Self {
        match settings.get("tui.theme").unwrap_or("dark") {
            "light" => Self::light(),
            "auto" => {
                // COLORFGBG is "fg;bg" with bg 0-6/8 = dark, 7/15 = light.
                let light_bg = std::env::var("COLORFGBG")
                    .ok()
                    .and_then(|v| v.rsplit(';').next().and_then(|b| b.parse::<u8>().ok()))
                    .is_some_and(|bg| bg == 7 || bg == 15);
                if light_bg {
                    Self::light()
                } else {
                    Self::dark()
                }
            }
            _ => Self::dark(),
        }
    }

    // ---- style helpers (used everywhere; keep renderers declarative) ----
    pub fn dim_style(&self) -> Style {
        Style::default().fg(self.dim)
    }
    pub fn accent_style(&self) -> Style {
        Style::default().fg(self.accent)
    }
    pub fn selection(&self) -> Style {
        Style::default().fg(self.sel_fg).bg(self.sel_bg)
    }
    pub fn title(&self) -> Style {
        Style::default().add_modifier(Modifier::BOLD)
    }
    pub fn border(&self, focused: bool) -> Style {
        Style::default().fg(if focused {
            self.border_focus
        } else {
            self.border_unfocus
        })
    }
}

/// Map a DTO color string (named or `#rrggbb`) to a terminal color. Named set
/// covers what `default_workflow()` seeds plus common user choices; unknown
/// names yield `None` (callers fall back to `theme.dim`).
pub fn parse_color(s: &str) -> Option<Color> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            return Some(Color::Rgb(r, g, b));
        }
        return None;
    }
    Some(match s.to_ascii_lowercase().as_str() {
        "gray" | "grey" => Color::DarkGray,
        "blue" => Color::Blue,
        "cyan" => Color::Cyan,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "red" => Color::Red,
        "magenta" | "pink" => Color::Magenta,
        "orange" => Color::Rgb(0xd7, 0x87, 0x00),
        "purple" | "violet" => Color::Rgb(0x87, 0x5f, 0xd7),
        "white" => Color::White,
        "black" => Color::Black,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_color_named_hex_and_garbage() {
        assert_eq!(parse_color("blue"), Some(Color::Blue));
        assert_eq!(parse_color("GREY"), Some(Color::DarkGray));
        assert_eq!(parse_color("#ff8000"), Some(Color::Rgb(0xff, 0x80, 0x00)));
        assert_eq!(parse_color("#ff80"), None);
        assert_eq!(parse_color("chartreuse-ish"), None);
    }
}
