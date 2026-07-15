//! Keybinding tables — data, not a match statement. One table per
//! [`FocusKind`] plus a global table, resolved context-first. The bottom
//! legend and the actionable `?` help are **projections of these tables**
//! (lazygit-style single source), and `tui.key.<action-id>` config overrides
//! rebind here at startup (bad overrides warn in the status line, never gate).

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::action::Action;
use super::app::Screen;
use crate::config::Settings;

/// Which binding table applies — derived from the app's focus (see
/// `App::focus()`); `Global` is implicit fallback for all non-input contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusKind {
    Board,
    Peek,
    List, // generic list-shaped screens (activity, log)
    Inbox,
    Members,
    Spaces,
    Config,
    Remotes,
    Help,
    // Input layers (Editor/Picker/Palette/Confirm) consume raw keys and never
    // hit the keymap, except through their own explicit Submit/Cancel checks.
}

/// One binding. `legend` marks the handful shown in the bottom bar; everything
/// appears in `?` help.
#[derive(Debug, Clone, Copy)]
pub struct Binding {
    pub key: KeyPattern,
    pub action: Action,
    pub desc: &'static str,
    pub legend: bool,
}

/// A parse/print-able key chord: `"ctrl+k"`, `"H"` (shift-h), `"enter"`,
/// `"tab"`, `"?"`. Uppercase letters mean shift+letter, matching how crossterm
/// reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPattern {
    pub code: KeyCode,
    pub mods: KeyModifiers,
}

impl KeyPattern {
    pub const fn ch(c: char) -> Self {
        KeyPattern {
            code: KeyCode::Char(c),
            mods: KeyModifiers::NONE,
        }
    }
    pub const fn ctrl(c: char) -> Self {
        KeyPattern {
            code: KeyCode::Char(c),
            mods: KeyModifiers::CONTROL,
        }
    }
    pub const fn code(code: KeyCode) -> Self {
        KeyPattern {
            code,
            mods: KeyModifiers::NONE,
        }
    }

    /// Whether a crossterm event matches. Char patterns ignore SHIFT (the
    /// char itself already encodes case); everything else matches mods exactly.
    pub fn matches(&self, ev: &KeyEvent) -> bool {
        if self.code != ev.code {
            return false;
        }
        match self.code {
            KeyCode::Char(_) => {
                let relevant = ev.modifiers - KeyModifiers::SHIFT;
                let wanted = self.mods - KeyModifiers::SHIFT;
                relevant == wanted
            }
            _ => ev.modifiers == self.mods,
        }
    }

    /// Parse the config string form: `[ctrl+][alt+]<key>` where `<key>` is a
    /// single char, `enter`, `esc`, `tab`, `space`, `up/down/left/right`,
    /// `pgup/pgdn`, `home`, `end`, or `f1`..`f12`.
    pub fn parse(s: &str) -> Option<Self> {
        let mut mods = KeyModifiers::NONE;
        let mut rest = s.trim();
        loop {
            let lower = rest.to_ascii_lowercase();
            if let Some(r) = lower.strip_prefix("ctrl+") {
                mods |= KeyModifiers::CONTROL;
                rest = &rest[rest.len() - r.len()..];
            } else if let Some(r) = lower.strip_prefix("alt+") {
                mods |= KeyModifiers::ALT;
                rest = &rest[rest.len() - r.len()..];
            } else {
                break;
            }
        }
        let code = match rest.to_ascii_lowercase().as_str() {
            "enter" => KeyCode::Enter,
            "esc" => KeyCode::Esc,
            "tab" => KeyCode::Tab,
            "space" => KeyCode::Char(' '),
            "up" => KeyCode::Up,
            "down" => KeyCode::Down,
            "left" => KeyCode::Left,
            "right" => KeyCode::Right,
            "pgup" => KeyCode::PageUp,
            "pgdn" | "pgdown" => KeyCode::PageDown,
            "home" => KeyCode::Home,
            "end" => KeyCode::End,
            f if f.starts_with('f') && f.len() <= 3 => {
                KeyCode::F(f[1..].parse().ok().filter(|n| (1..=12).contains(n))?)
            }
            _ => {
                let mut chars = rest.chars();
                let c = chars.next()?;
                if chars.next().is_some() {
                    return None;
                }
                KeyCode::Char(c)
            }
        };
        Some(KeyPattern { code, mods })
    }

    /// The config/help display form (inverse of `parse`).
    pub fn display(&self) -> String {
        let mut s = String::new();
        if self.mods.contains(KeyModifiers::CONTROL) {
            s.push_str("ctrl+");
        }
        if self.mods.contains(KeyModifiers::ALT) {
            s.push_str("alt+");
        }
        match self.code {
            KeyCode::Char(' ') => s.push_str("space"),
            KeyCode::Char(c) => s.push(c),
            KeyCode::Enter => s.push_str("enter"),
            KeyCode::Esc => s.push_str("esc"),
            KeyCode::Tab => s.push_str("tab"),
            KeyCode::Up => s.push('↑'),
            KeyCode::Down => s.push('↓'),
            KeyCode::Left => s.push('←'),
            KeyCode::Right => s.push('→'),
            KeyCode::PageUp => s.push_str("pgup"),
            KeyCode::PageDown => s.push_str("pgdn"),
            KeyCode::Home => s.push_str("home"),
            KeyCode::End => s.push_str("end"),
            KeyCode::F(n) => s.push_str(&format!("f{n}")),
            _ => s.push('?'),
        }
        s
    }
}

pub struct Keymap {
    pub global: Vec<Binding>,
    pub board: Vec<Binding>,
    pub peek: Vec<Binding>,
    pub list: Vec<Binding>,
    pub inbox: Vec<Binding>,
    pub members: Vec<Binding>,
    pub spaces: Vec<Binding>,
    pub config: Vec<Binding>,
    pub remotes: Vec<Binding>,
    pub help: Vec<Binding>,
}

fn b(key: KeyPattern, action: Action, desc: &'static str) -> Binding {
    Binding {
        key,
        action,
        desc,
        legend: false,
    }
}
fn bl(key: KeyPattern, action: Action, desc: &'static str) -> Binding {
    Binding {
        key,
        action,
        desc,
        legend: true,
    }
}

impl Keymap {
    /// The defaults — UI.md §6 baseline plus the DX-pass verbs.
    pub fn defaults() -> Self {
        use Action::*;
        use KeyCode as K;
        let global = vec![
            b(KeyPattern::ch('q'), Quit, "quit"),
            b(KeyPattern::code(K::Esc), Back, "back"),
            bl(KeyPattern::ch('?'), Help, "help"),
            bl(KeyPattern::ch(':'), OpenPalette, "palette"),
            b(KeyPattern::ctrl('k'), OpenPalette, "palette"),
            bl(KeyPattern::ch('/'), OpenFilter, "filter"),
            b(KeyPattern::ch('r'), Refresh, "refresh"),
            b(KeyPattern::ch('1'), Goto(Screen::Board), "board"),
            b(KeyPattern::ch('2'), Goto(Screen::Inbox), "inbox"),
            b(KeyPattern::ch('3'), Goto(Screen::Activity), "activity"),
            b(KeyPattern::ch('4'), Goto(Screen::Members), "members"),
            b(KeyPattern::ch('5'), Goto(Screen::Spaces), "spaces"),
            b(KeyPattern::ch('!'), Goto(Screen::Doctor), "doctor"),
            b(KeyPattern::code(K::Tab), NextProject, "next project"),
            b(KeyPattern::code(K::BackTab), PrevProject, "prev project"),
            b(KeyPattern::ch('j'), Down, "down"),
            b(KeyPattern::code(K::Down), Down, "down"),
            b(KeyPattern::ch('k'), Up, "up"),
            b(KeyPattern::code(K::Up), Up, "up"),
            b(KeyPattern::ch('h'), Left, "left"),
            b(KeyPattern::code(K::Left), Left, "left"),
            b(KeyPattern::ch('l'), Right, "right"),
            b(KeyPattern::code(K::Right), Right, "right"),
            b(KeyPattern::ch('g'), Top, "top"),
            b(KeyPattern::ch('G'), Bottom, "bottom"),
        ];
        let board = vec![
            bl(KeyPattern::ch('c'), Create, "new"),
            bl(KeyPattern::code(K::Enter), OpenPeek, "peek"),
            b(KeyPattern::ch('H'), StatusPrev, "status ←"),
            bl(KeyPattern::ch('L'), StatusNext, "status →"),
            b(KeyPattern::ch('K'), ReorderUp, "reorder ↑"),
            b(KeyPattern::ch('J'), ReorderDown, "reorder ↓"),
            bl(KeyPattern::ch('S'), StartIssue, "start"),
            bl(KeyPattern::ch('D'), DoneIssue, "done"),
            b(KeyPattern::ch('O'), StopIssue, "stop (put down)"),
            b(KeyPattern::ch('e'), EditTitle, "edit title"),
            b(KeyPattern::ch('C'), Comment, "comment"),
            b(KeyPattern::ch('a'), PickAssign, "assign"),
            b(KeyPattern::ch('b'), PickLabel, "label"),
            b(KeyPattern::ch('p'), PickPriority, "priority"),
            b(KeyPattern::ch('s'), PickStatus, "set status"),
            b(KeyPattern::ch('m'), PickMoveProject, "move project"),
            b(KeyPattern::ch('x'), ToggleSelect, "select"),
            b(KeyPattern::ch('X'), ClearSelection, "clear selection"),
            b(KeyPattern::ch('y'), YankRef, "yank ref"),
            b(KeyPattern::ch('P'), PinFilterAsTab, "pin filter as tab"),
            b(KeyPattern::ch(']'), TabNext, "next tab"),
            b(KeyPattern::ch('['), TabPrev, "prev tab"),
        ];
        let peek = vec![
            bl(KeyPattern::code(K::Enter), ExpandPeek, "expand"),
            b(KeyPattern::ch('o'), ExpandPeek, "expand"),
            bl(KeyPattern::code(K::Tab), TogglePeekFocus, "back to board"),
            b(KeyPattern::ch('e'), EditTitle, "edit title"),
            bl(KeyPattern::ch('d'), EditDescription, "description"),
            bl(KeyPattern::ch('C'), Comment, "comment"),
            b(KeyPattern::ch('a'), PickAssign, "assign"),
            b(KeyPattern::ch('b'), PickLabel, "label"),
            b(KeyPattern::ch('p'), PickPriority, "priority"),
            b(KeyPattern::ch('s'), PickStatus, "set status"),
            b(KeyPattern::ch('S'), StartIssue, "start"),
            b(KeyPattern::ch('D'), DoneIssue, "done"),
            b(KeyPattern::ch('y'), YankRef, "yank ref"),
        ];
        let list = vec![
            bl(KeyPattern::code(K::Enter), OpenPeek, "open"),
            b(KeyPattern::ch('c'), Create, "new"),
        ];
        let inbox = vec![
            bl(KeyPattern::code(K::Enter), OpenPeek, "open"),
            bl(KeyPattern::ch('C'), InboxClear, "mark all read"),
        ];
        let members = vec![
            bl(KeyPattern::ch('y'), MemberApprove, "approve"),
            b(KeyPattern::ch('n'), MemberDismiss, "dismiss"),
            bl(KeyPattern::ch('R'), MemberRename, "rename"),
            b(KeyPattern::ch('d'), MemberRemove, "remove"),
            bl(KeyPattern::ch('i'), MemberInvite, "invite link"),
        ];
        let spaces = vec![
            bl(KeyPattern::code(K::Enter), SpaceSwitch, "switch"),
            bl(KeyPattern::ch('f'), SpaceForget, "forget"),
            b(KeyPattern::ch('P'), SpacePrune, "prune missing"),
        ];
        let config = vec![bl(KeyPattern::code(K::Enter), OpenPeek, "edit key")];
        let remotes = vec![bl(KeyPattern::ch('d'), Delete, "unpin")];
        let help = vec![bl(KeyPattern::code(K::Enter), Submit, "run action")];
        Keymap {
            global,
            board,
            peek,
            list,
            inbox,
            members,
            spaces,
            config,
            remotes,
            help,
        }
    }

    /// Apply `tui.key.<action-id>` overrides. Returns human warnings for the
    /// status line (unknown action id / unparseable key) — never an error.
    pub fn apply_overrides(&mut self, settings: &Settings) -> Vec<String> {
        let mut warnings = Vec::new();
        let mut overrides: Vec<(String, String)> = Vec::new();
        for layer in [&settings.global, &settings.store] {
            for (k, v) in &layer.0 {
                if let Some(id) = k.strip_prefix("tui.key.") {
                    overrides.push((id.to_string(), v.clone()));
                }
            }
        }
        for (id, key_str) in overrides {
            let Some(action) = Action::from_id(&id) else {
                warnings.push(format!("tui.key.{id}: unknown action id (see `?`)"));
                continue;
            };
            let Some(pattern) = KeyPattern::parse(&key_str) else {
                warnings.push(format!("tui.key.{id}: can't parse key '{key_str}'"));
                continue;
            };
            let mut hit = false;
            for table in [
                &mut self.global,
                &mut self.board,
                &mut self.peek,
                &mut self.list,
                &mut self.inbox,
                &mut self.members,
                &mut self.spaces,
                &mut self.config,
                &mut self.remotes,
                &mut self.help,
            ] {
                for binding in table.iter_mut().filter(|b| b.action == action) {
                    binding.key = pattern;
                    hit = true;
                }
            }
            if !hit {
                warnings.push(format!("tui.key.{id}: action has no default binding"));
            }
        }
        warnings
    }

    fn table(&self, ctx: FocusKind) -> &[Binding] {
        match ctx {
            FocusKind::Board => &self.board,
            FocusKind::Peek => &self.peek,
            FocusKind::List => &self.list,
            FocusKind::Inbox => &self.inbox,
            FocusKind::Members => &self.members,
            FocusKind::Spaces => &self.spaces,
            FocusKind::Config => &self.config,
            FocusKind::Remotes => &self.remotes,
            FocusKind::Help => &self.help,
        }
    }

    /// Resolve a key event: context table first, then global.
    pub fn resolve(&self, ctx: FocusKind, ev: &KeyEvent) -> Option<Action> {
        self.table(ctx)
            .iter()
            .chain(self.global.iter())
            .find(|b| b.key.matches(ev))
            .map(|b| b.action)
    }

    /// The bottom-legend chips for a context (context-marked + global-marked).
    pub fn legend(&self, ctx: FocusKind) -> Vec<&Binding> {
        self.table(ctx)
            .iter()
            .filter(|b| b.legend)
            .chain(self.global.iter().filter(|b| b.legend))
            .collect()
    }

    /// Everything for the `?` overlay: (section, bindings).
    pub fn help_sections(&self, ctx: FocusKind) -> Vec<(&'static str, &[Binding])> {
        let ctx_name = match ctx {
            FocusKind::Board => "board",
            FocusKind::Peek => "issue",
            FocusKind::List => "list",
            FocusKind::Inbox => "inbox",
            FocusKind::Members => "members",
            FocusKind::Spaces => "spaces",
            FocusKind::Config => "config",
            FocusKind::Remotes => "remotes",
            FocusKind::Help => "help",
        };
        vec![(ctx_name, self.table(ctx)), ("global", &self.global)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigMap;

    fn ev(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    #[test]
    fn key_pattern_parse_display_roundtrip() {
        for s in ["ctrl+k", "H", "enter", "tab", "space", "f2", "alt+x", "?"] {
            let p = KeyPattern::parse(s).unwrap_or_else(|| panic!("parse {s}"));
            let back = KeyPattern::parse(&p.display()).unwrap();
            assert_eq!(p, back, "{s} roundtrips");
        }
        assert!(KeyPattern::parse("ctrl+").is_none());
        assert!(KeyPattern::parse("meta+q").is_none());
        assert!(KeyPattern::parse("f13").is_none());
    }

    #[test]
    fn shift_letters_match_and_context_beats_global() {
        let km = Keymap::defaults();
        // 'L' arrives as Char('L') + SHIFT; the pattern must still match.
        let a = km.resolve(
            FocusKind::Board,
            &ev(KeyCode::Char('L'), KeyModifiers::SHIFT),
        );
        assert_eq!(a, Some(Action::StatusNext));
        // 'l' (lowercase) falls through to global Right.
        let a = km.resolve(
            FocusKind::Board,
            &ev(KeyCode::Char('l'), KeyModifiers::NONE),
        );
        assert_eq!(a, Some(Action::Right));
        // 'd' means description in peek, nothing on the board table (falls to
        // global: unbound → None).
        assert_eq!(
            km.resolve(FocusKind::Peek, &ev(KeyCode::Char('d'), KeyModifiers::NONE)),
            Some(Action::EditDescription)
        );
        assert_eq!(
            km.resolve(
                FocusKind::Board,
                &ev(KeyCode::Char('d'), KeyModifiers::NONE)
            ),
            None
        );
    }

    #[test]
    fn config_overrides_rebind_and_warn() {
        let mut km = Keymap::defaults();
        let mut store = ConfigMap::default();
        store.set("tui.key.open-palette", "ctrl+p");
        store.set("tui.key.nonsense", "x");
        store.set("tui.key.start", "not a key");
        let settings = crate::config::Settings {
            global: ConfigMap::default(),
            store,
        };
        let warnings = km.apply_overrides(&settings);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        // The override wins…
        assert_eq!(
            km.resolve(
                FocusKind::Board,
                &ev(KeyCode::Char('p'), KeyModifiers::CONTROL)
            ),
            Some(Action::OpenPalette)
        );
        // …and the ':' binding for the same action was replaced too (both
        // default bindings of the action are rebound).
        assert_eq!(
            km.resolve(
                FocusKind::Board,
                &ev(KeyCode::Char(':'), KeyModifiers::NONE)
            ),
            None
        );
    }

    #[test]
    fn legend_projects_from_tables() {
        let km = Keymap::defaults();
        let legend = km.legend(FocusKind::Board);
        assert!(legend.iter().any(|b| b.action == Action::Create));
        assert!(legend.iter().any(|b| b.action == Action::Help));
        assert!(!legend.iter().any(|b| b.action == Action::YankRef));
    }
}
