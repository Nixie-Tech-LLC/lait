//! Semantic actions — the single vocabulary between keys, mouse, the legend,
//! the actionable help overlay, and (later) the palette's Special handling.
//! Keys and clicks never *do* anything directly: they resolve to an [`Action`]
//! via the keymap / hit-test, and `App::apply` executes it. `Action::id()` is
//! the stable kebab-case name used by `tui.key.<id>` config overrides.

use super::app::Screen;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    // ---- global ----
    Quit,
    Back,
    Help,
    OpenPalette,
    OpenFilter,
    Refresh,
    YankRef,
    Goto(Screen),
    NextProject,
    PrevProject,
    // ---- motion ----
    Up,
    Down,
    Left,
    Right,
    Top,
    Bottom,
    // ---- board / issue ops ----
    OpenPeek,
    TogglePeekFocus,
    ExpandPeek,
    ReorderUp,
    ReorderDown,
    StatusPrev,
    StatusNext,
    Create,
    EditTitle,
    EditDescription,
    Comment,
    PickAssign,
    PickLabel,
    PickPriority,
    PickStatus,
    PickMoveProject,
    StartIssue,
    DoneIssue,
    StopIssue,
    Delete,
    ToggleSelect,
    ClearSelection,
    // ---- panel-specific (wired as their screens land) ----
    InboxClear,
    MemberApprove,
    MemberDismiss,
    MemberRename,
    MemberRemove,
    MemberInvite,
    SpaceSwitch,
    SpaceForget,
    SpacePrune,
    PinFilterAsTab,
    TabNext,
    TabPrev,
    // ---- input-layer terminals ----
    Submit,
    Cancel,
}

impl Action {
    /// Stable kebab-case id for `tui.key.<id>` overrides and help display.
    pub fn id(&self) -> &'static str {
        use Action::*;
        match self {
            Quit => "quit",
            Back => "back",
            Help => "help",
            OpenPalette => "open-palette",
            OpenFilter => "open-filter",
            Refresh => "refresh",
            YankRef => "yank-ref",
            Goto(Screen::Board) => "goto-board",
            Goto(Screen::Inbox) => "goto-inbox",
            Goto(Screen::Activity) => "goto-activity",
            Goto(Screen::Members) => "goto-members",
            Goto(Screen::Spaces) => "goto-spaces",
            Goto(Screen::ConfigPanel) => "goto-config",
            Goto(Screen::Doctor) => "goto-doctor",
            Goto(Screen::Remotes) => "goto-remotes",
            Goto(Screen::Log) => "goto-log",
            NextProject => "next-project",
            PrevProject => "prev-project",
            Up => "up",
            Down => "down",
            Left => "left",
            Right => "right",
            Top => "top",
            Bottom => "bottom",
            OpenPeek => "open-peek",
            TogglePeekFocus => "toggle-peek-focus",
            ExpandPeek => "expand-peek",
            ReorderUp => "reorder-up",
            ReorderDown => "reorder-down",
            StatusPrev => "status-prev",
            StatusNext => "status-next",
            Create => "create",
            EditTitle => "edit-title",
            EditDescription => "edit-description",
            Comment => "comment",
            PickAssign => "assign",
            PickLabel => "label",
            PickPriority => "priority",
            PickStatus => "status",
            PickMoveProject => "move-project",
            StartIssue => "start",
            DoneIssue => "done",
            StopIssue => "stop",
            Delete => "delete",
            ToggleSelect => "toggle-select",
            ClearSelection => "clear-selection",
            InboxClear => "inbox-clear",
            MemberApprove => "member-approve",
            MemberDismiss => "member-dismiss",
            MemberRename => "member-rename",
            MemberRemove => "member-remove",
            MemberInvite => "member-invite",
            SpaceSwitch => "space-switch",
            SpaceForget => "space-forget",
            SpacePrune => "space-prune",
            PinFilterAsTab => "pin-tab",
            TabNext => "tab-next",
            TabPrev => "tab-prev",
            Submit => "submit",
            Cancel => "cancel",
        }
    }

    /// Look an action up by its id (config overrides).
    pub fn from_id(id: &str) -> Option<Action> {
        ALL.iter().copied().find(|a| a.id() == id)
    }
}

/// Every action, for `from_id` and the help overlay. Keep in sync with the enum
/// (a unit test walks this against `id()` uniqueness).
pub const ALL: &[Action] = &[
    Action::Quit,
    Action::Back,
    Action::Help,
    Action::OpenPalette,
    Action::OpenFilter,
    Action::Refresh,
    Action::YankRef,
    Action::Goto(Screen::Board),
    Action::Goto(Screen::Inbox),
    Action::Goto(Screen::Activity),
    Action::Goto(Screen::Members),
    Action::Goto(Screen::Spaces),
    Action::Goto(Screen::ConfigPanel),
    Action::Goto(Screen::Doctor),
    Action::Goto(Screen::Remotes),
    Action::Goto(Screen::Log),
    Action::NextProject,
    Action::PrevProject,
    Action::Up,
    Action::Down,
    Action::Left,
    Action::Right,
    Action::Top,
    Action::Bottom,
    Action::OpenPeek,
    Action::TogglePeekFocus,
    Action::ExpandPeek,
    Action::ReorderUp,
    Action::ReorderDown,
    Action::StatusPrev,
    Action::StatusNext,
    Action::Create,
    Action::EditTitle,
    Action::EditDescription,
    Action::Comment,
    Action::PickAssign,
    Action::PickLabel,
    Action::PickPriority,
    Action::PickStatus,
    Action::PickMoveProject,
    Action::StartIssue,
    Action::DoneIssue,
    Action::StopIssue,
    Action::Delete,
    Action::ToggleSelect,
    Action::ClearSelection,
    Action::InboxClear,
    Action::MemberApprove,
    Action::MemberDismiss,
    Action::MemberRename,
    Action::MemberRemove,
    Action::MemberInvite,
    Action::SpaceSwitch,
    Action::SpaceForget,
    Action::SpacePrune,
    Action::PinFilterAsTab,
    Action::TabNext,
    Action::TabPrev,
    Action::Submit,
    Action::Cancel,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn action_ids_are_unique_and_roundtrip() {
        let mut seen = HashSet::new();
        for a in ALL {
            assert!(seen.insert(a.id()), "duplicate action id {}", a.id());
            assert_eq!(Action::from_id(a.id()), Some(*a));
        }
    }
}
