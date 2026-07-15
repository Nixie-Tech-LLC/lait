//! Programmatic clap command registry.
//!
//! The CLI surface (UI.md §2) is defined as **data** — a `Vec<Spec>` built by
//! [`specs`] — instead of a `#[derive(Parser)]` enum. [`build_cli`] turns that
//! data into a `clap::Command` at runtime, so completions (`clap_complete`) and
//! the man page (`clap_mangen`) still generate from the live tree exactly as
//! before; only the *front-end* changed, not the wire (`control::Request`).
//!
//! Why data-driven: a command is now one [`Spec`] entry mapping parsed args to a
//! single Layer-B [`Request`] (or a `Special` handler), which is the same registry
//! other surfaces (MCP) can derive from instead of re-declaring the command list.
//! The trade vs. the derive macro: `ArgMatches` lookups are keyed by string, so a
//! name typo is a runtime, not compile-time, error — concentrated inside each
//! spec's `to_request` closure and covered by `tests/cli_parse.rs`.

use anyhow::{anyhow, Result};
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_complete::Shell;

use crate::{
    control::{BoardPos, Filter, Request},
    install::{Client, Scope},
};

/// How a resolved leaf command is executed.
pub enum Dispatch {
    /// Build a `Request` from the parsed args, then round-trip the daemon and
    /// render (`cli::run`). Covers the ~22 uniform commands.
    Request(fn(&ArgMatches) -> Result<Request>),
    /// A command with bespoke handling in `app::run` (spawns a daemon, mints a
    /// key, custom output). The arg reading lives in the matching handler.
    Special(Special),
}

/// The commands `app::run` handles by hand (they do more than one `Request`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Special {
    Init,
    Start,
    Done,
    Stop,
    Id,
    Daemon,
    Mcp,
    InstallMcp,
    Tui,
    Invite,
    Join,
    Watch,
    Completions,
    Man,
    Profiles,
    Resume,
    Workspaces,
    WorkspacesForget,
    WorkspacesPrune,
    ConfigGet,
    ConfigSet,
    ConfigUnset,
    ConfigList,
    Update,
}

/// One command (or nested group) in the tree.
pub struct Spec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub about: &'static str,
    pub args: Vec<ArgSpec>,
    pub subs: Vec<Spec>,
    /// Require a subcommand (a group with no bare form, e.g. `remote`).
    pub sub_required: bool,
    /// Escape hatch for arg shapes ArgSpec doesn't model (value-enums, etc.).
    pub customize: Option<fn(Command) -> Command>,
    pub dispatch: Dispatch,
    /// A long-running networked service (`daemon`, `mcp`) that must keep Rust's
    /// default SIGPIPE-ignored so a dropped socket returns EPIPE, not a kill.
    pub service: bool,
    /// Help-screen bucket (clap `display_order`): the first screen leads with
    /// the daily loop, registries and node plumbing sink to the bottom.
    pub order: usize,
}

impl Spec {
    /// A leaf command mapping args → one `Request`.
    fn req(
        name: &'static str,
        about: &'static str,
        args: Vec<ArgSpec>,
        f: fn(&ArgMatches) -> Result<Request>,
    ) -> Spec {
        Spec {
            name,
            aliases: &[],
            about,
            args,
            subs: Vec::new(),
            sub_required: false,
            customize: None,
            dispatch: Dispatch::Request(f),
            service: false,
            order: ORDER_DEFAULT,
        }
    }

    /// A leaf command handled by a bespoke `Special` arm.
    fn special(name: &'static str, about: &'static str, args: Vec<ArgSpec>, s: Special) -> Spec {
        Spec {
            name,
            aliases: &[],
            about,
            args,
            subs: Vec::new(),
            sub_required: false,
            customize: None,
            dispatch: Dispatch::Special(s),
            service: false,
            order: ORDER_DEFAULT,
        }
    }

    fn alias(mut self, a: &'static [&'static str]) -> Spec {
        self.aliases = a;
        self
    }
    fn service(mut self) -> Spec {
        self.service = true;
        self
    }
    fn customize(mut self, f: fn(Command) -> Command) -> Spec {
        self.customize = Some(f);
        self
    }
}

/// One argument, modelled declaratively. Every value is a `String`; numerics are
/// parsed in the `to_request` closure (keeps this type free of clap value-parser
/// generics). Exotic parsers (shell/client/scope value-enums) go via `customize`.
pub struct ArgSpec {
    name: &'static str,
    short: Option<char>,
    long: Option<&'static str>,
    help: &'static str,
    action: Act,
    required: bool,
    default: Option<&'static str>,
    value_name: Option<&'static str>,
    allow_hyphen: bool,
    trailing: bool,
    conflicts: &'static [&'static str],
}

enum Act {
    Set,
    Append,
    Flag,
}

impl ArgSpec {
    fn base(
        name: &'static str,
        help: &'static str,
        long: Option<&'static str>,
        action: Act,
    ) -> Self {
        ArgSpec {
            name,
            short: None,
            long,
            help,
            action,
            required: false,
            default: None,
            value_name: None,
            allow_hyphen: false,
            trailing: false,
            conflicts: &[],
        }
    }

    /// `--name <v>` (optional value).
    pub fn val(name: &'static str, help: &'static str) -> Self {
        Self::base(name, help, Some(name), Act::Set)
    }
    /// `--name` (boolean).
    pub fn flag(name: &'static str, help: &'static str) -> Self {
        Self::base(name, help, Some(name), Act::Flag)
    }
    /// `--name <v>` repeatable (collected into a `Vec`).
    pub fn multi(name: &'static str, help: &'static str) -> Self {
        Self::base(name, help, Some(name), Act::Append)
    }
    /// A required positional.
    pub fn pos(name: &'static str, help: &'static str) -> Self {
        let mut a = Self::base(name, help, None, Act::Set);
        a.required = true;
        a
    }
    /// An optional positional.
    pub fn pos_opt(name: &'static str, help: &'static str) -> Self {
        Self::base(name, help, None, Act::Set)
    }
    /// A variadic positional (collected into a `Vec`).
    pub fn pos_multi(name: &'static str, help: &'static str) -> Self {
        Self::base(name, help, None, Act::Append)
    }

    pub fn short(mut self, c: char) -> Self {
        self.short = Some(c);
        self
    }
    /// Override the `--long` when it differs from the arg id (kebab vs snake).
    pub fn long(mut self, l: &'static str) -> Self {
        self.long = Some(l);
        self
    }
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
    pub fn default(mut self, d: &'static str) -> Self {
        self.default = Some(d);
        self
    }
    pub fn value_name(mut self, v: &'static str) -> Self {
        self.value_name = Some(v);
        self
    }
    /// Let a value begin with `-` (so `label ENG-1 -wip` isn't read as a flag).
    pub fn hyphen(mut self) -> Self {
        self.allow_hyphen = true;
        self
    }
    pub fn trailing(mut self) -> Self {
        self.trailing = true;
        self
    }
    pub fn conflicts(mut self, c: &'static [&'static str]) -> Self {
        self.conflicts = c;
        self
    }

    fn is_positional(&self) -> bool {
        self.long.is_none() && self.short.is_none()
    }

    fn to_arg(&self) -> Arg {
        let mut a = Arg::new(self.name).help(self.help);
        if let Some(l) = self.long {
            a = a.long(l);
        }
        if let Some(s) = self.short {
            a = a.short(s);
        }
        match self.action {
            Act::Flag => a = a.action(ArgAction::SetTrue),
            Act::Append => {
                a = a.action(ArgAction::Append);
                if self.is_positional() {
                    a = a.num_args(0..);
                }
            }
            Act::Set => {}
        }
        if self.required {
            a = a.required(true);
        }
        if let Some(d) = self.default {
            a = a.default_value(d);
        }
        if let Some(v) = self.value_name {
            a = a.value_name(v);
        }
        if self.allow_hyphen {
            a = a.allow_hyphen_values(true);
        }
        if self.trailing {
            a = a.trailing_var_arg(true);
        }
        if !self.conflicts.is_empty() {
            a = a.conflicts_with_all(self.conflicts.iter().copied());
        }
        a
    }
}

/// Build the root `clap::Command` from the registry. Fed verbatim to
/// `clap_complete::generate` and `clap_mangen::Man::new`, so completions and the
/// man page stay generated from the live tree.
pub fn build_cli(specs: &[Spec]) -> Command {
    let mut root = Command::new("lait")
        .version(env!("LAIT_VERSION_LONG"))
        .about("A local-first, peer-to-peer issue tracker")
        // No subcommand required: bare `lait` is the FOCUS view (inbox + your
        // active issues, UI.md §2) — the most valuable keystroke goes to the
        // most-asked question, not to help. `lait help` / `-h` still work.
        .arg(
            Arg::new("home")
                .long("home")
                .global(true)
                .action(ArgAction::Set)
                .help("Select the node's home directory (overrides $LAIT_HOME)."),
        )
        .arg(
            Arg::new("workspace")
                .short('w')
                .long("space")
                .alias("workspace")
                .global(true)
                .action(ArgAction::Set)
                .conflicts_with("home")
                .value_name("SEL")
                .help(
                    "Select a space by name, ws_ id (or prefix), or path — from any \
                     directory (see `lait spaces`).",
                ),
        )
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Emit the versioned JSON DTO instead of human output (UI.md §2.3)."),
        )
        .arg(
            Arg::new("no_color")
                .long("no-color")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Disable ANSI colours."),
        );
    for s in specs {
        root = root.subcommand(build_sub(s));
    }
    root
}

/// Help buckets (see `Spec.order`). Within a bucket, declaration order holds.
const ORDER_DAILY: usize = 10; // the loop: new/start/done/stop/inbox/show/board/ls…
const ORDER_SHARE: usize = 20; // init/join/invite/spaces/members/doctor/status
const ORDER_DEFAULT: usize = 30; // registries, settings
const ORDER_NODE: usize = 40; // daemon/remote/mcp/plumbing

fn build_sub(s: &Spec) -> Command {
    let mut c = Command::new(s.name).about(s.about).display_order(s.order);
    for a in s.aliases {
        c = c.alias(*a);
    }
    for a in &s.args {
        c = c.arg(a.to_arg());
    }
    for sub in &s.subs {
        c = c.subcommand(build_sub(sub));
    }
    if s.sub_required {
        c = c.subcommand_required(true).arg_required_else_help(true);
    }
    if let Some(f) = s.customize {
        c = f(c);
    }
    c
}

/// Parse an argv (`["lait", "label", "ENG-1", "+bug"]`) and, when it resolves to
/// a `Request`-dispatch command, build that `Request`. The parity seam: it maps
/// argv → the exact Layer-B request the daemon receives, so `tests/cli_parse.rs`
/// can pin the arg semantics without a running daemon. Returns a clap usage error
/// for bad input, or an error naming the command if it is a `Special` handler.
pub fn parse_to_request(argv: &[&str]) -> Result<Request> {
    match parse_to_dispatch(argv)? {
        ParsedCommand::Request(r) => Ok(r),
        ParsedCommand::Special { name, .. } => {
            Err(anyhow!("`{name}` is a special-dispatch command"))
        }
    }
}

/// A parsed command line, surfacing `Special` leaves instead of erroring on
/// them — the seam the TUI command palette dispatches through (one grammar,
/// two entry points, UI.md tenet 4). The palette decides per-`Special` whether
/// it has a native equivalent (start/done/stop, config, spaces, …) or rejects
/// with "CLI-only".
pub enum ParsedCommand {
    Request(Request),
    Special {
        which: Special,
        /// The leaf's name (for messages) — e.g. "start", "set".
        name: &'static str,
        matches: ArgMatches,
    },
}

/// Like [`parse_to_request`], but classifies rather than rejecting `Special`s.
pub fn parse_to_dispatch(argv: &[&str]) -> Result<ParsedCommand> {
    let specs = specs();
    let cli = build_cli(&specs);
    let m = cli.try_get_matches_from(argv).map_err(|e| anyhow!("{e}"))?;
    let (leaf, lm) = resolve(&specs, &m).ok_or_else(|| anyhow!("no subcommand"))?;
    match &leaf.dispatch {
        Dispatch::Request(f) => Ok(ParsedCommand::Request(f(lm)?)),
        Dispatch::Special(s) => Ok(ParsedCommand::Special {
            which: *s,
            name: leaf.name,
            matches: lm.clone(),
        }),
    }
}

/// The palette's completion source: every invocable leaf as `(full name, about)`
/// — top-level verbs plus one level of group subcommands ("members approve").
pub fn command_index() -> Vec<(String, &'static str)> {
    let mut out = Vec::new();
    for s in specs() {
        if s.subs.is_empty() {
            out.push((s.name.to_string(), s.about));
        } else {
            // The group's bare form is invocable too (e.g. `members` lists).
            out.push((s.name.to_string(), s.about));
            for c in &s.subs {
                out.push((format!("{} {}", s.name, c.name), c.about));
            }
        }
    }
    out
}

/// Resolve the invoked matches down to the leaf `Spec` + its `ArgMatches`,
/// descending one level into groups (`projects`/`members`/…). A group invoked
/// bare (`lait members`) resolves to the group spec itself (its bare dispatch).
pub fn resolve<'a>(specs: &'a [Spec], m: &'a ArgMatches) -> Option<(&'a Spec, &'a ArgMatches)> {
    let (name, sub_m) = m.subcommand()?;
    let spec = specs
        .iter()
        .find(|s| s.name == name || s.aliases.contains(&name))?;
    if !spec.subs.is_empty() {
        if let Some((cn, cm)) = sub_m.subcommand() {
            if let Some(child) = spec
                .subs
                .iter()
                .find(|s| s.name == cn || s.aliases.contains(&cn))
            {
                return Some((child, cm));
            }
        }
        return Some((spec, sub_m));
    }
    Some((spec, sub_m))
}

// ---- ArgMatches readers (all values are String; numerics parsed here) --------

fn opt_str(m: &ArgMatches, id: &str) -> Option<String> {
    m.get_one::<String>(id).cloned()
}
fn req_str(m: &ArgMatches, id: &str) -> String {
    // Required/defaulted at the clap layer, so this is always present.
    m.get_one::<String>(id).cloned().unwrap_or_default()
}
fn flag(m: &ArgMatches, id: &str) -> bool {
    m.get_flag(id)
}
fn multi(m: &ArgMatches, id: &str) -> Vec<String> {
    m.get_many::<String>(id)
        .map(|v| v.cloned().collect())
        .unwrap_or_default()
}
fn u64_arg(m: &ArgMatches, id: &str) -> Result<u64> {
    req_str(m, id)
        .parse::<u64>()
        .map_err(|_| anyhow!("--{id} must be a non-negative integer"))
}

// ---- Issue-ref inference from the git branch (VCS-native ergonomics) ---------

/// Pull the first `KEY-n` token out of a string, key uppercased:
/// `eng-142-fix-login` → `ENG-142`, `feature/ENG-7` → `ENG-7`. `None` if absent.
/// No regex dependency — a small forward scan.
fn parse_key_n(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphabetic() {
            let start = i;
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            if i < b.len() && b[i] == b'-' {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if j > i + 1 {
                    return Some(format!(
                        "{}-{}",
                        s[start..i].to_ascii_uppercase(),
                        &s[i + 1..j]
                    ));
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Infer an issue ref from the current git branch: `eng-142-fix` → `ENG-142`, so
/// `show`/`edit`/`history` are argument-free while you work the branch. `None` if
/// not a git repo, detached HEAD, or the branch carries no `KEY-n`.
fn infer_ref_from_git_branch() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_key_n(String::from_utf8_lossy(&out.stdout).trim())
}

/// Resolve an optional issue-ref arg: explicit value, else the git-branch
/// inference, else a clear error. `pub(crate)` — the work-state Specials
/// (`start`/`done`/`stop`) resolve their ref in `app::run`.
pub(crate) fn resolve_reff(m: &ArgMatches) -> Result<String> {
    match opt_str(m, "reff") {
        Some(r) => Ok(r),
        None => infer_ref_from_git_branch().ok_or_else(|| {
            anyhow!(
                "no issue given, and none could be inferred from the current git branch \
                 (name it like `eng-142-short-desc`). Pass a ref explicitly, e.g. `lait show ENG-142`."
            )
        }),
    }
}

/// "OPS" → "Ops": the default project name when `projects add` gets only a key.
fn title_case(key: &str) -> String {
    let lower = key.to_ascii_lowercase();
    let mut c = lower.chars();
    match c.next() {
        Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
        None => lower,
    }
}

/// The project KEY implied by the current git branch (`eng-142-fix` → `ENG`) —
/// the environment hint for the daemon's choose-project chain. Shipped as
/// `project_hint`, distinct from an explicit `-p`: the daemon uses it only if
/// it resolves to a real project, so a branch like `wip-2` never breaks `new`.
fn infer_project_key_from_git_branch() -> Option<String> {
    let key_n = infer_ref_from_git_branch()?;
    key_n.split('-').next().map(str::to_string)
}

/// The optional `-p/--project` flag shared by `new`/`ls`/`move` (one place to
/// keep the flag shape consistent).
fn project_flag(help: &'static str) -> ArgSpec {
    ArgSpec::val("project", help).short('p')
}

/// Fill the `project_hint` field: only worth computing (a git subprocess) when
/// no explicit project was given — an explicit `-p` always wins anyway.
fn project_hint(m: &ArgMatches) -> Option<String> {
    if opt_str(m, "project").is_some() {
        None
    } else {
        infer_project_key_from_git_branch()
    }
}

// ---- The registry ------------------------------------------------------------

/// The full CLI surface as data. Built once per invocation in `app::run`.
pub fn specs() -> Vec<Spec> {
    use ArgSpec as A;
    let mut v = vec![
        // ---- workspace founding ----
        Spec::special(
            "init",
            "Found a new space here (mints the genesis; seeds a first project).",
            vec![
                A::val("name", "Workspace display name (default: this directory's name)."),
                A::val("nick", "Display nickname (sugar for `lait config set user.nick`)."),
            ],
            Special::Init,
        ),
        // ---- issues (flat verbs) ----
        Spec::req(
            "new",
            "Create an issue; echoes the resolved handle.",
            vec![
                A::pos("title", "Issue title."),
                project_flag("Target project key (default: branch key, `project.default`, or the sole project)."),
                A::multi("assignees", "Assign a member (repeatable).")
                    .short('a')
                    .long("assign"),
                A::val("priority", "Priority (urgent/high/medium/low/none).").short('P'),
                A::multi("labels", "Attach a label (repeatable).")
                    .short('l')
                    .long("label"),
                A::val("body", "Issue body/description.").short('b'),
                A::flag(
                    "start",
                    "Also start it: assign yourself, set it active, create+checkout its branch.",
                ),
            ],
            |m| {
                Ok(Request::IssueNew {
                    title: req_str(m, "title"),
                    project: opt_str(m, "project"),
                    project_hint: project_hint(m),
                    assignees: multi(m, "assignees"),
                    priority: opt_str(m, "priority"),
                    labels: multi(m, "labels"),
                    body: opt_str(m, "body"),
                })
            },
        ),
        Spec::special(
            "start",
            "Claim an issue and get moving: assign yourself, set it active, create+checkout its branch.",
            vec![
                A::pos_opt("reff", "Issue ref (default: the current branch's issue)."),
                A::flag("no_branch", "Skip the git branch step.").long("no-branch"),
            ],
            Special::Start,
        ),
        Spec::special(
            "done",
            "Finish an issue (ref optional — inferred from the git branch).",
            vec![A::pos_opt("reff", "Issue ref.")],
            Special::Done,
        ),
        Spec::special(
            "stop",
            "Put an issue down gracefully: back to backlog, unassign yourself.",
            vec![A::pos_opt("reff", "Issue ref.")],
            Special::Stop,
        ),
        Spec::req(
            "inbox",
            "Things addressed to you: assignments, comments on your work, @mentions.",
            vec![A::flag("clear", "Mark everything read after listing.")],
            |m| {
                Ok(Request::Inbox {
                    clear: flag(m, "clear"),
                })
            },
        ),
        Spec::req(
            "ls",
            "List issue rows from the Catalog cache (no issue-doc loads).",
            vec![
                project_flag("Filter to a project (a pure filter — never defaulted)."),
                A::flag("mine", "Only issues assigned to you."),
                A::val("status", "Filter by status."),
                A::val("label", "Filter by label."),
                A::flag("all", "Include done/archived."),
            ],
            |m| {
                Ok(Request::List {
                    project: opt_str(m, "project"),
                    filter: Filter {
                        mine: flag(m, "mine"),
                        status: opt_str(m, "status"),
                        label: opt_str(m, "label"),
                        all: flag(m, "all"),
                    },
                })
            },
        ),
        Spec::req(
            "board",
            "Render a project's board (workflow columns × ordered rows).",
            vec![A::pos_opt(
                "project",
                "Project key (default: branch key, `project.default`, or the sole project).",
            )],
            |m| {
                Ok(Request::Board {
                    project: opt_str(m, "project"),
                    project_hint: project_hint(m),
                })
            },
        ),
        Spec::req(
            "show",
            "Show a full issue (ref optional — inferred from the git branch).",
            vec![A::pos_opt("reff", "Issue ref (e.g. ENG-142).")],
            |m| {
                Ok(Request::IssueView {
                    reff: resolve_reff(m)?,
                })
            },
        ),
        Spec::req(
            "edit",
            "Patch an issue's fields (ref optional — inferred from the git branch).",
            vec![
                A::pos_opt("reff", "Issue ref."),
                A::val("title", "New title."),
                A::val("status", "New status."),
                A::val("priority", "New priority."),
                A::val("body", "Replace the description (whole body).").short('b'),
            ],
            |m| {
                Ok(Request::IssueEdit {
                    reff: resolve_reff(m)?,
                    title: opt_str(m, "title"),
                    status: opt_str(m, "status"),
                    priority: opt_str(m, "priority"),
                    description: opt_str(m, "body"),
                })
            },
        ),
        Spec::req(
            "move",
            "Set project (truth) and/or board position (ref optional — inferred from git).",
            vec![
                A::pos_opt("reff", "Issue ref."),
                project_flag("Move to project (explicit only — membership is never inferred)."),
                A::flag("top", "Move to top of its column."),
                A::flag("bottom", "Move to bottom of its column."),
                A::val("before", "Place before this ref."),
                A::val("after", "Place after this ref."),
            ],
            |m| {
                let pos = if flag(m, "top") {
                    Some(BoardPos::Top)
                } else if flag(m, "bottom") {
                    Some(BoardPos::Bottom)
                } else if let Some(r) = opt_str(m, "before") {
                    Some(BoardPos::Before { reff: r })
                } else {
                    opt_str(m, "after").map(|r| BoardPos::After { reff: r })
                };
                Ok(Request::IssueMove {
                    reff: resolve_reff(m)?,
                    project: opt_str(m, "project"),
                    pos,
                })
            },
        ),
        Spec::req(
            "assign",
            "Add/remove assignees (present-key set).",
            vec![
                A::pos("reff", "Issue ref."),
                A::pos_multi("who", "Members to (un)assign."),
                A::flag("remove", "Remove instead of add."),
            ],
            |m| {
                Ok(Request::Assign {
                    reff: req_str(m, "reff"),
                    who: multi(m, "who"),
                    add: !flag(m, "remove"),
                })
            },
        ),
        Spec::req(
            "label",
            "Add (`+LABEL`) / remove (`-LABEL`) labels on an issue.",
            vec![
                A::pos("reff", "Issue ref."),
                A::pos_multi("tokens", "Tokens like `+bug` (add) or `-wip` (remove).")
                    .hyphen()
                    .trailing(),
            ],
            |m| {
                let mut add = Vec::new();
                let mut remove = Vec::new();
                for t in multi(m, "tokens") {
                    if let Some(l) = t.strip_prefix('+') {
                        add.push(l.to_string());
                    } else if let Some(l) = t.strip_prefix('-') {
                        remove.push(l.to_string());
                    } else {
                        add.push(t);
                    }
                }
                Ok(Request::Label {
                    reff: req_str(m, "reff"),
                    add,
                    remove,
                })
            },
        ),
        Spec::req(
            "comment",
            "Append a comment (immutable body). One arg on a KEY-n branch = the body (ref inferred). No BODY → read stdin.",
            vec![
                A::pos_opt("reff", "Issue ref (optional on a KEY-n branch when a body is given)."),
                A::pos_opt("body", "Comment body (omit to read stdin)."),
            ],
            |m| {
                // Grammar: `comment [ref] [body]`. With ONE positional, it's
                // ambiguous — resolve it as the BODY and infer the ref from the
                // git branch (the branch-native loop: `lait comment "found it"`).
                // A ref that happens to look like a body still works explicitly:
                // `lait comment ENG-1 "body"`.
                let (reff, body) = match (opt_str(m, "reff"), opt_str(m, "body")) {
                    (Some(r), Some(b)) => (Some(r), Some(b)),
                    (Some(only), None) => (None, Some(only)),
                    _ => (None, None),
                };
                let reff = match reff {
                    Some(r) => r,
                    None => infer_ref_from_git_branch().ok_or_else(|| {
                        anyhow!(
                            "no issue ref given, and none could be inferred from the git branch — \
                             pass one: `lait comment ENG-142 \"...\"`"
                        )
                    })?,
                };
                let body = match body {
                    Some(b) => b,
                    None => {
                        use std::io::Read;
                        let mut s = String::new();
                        std::io::stdin().read_to_string(&mut s).ok();
                        s.trim_end().to_string()
                    }
                };
                Ok(Request::Comment { reff, body })
            },
        ),
        Spec::req(
            "delete",
            "Delete (tombstone) an issue (ref optional — inferred from git).",
            vec![A::pos_opt("reff", "Issue ref.")],
            |m| {
                Ok(Request::IssueDelete {
                    reff: resolve_reff(m)?,
                })
            },
        ),
        Spec::req(
            "history",
            "The issue's derived activity/time-travel feed (ref optional — inferred from git).",
            vec![A::pos_opt("reff", "Issue ref.")],
            |m| {
                Ok(Request::History {
                    reff: resolve_reff(m)?,
                })
            },
        ),
        // ---- registries (grouped: bare = list) ----
        Spec {
            subs: vec![
                Spec::req(
                    "add",
                    "Create a project: `projects add OPS [\"Operations\"]` (name defaults to the key).",
                    vec![
                        A::pos("key", "Short KEY (e.g. ENG) — becomes the KEY in KEY-1 refs."),
                        A::pos_opt("name", "Project name (default: the key, title-cased)."),
                    ],
                    |m| {
                        let key = req_str(m, "key");
                        let name = opt_str(m, "name").unwrap_or_else(|| title_case(&key));
                        Ok(Request::ProjectNew { name, key })
                    },
                )
                .alias(&["new"]),
                Spec::req("ls", "List projects.", vec![], |_| Ok(Request::ProjectList)),
            ],
            ..Spec::req("projects", "Manage the project registry.", vec![], |_| {
                Ok(Request::ProjectList)
            })
        },
        Spec {
            subs: vec![
                Spec::req(
                    "new",
                    "Create a label.",
                    vec![
                        A::pos("name", "Label name."),
                        A::val("color", "Hex/name color."),
                    ],
                    |m| {
                        Ok(Request::LabelNew {
                            name: req_str(m, "name"),
                            color: opt_str(m, "color"),
                        })
                    },
                ),
                Spec::req("ls", "List labels.", vec![], |_| Ok(Request::LabelList)),
            ],
            ..Spec::req("labels", "Manage the label registry.", vec![], |_| {
                Ok(Request::LabelList)
            })
        },
        Spec {
            subs: vec![
                Spec::req(
                    "add",
                    "Add a member (admin-only). Seals the space key to them.",
                    vec![
                        A::pos(
                            "who",
                            "@me, a local name, a key id-prefix, or a 64-hex key.",
                        ),
                        A::flag("admin", "Grant admin."),
                        A::val("as_name", "Attach a local name as you add them.")
                            .long("as")
                            .value_name("NAME"),
                    ],
                    |m| {
                        Ok(Request::MemberAdd {
                            who: req_str(m, "who"),
                            admin: flag(m, "admin"),
                            as_name: opt_str(m, "as_name"),
                        })
                    },
                ),
                Spec::req(
                    "remove",
                    "Remove a member (admin-only) and rotate the space key.",
                    vec![A::pos("who", "A user ref.")],
                    |m| {
                        Ok(Request::MemberRemove {
                            who: req_str(m, "who"),
                        })
                    },
                ),
                Spec::req("requests", "List pending join requests.", vec![], |_| {
                    Ok(Request::MemberRequests)
                }),
                Spec::req(
                    "approve",
                    "Approve a pending join request by id-prefix / key (admin-only).",
                    vec![
                        A::pos("who", "A key id-prefix or a 64-hex key."),
                        A::val("as_name", "Attach a local name as you approve them.")
                            .long("as")
                            .value_name("NAME"),
                    ],
                    |m| {
                        Ok(Request::MemberApprove {
                            who: req_str(m, "who"),
                            as_name: opt_str(m, "as_name"),
                        })
                    },
                ),
                Spec::req(
                    "name",
                    "Set (or clear) a local name for a member/key.",
                    vec![
                        A::pos("who", "A key id-prefix, a full key, or an existing name."),
                        A::pos_opt("name", "The name to assign (omit or \"\" to clear).")
                            .default(""),
                    ],
                    |m| {
                        Ok(Request::MemberAlias {
                            who: req_str(m, "who"),
                            name: req_str(m, "name"),
                        })
                    },
                )
                .alias(&["alias"]),
                Spec::req(
                    "rotate-key",
                    "Rotate the space key (admin-only).",
                    vec![],
                    |_| Ok(Request::KeyRotate),
                ),
                Spec::req("ls", "List members.", vec![], |_| Ok(Request::Members)),
            ],
            ..Spec::req(
                "members",
                "Manage space membership (the signed ACL, P3). `members` lists.",
                vec![],
                |_| Ok(Request::Members),
            )
        },
        Spec::req(
            "activity",
            "Workspace-wide recent transitions.",
            vec![A::val("since", "Only events after this seq.").default("0")],
            |m| {
                Ok(Request::Activity {
                    since: u64_arg(m, "since")?,
                })
            },
        ),
        Spec::special(
            "tui",
            "Launch the full-screen TUI board.",
            vec![],
            Special::Tui,
        ),
        Spec::req(
            "doctor",
            "Guided-join verifier: diagnose why you can't get to work yet.",
            vec![],
            |_| {
                Ok(Request::Diagnose {
                    expected_workspace: None,
                })
            },
        )
        .alias(&["verify"]),
        Spec {
            subs: vec![
                Spec::special(
                    "ls",
                    "List known spaces with status (default).",
                    vec![],
                    Special::Workspaces,
                ),
                Spec::special(
                    "forget",
                    "Deregister a space (registry only — never touches the store on disk).",
                    vec![A::pos("sel", "A store path, ws_ id, or unique id prefix.")],
                    Special::WorkspacesForget,
                ),
                Spec::special(
                    "prune",
                    "Drop registry entries whose store no longer exists on disk.",
                    vec![],
                    Special::WorkspacesPrune,
                ),
            ],
            ..Spec::special(
                "spaces",
                "Every space on this machine: name, id, origin, status, projects, path.",
                vec![],
                Special::Workspaces,
            )
            .alias(&["workspaces"])
        },
        Spec {
            subs: vec![
                Spec::special(
                    "get",
                    "Print a key's effective value (store layer wins over global).",
                    vec![A::pos("key", "Config key (see `lait config ls`).")],
                    Special::ConfigGet,
                ),
                Spec::special(
                    "set",
                    "Set a key. Store layer by default; --global for the machine layer.",
                    vec![
                        A::pos("key", "Config key (e.g. user.nick, project.default)."),
                        A::pos("value", "The value."),
                        A::flag("global", "Write the global layer instead of this store's."),
                    ],
                    Special::ConfigSet,
                ),
                Spec::special(
                    "unset",
                    "Remove a key from a layer.",
                    vec![
                        A::pos("key", "Config key."),
                        A::flag("global", "Remove from the global layer instead."),
                    ],
                    Special::ConfigUnset,
                ),
                Spec::special(
                    "ls",
                    "List effective settings, annotated with their origin layer (default).",
                    vec![],
                    Special::ConfigList,
                ),
            ],
            ..Spec::special(
                "config",
                "Get/set layered local settings (global + per-store; store wins).",
                vec![],
                Special::ConfigList,
            )
        },
        Spec::special("id", "Print our endpoint id.", vec![], Special::Id),
        Spec::special(
            "daemon",
            "Run the node daemon in the foreground.",
            vec![A::flag(
                "seed",
                "Run as an always-on seed (never idle-shuts-down).",
            )],
            Special::Daemon,
        )
        .service(),
        Spec::special(
            "mcp",
            "Run the MCP server over stdio (for agents).",
            vec![],
            Special::Mcp,
        )
        .service(),
        Spec::special(
            "install-mcp",
            "Register lait's MCP server with an agent's config.",
            vec![A::flag("print", "Print the config instead of writing it.")],
            Special::InstallMcp,
        )
        .customize(|c| {
            c.arg(
                Arg::new("client")
                    .long("client")
                    .value_parser(clap::value_parser!(Client))
                    .default_value("claude")
                    .help("Target agent client."),
            )
            .arg(
                Arg::new("scope")
                    .long("scope")
                    .value_parser(clap::value_parser!(Scope))
                    .help("Config scope (user/project)."),
            )
            .arg(
                Arg::new("name")
                    .long("name")
                    .default_value("lait")
                    .help("Server name in the client config."),
            )
        }),
        Spec::req("status", "Show node and space status.", vec![], |_| {
            Ok(Request::Status)
        }),
        Spec::special(
            "invite",
            "Print a base32 ticket (+ QR) others use to join your space.",
            vec![
                A::val(
                    "email",
                    "Open your mail client with a prefilled invite to this address.",
                ),
                A::flag(
                    "require_approval",
                    "Mint a pass-less ticket: the joiner lands as a pending request.",
                )
                .long("require-approval")
                .conflicts(&["reusable", "ttl_hours"]),
                A::flag(
                    "reusable",
                    "Let one ticket admit your whole team until it expires.",
                ),
                A::val(
                    "ttl_hours",
                    "Hours until the pass expires (default 168 = 7 days).",
                )
                .long("ttl-hours")
                .value_name("HOURS"),
            ],
            Special::Invite,
        ),
        Spec::special(
            "join",
            "Join a space from an invite link (creates the store here, or at --dir).",
            vec![
                A::pos("ticket", "The invite link / ticket from `lait invite`."),
                A::val("nick", "Set your display name as you join."),
                A::val("dir", "Create the joined space's store under this directory."),
            ],
            Special::Join,
        )
        .alias(&["connect"]),
        Spec {
            subs: vec![
                Spec::req(
                    "add",
                    "Pin a remote for this space (an invite link for it, or an endpoint id).",
                    vec![A::pos("target", "An invite link or an endpoint id.")],
                    |m| {
                        Ok(Request::SeedAdd {
                            arg: req_str(m, "target"),
                        })
                    },
                ),
                Spec::req(
                    "ls",
                    "List pinned remotes and reachability.",
                    vec![],
                    |_| Ok(Request::SeedList),
                ),
                Spec::req(
                    "rm",
                    "Unpin a remote by endpoint id (or prefix) or name.",
                    vec![A::pos("who", "Endpoint id (or prefix) or name to unpin.")],
                    |m| {
                        Ok(Request::SeedRemove {
                            who: req_str(m, "who"),
                        })
                    },
                ),
            ],
            sub_required: true,
            ..Spec::req(
                "remote",
                "Manage pinned remotes (always-on peers your node always dials).",
                vec![],
                |_| Ok(Request::SeedList),
            )
            .alias(&["seed"])
        },
        Spec::req(
            "log",
            "Print presence/system events (optionally only after --since).",
            vec![A::val("since", "Only events after this seq.").default("0")],
            |m| {
                Ok(Request::Log {
                    since: u64_arg(m, "since")?,
                })
            },
        ),
        Spec::special(
            "watch",
            "Follow presence events like a notification stream.",
            vec![
                A::val("since", "Start after this seq."),
                A::val("exec", "Run a hook command per event."),
                A::flag("notify", "Emit a desktop notification per event."),
            ],
            Special::Watch,
        ),
        Spec::req("who", "List peers and their online status.", vec![], |_| {
            Ok(Request::Who)
        }),
        Spec::special(
            "profiles",
            "List your profiles — each a separate private identity.",
            vec![],
            Special::Profiles,
        )
        .alias(&["agents"]),
        Spec::special(
            "resume",
            "Switch to (or create) a named profile for this session.",
            vec![A::pos("name", "Profile name.")],
            Special::Resume,
        ),
        Spec::special(
            "update",
            "Update lait in place from the latest GitHub release.",
            vec![],
            Special::Update,
        ),
        // `stop` the word belongs to the work loop (put an issue down); the
        // daemon's off-switch is `shutdown`.
        Spec::req("shutdown", "Stop the running daemon.", vec![], |_| {
            Ok(Request::Stop)
        }),
        Spec::special(
            "completions",
            "Print shell completions to stdout for the given shell.",
            vec![],
            Special::Completions,
        )
        .customize(|c| {
            c.arg(
                Arg::new("shell")
                    .value_parser(clap::value_parser!(Shell))
                    .required(true)
                    .help("bash, zsh, fish, powershell, or elvish."),
            )
        }),
        Spec::special(
            "man",
            "Render the lait(1) man page (roff) to stdout.",
            vec![],
            Special::Man,
        ),
    ];
    // Help buckets in one greppable place: the first help screen leads with the
    // daily loop; registries/settings follow; node plumbing sinks to the bottom.
    // Within a bucket, declaration order holds.
    for s in &mut v {
        s.order = match s.name {
            "new" | "start" | "done" | "stop" | "inbox" | "show" | "board" | "ls" | "edit"
            | "move" | "assign" | "label" | "comment" | "delete" | "history" | "activity"
            | "tui" => ORDER_DAILY,
            "init" | "join" | "invite" | "spaces" | "members" | "doctor" | "status" | "who" => {
                ORDER_SHARE
            }
            "projects" | "labels" | "config" | "profiles" | "resume" => ORDER_DEFAULT,
            _ => ORDER_NODE,
        };
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_n_inference_from_branch_names() {
        // Common branch shapes → KEY-n (key upper-cased).
        assert_eq!(parse_key_n("eng-142-fix-login").as_deref(), Some("ENG-142"));
        assert_eq!(parse_key_n("ENG-7").as_deref(), Some("ENG-7"));
        assert_eq!(parse_key_n("feature/eng-142-x").as_deref(), Some("ENG-142"));
        assert_eq!(parse_key_n("bob/PROJ-3-thing").as_deref(), Some("PROJ-3"));
        // No KEY-n present → nothing inferred (fall back to explicit ref).
        assert_eq!(parse_key_n("main"), None);
        assert_eq!(parse_key_n("142-eng"), None);
        assert_eq!(parse_key_n("release/v0.4.5"), None);
        assert_eq!(parse_key_n("feat/onboarding-dx-bridge"), None);
    }

    #[test]
    fn cli_tree_builds_and_validates() {
        // clap panics on a malformed tree (dup ids, bad positionals); this asserts
        // the whole registry assembles into a legal Command.
        build_cli(&specs()).debug_assert();
    }
}
