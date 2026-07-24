//! Programmatic clap command registry.
//!
//! The CLI command set is defined as **data** — a `Vec<Spec>` built by
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
    Serve,
    Invite,
    Join,
    Watch,
    Completions,
    Man,
    Profiles,
    Resume,
    Spaces,
    SpacesForget,
    SpacesPrune,
    ConfigGet,
    ConfigSet,
    ConfigUnset,
    ConfigList,
    Update,
    /// New-machine side of device enrollment: consume a `device invite` token
    /// and print a consent blob (no daemon, no store — just this identity).
    DeviceAccept,
    /// File-touching halves of attachments (CREATE-5): read/encode on attach,
    /// decode/write on get — the daemon only ever sees base64.
    Attach,
    AttachmentGet,
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
        // active issues) — the most valuable keystroke goes to the
        // most-asked question, not to help. `lait help` / `-h` still work.
        .arg(
            Arg::new("home")
                .long("home")
                .global(true)
                .action(ArgAction::Set)
                .help_heading(GLOBAL_HEADING)
                .help("Select the node's home directory (overrides $LAIT_HOME)."),
        )
        .arg(
            Arg::new("space")
                .short('w')
                .long("space")
                .alias("workspace")
                .global(true)
                .action(ArgAction::Set)
                .conflicts_with("home")
                .value_name("SEL")
                .help_heading(GLOBAL_HEADING)
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
                .help_heading(GLOBAL_HEADING)
                .help("Emit the versioned JSON DTO instead of human output."),
        )
        .arg(
            Arg::new("yes")
                .short('y')
                .long("yes")
                .global(true)
                .action(ArgAction::SetTrue)
                .help_heading(GLOBAL_HEADING)
                .help("Assume yes: skip confirmation prompts (for scripts and CI)."),
        )
        .arg(
            Arg::new("no_color")
                .long("no-color")
                .global(true)
                .action(ArgAction::SetTrue)
                .help_heading(GLOBAL_HEADING)
                .help("Disable ANSI colours."),
        );
    for s in specs {
        root = root.subcommand(build_sub(s));
    }
    root
}

/// The heading the four global flags file under. Without it clap interleaves
/// them with each command's own flags in declaration order (`--home` between
/// `-p` and `-a` on `lait new`), so the flags that apply *everywhere* read as
/// command-specific noise. One heading separates the two kinds.
const GLOBAL_HEADING: &str = "Global Options";

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
/// them — the seam interactive clients dispatch through. The caller decides per
/// `Special` whether
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
/// — top-level verbs plus one level of group subcommands ("members name").
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
        // ---- space founding ----
        Spec::special(
            "init",
            "Found a new space here (mints the genesis; seeds a first project).",
            vec![
                A::val("name", "Space display name (default: this directory's name)."),
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
                A::val("due", "Due date (YYYY-MM-DD or unix seconds)."),
                A::val("estimate", "Estimate points.").short('e'),
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
                    due: opt_str(m, "due"),
                    estimate: opt_str(m, "estimate")
                        .map(|s| {
                            s.parse::<u32>()
                                .map_err(|_| anyhow!("--estimate takes a whole number of points"))
                        })
                        .transpose()?,
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
                A::val("due", "Due date (YYYY-MM-DD, unix seconds, or `none` to clear)."),
                A::val("estimate", "Estimate points, or `none` to clear.").short('e'),
            ],
            |m| {
                Ok(Request::IssueEdit {
                    reff: resolve_reff(m)?,
                    title: opt_str(m, "title"),
                    status: opt_str(m, "status"),
                    priority: opt_str(m, "priority"),
                    description: opt_str(m, "body"),
                    due: opt_str(m, "due"),
                    estimate: opt_str(m, "estimate"),
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
                A::val("reply_to", "Reply to a comment (its `cmt_…` id, from `show --json`).")
                    .long("reply-to"),
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
                Ok(Request::Comment {
                    reff,
                    body,
                    reply_to: opt_str(m, "reply_to"),
                })
            },
        ),
        Spec::req(
            "react",
            "Toggle an emoji reaction on a comment (its `cmt_…` id, from `show --json`).",
            vec![
                A::pos("reff", "Issue ref."),
                A::pos("comment", "Comment id (`cmt_…`)."),
                A::pos("emoji", "The emoji."),
                A::flag("remove", "Remove your reaction instead of adding it."),
            ],
            |m| {
                Ok(Request::React {
                    reff: req_str(m, "reff"),
                    comment: req_str(m, "comment"),
                    emoji: req_str(m, "emoji"),
                    on: !flag(m, "remove"),
                })
            },
        ),
        Spec::req(
            "world-upgrade",
            "Activate this build's reviewed IssuesWorld implementation for the space \
             (admin; no-op when already active). Run after upgrading builds when the \
             daemon warns about an implementation mismatch.",
            vec![],
            |_| Ok(Request::WorldUpgrade),
        ),
        Spec::req(
            "delete",
            "Delete (tombstone) an issue \u{2014} a signed, reversible authority op \
             (ref optional \u{2014} inferred from git).",
            vec![A::pos_opt("reff", "Issue ref.")],
            |m| {
                Ok(Request::IssueDelete {
                    reff: resolve_reff(m)?,
                })
            },
        ),
        Spec::req(
            "restore",
            "Restore a deleted issue (ref optional \u{2014} inferred from git).",
            vec![A::pos_opt("reff", "Issue ref.")],
            |m| {
                Ok(Request::IssueRestore {
                    reff: resolve_reff(m)?,
                })
            },
        )
        .alias(&["undelete"]),
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
        Spec::req(
            "link",
            "Link two issues: `link ENG-1 blocks ENG-2` (kinds: blocks/relates/duplicates; two refs = relates).",
            vec![
                A::pos("reff", "Issue ref."),
                A::pos("kind_or_target", "Link kind, or the target ref (kind defaults to relates)."),
                A::pos_opt("target", "Target issue ref (when a kind was given)."),
            ],
            |m| {
                let reff = req_str(m, "reff");
                let a = req_str(m, "kind_or_target");
                let (kind, target) = match opt_str(m, "target") {
                    Some(t) => (a, t),
                    None => ("relates".to_string(), a),
                };
                Ok(Request::IssueLink { reff, kind, target })
            },
        ),
        Spec::req(
            "unlink",
            "Remove an issue link: `unlink ENG-1 blocks ENG-2`.",
            vec![
                A::pos("reff", "Issue ref."),
                A::pos("kind_or_target", "Link kind, or the target ref (kind defaults to relates)."),
                A::pos_opt("target", "Target issue ref (when a kind was given)."),
            ],
            |m| {
                let reff = req_str(m, "reff");
                let a = req_str(m, "kind_or_target");
                let (kind, target) = match opt_str(m, "target") {
                    Some(t) => (a, t),
                    None => ("relates".to_string(), a),
                };
                Ok(Request::IssueUnlink { reff, kind, target })
            },
        ),
        Spec::req(
            "parent",
            "Set an issue's parent (sub-issue hierarchy): `parent ENG-3 ENG-1`; `--none` clears it.",
            vec![
                A::pos("reff", "Issue ref."),
                A::pos_opt("parent", "Parent issue ref (omit with --none to clear)."),
                A::flag("none", "Clear the parent (make it a top-level issue)."),
            ],
            |m| {
                let reff = req_str(m, "reff");
                let parent = opt_str(m, "parent");
                if parent.is_none() && !flag(m, "none") {
                    anyhow::bail!(
                        "give a parent ref, or --none to clear: `lait parent {reff} <epic>`"
                    );
                }
                Ok(Request::IssueParent { reff, parent })
            },
        ),
        Spec::req(
            "graph",
            "The issue's relations: parent, sub-issues, links, and open blockers (ref optional — inferred from git).",
            vec![A::pos_opt("reff", "Issue ref.")],
            |m| {
                Ok(Request::IssueGraph {
                    reff: resolve_reff(m)?,
                })
            },
        )
        .alias(&["links", "deps"]),
        // ---- registries (grouped: bare = list) ----
        Spec {
            subs: vec![
                Spec::req(
                    "add",
                    "Create a project: `projects add OPS [\"Operations\"]` (name defaults to the key).",
                    vec![
                        A::pos("key", "Short KEY (e.g. ENG) — becomes the KEY in KEY-1 refs."),
                        A::pos_opt("name", "Project name (default: the key, title-cased)."),
                        A::val("color", "Hex/name color (default: blue)."),
                    ],
                    |m| {
                        let key = req_str(m, "key");
                        let name = opt_str(m, "name").unwrap_or_else(|| title_case(&key));
                        Ok(Request::ProjectNew {
                            name,
                            key,
                            color: opt_str(m, "color"),
                        })
                    },
                )
                .alias(&["new"]),
                Spec::req(
                    "edit",
                    "Edit a project's overview: name/color/description/lead/dates. `projects edit ENG --name Engineering --target 2026-09-01`. The KEY is immutable.",
                    vec![
                        A::pos("project", "Project KEY or prj_ id."),
                        A::val("name", "New name."),
                        A::val("color", "New color (hex/name)."),
                        A::val("description", "Overview markdown."),
                        A::val("lead", "Lead actor key (or `none` to clear)."),
                        A::val("start", "Start date YYYY-MM-DD (or `none`)."),
                        A::val("target", "Target date YYYY-MM-DD (or `none`)."),
                        A::val("team", "Owning team (KEY/name, or `none` to clear).")
                            .long("team")
                            .value_name("TEAM"),
                        A::flag("archive", "Soft-hide this project from pickers and all-project lists."),
                        A::flag("unarchive", "Restore a previously archived project."),
                    ],
                    |m| {
                        Ok(Request::ProjectEdit {
                            project: req_str(m, "project"),
                            name: opt_str(m, "name"),
                            color: opt_str(m, "color"),
                            description: opt_str(m, "description"),
                            lead: opt_str(m, "lead"),
                            start: opt_str(m, "start"),
                            target: opt_str(m, "target"),
                            team: opt_str(m, "team"),
                            archived: if flag(m, "archive") {
                                Some(true)
                            } else if flag(m, "unarchive") {
                                Some(false)
                            } else {
                                None
                            },
                        })
                    },
                ),
                Spec::req(
                    "delete",
                    "Hard-delete an EMPTY project (refused while any issue still references it).",
                    vec![A::pos("project", "Project KEY or prj_ id.")],
                    |m| {
                        Ok(Request::ProjectDelete {
                            project: req_str(m, "project"),
                        })
                    },
                ),
                Spec::req("ls", "List projects.", vec![], |_| Ok(Request::ProjectList)),
                Spec::req(
                    "update",
                    "Post a status update to a project's feed: `projects update ENG \"Shipped the API\" --health on_track`.",
                    vec![
                        A::pos("project", "Project KEY or prj_ id."),
                        A::pos("body", "The update text."),
                        A::val("health", "on_track | at_risk | off_track."),
                    ],
                    |m| {
                        Ok(Request::ProjectUpdatePost {
                            project: req_str(m, "project"),
                            body: req_str(m, "body"),
                            health: opt_str(m, "health"),
                        })
                    },
                ),
                Spec::req(
                    "updates",
                    "Show a project's status-update feed (newest first).",
                    vec![A::pos("project", "Project KEY or prj_ id.")],
                    |m| {
                        Ok(Request::ProjectUpdates {
                            project: req_str(m, "project"),
                        })
                    },
                ),
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
                Spec::req(
                    "edit",
                    "Rename and/or recolor a label: `labels edit bug --name defect --color red`.",
                    vec![
                        A::pos("label", "Label name or lbl_ id."),
                        A::val("name", "New name."),
                        A::val("color", "New color (hex/name)."),
                    ],
                    |m| {
                        Ok(Request::LabelEdit {
                            label: req_str(m, "label"),
                            name: opt_str(m, "name"),
                            color: opt_str(m, "color"),
                        })
                    },
                ),
                Spec::req(
                    "rm",
                    "Delete a label from the registry: `labels rm bug`. Issues keep the raw id until it's re-created.",
                    vec![A::pos("label", "Label name or lbl_ id.")],
                    |m| {
                        Ok(Request::LabelDelete {
                            label: req_str(m, "label"),
                        })
                    },
                )
                .alias(&["delete"]),
                Spec::req("ls", "List labels.", vec![], |_| Ok(Request::LabelList)),
            ],
            ..Spec::req("labels", "Manage the label registry.", vec![], |_| {
                Ok(Request::LabelList)
            })
        },
        Spec::req(
            "follow",
            "Subscribe to an issue's activity without being assigned (it lands in your inbox).",
            vec![A::pos("reff", "Issue ref.")],
            |m| {
                Ok(Request::Follow {
                    reff: req_str(m, "reff"),
                    on: true,
                })
            },
        ),
        Spec::req(
            "unfollow",
            "Unsubscribe from an issue's activity.",
            vec![A::pos("reff", "Issue ref.")],
            |m| {
                Ok(Request::Follow {
                    reff: req_str(m, "reff"),
                    on: false,
                })
            },
        ),
        Spec {
            subs: vec![
                Spec::req(
                    "ls",
                    "List a project's milestones with progress.",
                    vec![A::pos("project", "Project KEY or prj_ id.")],
                    |m| {
                        Ok(Request::MilestoneList {
                            project: req_str(m, "project"),
                        })
                    },
                ),
                Spec::req(
                    "new",
                    "Create a milestone: `milestone new ENG \"Beta\" --target 2026-09-01`.",
                    vec![
                        A::pos("project", "Project KEY or prj_ id."),
                        A::pos("name", "Milestone name."),
                        A::val("target", "Target date YYYY-MM-DD (or `none`)."),
                    ],
                    |m| {
                        Ok(Request::MilestoneSet {
                            project: req_str(m, "project"),
                            milestone: None,
                            name: Some(req_str(m, "name")),
                            target: opt_str(m, "target"),
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "edit",
                    "Rename or retarget a milestone.",
                    vec![
                        A::pos("project", "Project KEY or prj_ id."),
                        A::pos("milestone", "Milestone name or mls_ id."),
                        A::val("name", "New name."),
                        A::val("target", "Target date YYYY-MM-DD (or `none`)."),
                    ],
                    |m| {
                        Ok(Request::MilestoneSet {
                            project: req_str(m, "project"),
                            milestone: opt_str(m, "milestone"),
                            name: opt_str(m, "name"),
                            target: opt_str(m, "target"),
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "rm",
                    "Remove a milestone (issues keep working; the pointer reads as cleared).",
                    vec![
                        A::pos("project", "Project KEY or prj_ id."),
                        A::pos("milestone", "Milestone name or mls_ id."),
                    ],
                    |m| {
                        Ok(Request::MilestoneSet {
                            project: req_str(m, "project"),
                            milestone: opt_str(m, "milestone"),
                            name: None,
                            target: None,
                            remove: true,
                        })
                    },
                ),
                Spec::req(
                    "set",
                    "Point an issue at a milestone in its project (`none` clears).",
                    vec![
                        A::pos("reff", "Issue ref."),
                        A::pos("milestone", "Milestone name, mls_ id, or `none`."),
                    ],
                    |m| {
                        Ok(Request::IssueMilestone {
                            reff: req_str(m, "reff"),
                            milestone: opt_str(m, "milestone"),
                        })
                    },
                ),
            ],
            ..Spec::req(
                "milestone",
                "Project milestones: named targets with derived progress.",
                vec![],
                |_| anyhow::bail!("pick a subcommand: ls | new | edit | rm | set"),
            )
        },
        Spec {
            subs: vec![
                Spec::req(
                    "ls",
                    "List a project's cycles with counts.",
                    vec![A::pos("project", "Project KEY or prj_ id.")],
                    |m| {
                        Ok(Request::CycleList {
                            project: req_str(m, "project"),
                        })
                    },
                ),
                Spec::req(
                    "new",
                    "Create a cycle: `cycle new ENG \"Sprint 12\" --start 2026-08-01 --end 2026-08-14`.",
                    vec![
                        A::pos("project", "Project KEY or prj_ id."),
                        A::pos("name", "Cycle name."),
                        A::val("start", "Start date YYYY-MM-DD (or `none`)."),
                        A::val("end", "End date YYYY-MM-DD (or `none`)."),
                    ],
                    |m| {
                        Ok(Request::CycleSet {
                            project: req_str(m, "project"),
                            cycle: None,
                            name: Some(req_str(m, "name")),
                            start: opt_str(m, "start"),
                            end: opt_str(m, "end"),
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "edit",
                    "Rename or re-box a cycle.",
                    vec![
                        A::pos("project", "Project KEY or prj_ id."),
                        A::pos("cycle", "Cycle name or cyc_ id."),
                        A::val("name", "New name."),
                        A::val("start", "Start date YYYY-MM-DD (or `none`)."),
                        A::val("end", "End date YYYY-MM-DD (or `none`)."),
                    ],
                    |m| {
                        Ok(Request::CycleSet {
                            project: req_str(m, "project"),
                            cycle: opt_str(m, "cycle"),
                            name: opt_str(m, "name"),
                            start: opt_str(m, "start"),
                            end: opt_str(m, "end"),
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "rm",
                    "Remove a cycle (scheduled issues read as unscheduled).",
                    vec![
                        A::pos("project", "Project KEY or prj_ id."),
                        A::pos("cycle", "Cycle name or cyc_ id."),
                    ],
                    |m| {
                        Ok(Request::CycleSet {
                            project: req_str(m, "project"),
                            cycle: opt_str(m, "cycle"),
                            name: None,
                            start: None,
                            end: None,
                            remove: true,
                        })
                    },
                ),
                Spec::req(
                    "set",
                    "Schedule an issue into a cycle (`none` clears).",
                    vec![
                        A::pos("reff", "Issue ref."),
                        A::pos("cycle", "Cycle name, cyc_ id, or `none`."),
                    ],
                    |m| {
                        Ok(Request::IssueCycle {
                            reff: req_str(m, "reff"),
                            cycle: opt_str(m, "cycle"),
                        })
                    },
                ),
            ],
            ..Spec::req(
                "cycle",
                "Cycles: time-boxed iterations per project.",
                vec![],
                |_| anyhow::bail!("pick a subcommand: ls | new | edit | rm | set"),
            )
        },
        Spec {
            subs: vec![
                Spec::req(
                    "new",
                    "Create an initiative: `initiative new \"Q3 platform\" --owner act_… --target 2026-09-30`.",
                    vec![
                        A::pos("name", "Initiative name."),
                        A::val("description", "What this goal is."),
                        A::val("owner", "Owner actor key (or `none`)."),
                        A::val("health", "on_track | at_risk | off_track."),
                        A::val("target", "Target date YYYY-MM-DD (or `none`)."),
                    ],
                    |m| {
                        Ok(Request::InitiativeSet {
                            initiative: None,
                            name: Some(req_str(m, "name")),
                            description: opt_str(m, "description"),
                            owner: opt_str(m, "owner"),
                            health: opt_str(m, "health"),
                            target: opt_str(m, "target"),
                            add_projects: vec![],
                            remove_projects: vec![],
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "edit",
                    "Edit an initiative's fields, or its project membership with --add/--remove.",
                    vec![
                        A::pos("initiative", "Initiative name or ini_ id."),
                        A::val("name", "New name."),
                        A::val("description", "New description."),
                        A::val("owner", "Owner actor key (or `none`)."),
                        A::val("health", "on_track | at_risk | off_track."),
                        A::val("target", "Target date YYYY-MM-DD (or `none`)."),
                        A::val("add", "Project KEY to add (repeatable via comma list)."),
                        A::val("remove", "Project KEY to remove (comma list)."),
                    ],
                    |m| {
                        let split = |v: Option<String>| -> Vec<String> {
                            v.map(|s| {
                                s.split(',')
                                    .map(|p| p.trim().to_string())
                                    .filter(|p| !p.is_empty())
                                    .collect()
                            })
                            .unwrap_or_default()
                        };
                        Ok(Request::InitiativeSet {
                            initiative: Some(req_str(m, "initiative")),
                            name: opt_str(m, "name"),
                            description: opt_str(m, "description"),
                            owner: opt_str(m, "owner"),
                            health: opt_str(m, "health"),
                            target: opt_str(m, "target"),
                            add_projects: split(opt_str(m, "add")),
                            remove_projects: split(opt_str(m, "remove")),
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "rm",
                    "Remove an initiative (its projects are untouched).",
                    vec![A::pos("initiative", "Initiative name or ini_ id.")],
                    |m| {
                        Ok(Request::InitiativeSet {
                            initiative: Some(req_str(m, "initiative")),
                            name: None,
                            description: None,
                            owner: None,
                            health: None,
                            target: None,
                            add_projects: vec![],
                            remove_projects: vec![],
                            remove: true,
                        })
                    },
                ),
                Spec::req(
                    "ls",
                    "List initiatives with their project roll-ups.",
                    vec![],
                    |_| Ok(Request::InitiativeList),
                ),
            ],
            ..Spec::req(
                "initiatives",
                "Initiatives: named goals grouping projects, with roll-up progress.",
                vec![],
                |_| Ok(Request::InitiativeList),
            )
        }
        .alias(&["initiative"]),
        Spec {
            subs: vec![
                Spec::req(
                    "new",
                    "Create a team (admin-only): `team new \"Platform\" --key PLT`.",
                    vec![
                        A::pos("name", "Team name."),
                        A::val("key", "Short KEY (immutable after creation)."),
                        A::val("icon", "Emoji/icon."),
                        A::val("lead", "Lead actor key (or `none`)."),
                    ],
                    |m| {
                        Ok(Request::TeamSet {
                            team: None,
                            name: Some(req_str(m, "name")),
                            key: opt_str(m, "key"),
                            icon: opt_str(m, "icon"),
                            lead: opt_str(m, "lead"),
                            add_members: vec![],
                            remove_members: vec![],
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "edit",
                    "Edit a team's name/icon/lead (the KEY is immutable).",
                    vec![
                        A::pos("team", "Team KEY, name, or tm_ id."),
                        A::val("name", "New name."),
                        A::val("icon", "Emoji/icon."),
                        A::val("lead", "Lead actor key (or `none`)."),
                    ],
                    |m| {
                        Ok(Request::TeamSet {
                            team: Some(req_str(m, "team")),
                            name: opt_str(m, "name"),
                            key: None,
                            icon: opt_str(m, "icon"),
                            lead: opt_str(m, "lead"),
                            add_members: vec![],
                            remove_members: vec![],
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "add",
                    "Add members to a team (full actor keys, from `members ls`).",
                    vec![
                        A::pos("team", "Team KEY, name, or tm_ id."),
                        A::pos_multi("who", "Actor keys to add."),
                    ],
                    |m| {
                        Ok(Request::TeamSet {
                            team: Some(req_str(m, "team")),
                            name: None,
                            key: None,
                            icon: None,
                            lead: None,
                            add_members: multi(m, "who"),
                            remove_members: vec![],
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "remove",
                    "Remove members from a team.",
                    vec![
                        A::pos("team", "Team KEY, name, or tm_ id."),
                        A::pos_multi("who", "Actor keys to remove."),
                    ],
                    |m| {
                        Ok(Request::TeamSet {
                            team: Some(req_str(m, "team")),
                            name: None,
                            key: None,
                            icon: None,
                            lead: None,
                            add_members: vec![],
                            remove_members: multi(m, "who"),
                            remove: false,
                        })
                    },
                ),
                Spec::req(
                    "rm",
                    "Remove a team (owned projects keep working, unowned).",
                    vec![A::pos("team", "Team KEY, name, or tm_ id.")],
                    |m| {
                        Ok(Request::TeamSet {
                            team: Some(req_str(m, "team")),
                            name: None,
                            key: None,
                            icon: None,
                            lead: None,
                            add_members: vec![],
                            remove_members: vec![],
                            remove: true,
                        })
                    },
                ),
                Spec::req("ls", "List teams.", vec![], |_| Ok(Request::TeamList)),
            ],
            ..Spec::req(
                "teams",
                "Teams: durable work-owning groups with product-level membership.",
                vec![],
                |_| Ok(Request::TeamList),
            )
        }
        .alias(&["team"]),
        Spec {
            subs: vec![
                Spec::req(
                    "submit",
                    "Report work into the intake queue (no project needed).",
                    vec![
                        A::pos("title", "What needs looking at."),
                        A::val("body", "Details."),
                        A::val("source", "Where this came from."),
                    ],
                    |m| {
                        Ok(Request::TriageSubmit {
                            title: req_str(m, "title"),
                            body: opt_str(m, "body"),
                            source: opt_str(m, "source"),
                        })
                    },
                ),
                Spec::req(
                    "accept",
                    "Accept an item into a project as a fresh issue.",
                    vec![
                        A::pos("id", "The trg_ intake id."),
                        A::val("project", "Target project KEY.")
                            .long("project")
                            .short('p')
                            .value_name("PROJECT"),
                        A::val("note", "Review note."),
                    ],
                    |m| {
                        Ok(Request::TriageDecide {
                            id: req_str(m, "id"),
                            outcome: "accepted".into(),
                            project: opt_str(m, "project"),
                            target: None,
                            note: opt_str(m, "note"),
                        })
                    },
                ),
                Spec::req(
                    "decline",
                    "Decline an item (it stays in the record, decided).",
                    vec![
                        A::pos("id", "The trg_ intake id."),
                        A::val("note", "Why."),
                    ],
                    |m| {
                        Ok(Request::TriageDecide {
                            id: req_str(m, "id"),
                            outcome: "declined".into(),
                            project: None,
                            target: None,
                            note: opt_str(m, "note"),
                        })
                    },
                ),
                Spec::req(
                    "dupe",
                    "Mark an item as a duplicate of an existing issue.",
                    vec![
                        A::pos("id", "The trg_ intake id."),
                        A::pos("reff", "The existing issue's ref."),
                        A::val("note", "Review note."),
                    ],
                    |m| {
                        Ok(Request::TriageDecide {
                            id: req_str(m, "id"),
                            outcome: "duplicate".into(),
                            project: None,
                            target: opt_str(m, "reff"),
                            note: opt_str(m, "note"),
                        })
                    },
                ),
                Spec::req("ls", "The intake queue, pending first.", vec![], |_| {
                    Ok(Request::TriageList)
                }),
            ],
            ..Spec::req(
                "triage",
                "The intake queue: review reported work before it enters the backlog.",
                vec![],
                |_| Ok(Request::TriageList),
            )
        },
        Spec::special(
            "attach",
            "Attach a file to an issue (≤256 KiB; rides the issue's sync + encryption).",
            vec![
                A::pos("reff", "Issue ref."),
                A::pos("file", "Path to the file."),
                A::val("comment", "A comment id to associate it with."),
            ],
            Special::Attach,
        ),
        Spec {
            subs: vec![
                Spec::special(
                    "get",
                    "Save an attachment to disk.",
                    vec![
                        A::pos("reff", "Issue ref."),
                        A::pos("id", "The att_ attachment id (see `show`)."),
                        A::val("out", "Output path (default: the stored name)."),
                    ],
                    Special::AttachmentGet,
                ),
                Spec::req(
                    "rm",
                    "Remove an attachment.",
                    vec![
                        A::pos("reff", "Issue ref."),
                        A::pos("id", "The att_ attachment id."),
                    ],
                    |m| {
                        Ok(Request::Detach {
                            reff: req_str(m, "reff"),
                            id: req_str(m, "id"),
                        })
                    },
                ),
            ],
            ..Spec::special(
                "attachment",
                "Fetch or remove issue attachments.",
                vec![],
                Special::AttachmentGet,
            )
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
                    vec![A::pos("who", "A who-ref.")],
                    |m| {
                        Ok(Request::MemberRemove {
                            who: req_str(m, "who"),
                        })
                    },
                ),
                Spec::req(
                    "promote",
                    "Grant an existing member admin standing (admin-only).",
                    vec![A::pos(
                        "who",
                        "An actor id (full or unique act_ prefix) or a device id.",
                    )],
                    |m| {
                        Ok(Request::MemberSetRole {
                            who: req_str(m, "who"),
                            admin: true,
                        })
                    },
                ),
                Spec::req(
                    "demote",
                    "Reduce an admin to a plain member (admin-only; the last \
                     admin cannot be demoted).",
                    vec![A::pos(
                        "who",
                        "An actor id (full or unique act_ prefix) or a device id.",
                    )],
                    |m| {
                        Ok(Request::MemberSetRole {
                            who: req_str(m, "who"),
                            admin: false,
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
                    "agent",
                    "Sponsor an agent keypair (any member). It can read/write but not \
                     manage membership or delete; its standing dies with you.",
                    vec![A::pos("key", "The agent's 64-hex ed25519 public key.")],
                    |m| {
                        Ok(Request::AgentAdd {
                            key: req_str(m, "key"),
                        })
                    },
                ),
                Spec::req(
                    "log",
                    "The membership audit log: the signed ACL DAG in causal order, \
                     with each op's authorization verdict.",
                    vec![],
                    |_| Ok(Request::MemberLog),
                )
                .alias(&["history"]),
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
                "Manage space membership through the signed ACL. `members` lists.",
                vec![],
                |_| Ok(Request::Members),
            )
        },
        Spec {
            subs: vec![
                Spec::req(
                    "invite",
                    "Print a token to enroll another device into your actor.",
                    vec![],
                    |_| Ok(Request::DeviceInvite),
                ),
                Spec::special(
                    "accept",
                    "On a new machine: consume a `device invite` token and print a \
                     consent blob to hand back for `device add`.",
                    vec![A::pos("token", "The token from `lait device invite`.")],
                    Special::DeviceAccept,
                ),
                Spec::req(
                    "add",
                    "Add a device to your actor from its consent blob, sealing it \
                     the space key.",
                    vec![A::pos("consent", "The blob from `device accept`.")],
                    |m| {
                        Ok(Request::DeviceAdd {
                            consent: req_str(m, "consent"),
                        })
                    },
                ),
                Spec::req(
                    "revoke",
                    "Revoke a device from your actor and rotate the key to fence it.",
                    vec![A::pos("device", "The device's 64-hex key.")],
                    |m| {
                        Ok(Request::DeviceRevoke {
                            device: req_str(m, "device"),
                        })
                    },
                ),
                Spec::req("ls", "List your actor's devices.", vec![], |_| {
                    Ok(Request::DeviceList)
                }),
            ],
            ..Spec::req(
                "device",
                "Manage the devices of your actor (multi-device identity).",
                vec![],
                |_| Ok(Request::DeviceList),
            )
        },
        Spec::req(
            "recover",
            "Recover your actor with the offline recovery key: reset the device \
             set to this device (content access re-seals once a peer syncs).",
            vec![],
            |_| Ok(Request::Recover),
        ),
        Spec::req(
            "recover-space",
            "Break-glass: re-root the WHOLE space to this device using the \
             offline space recovery keys (threshold K-of-N), when the admins \
             are lost or compromised. Sync from a surviving peer first. Under a \
             group key, repeat on each holder until the threshold co-signs.",
            vec![],
            |_| Ok(Request::SpaceRecover),
        )
        .alias(&["recover-workspace"]),
        Spec::req(
            "recover-approve",
            "Co-sign a pending break-glass recovery as a holder of the group \
             recovery key. You must name who you expect it to re-root to (`--to`); \
             a request that re-roots elsewhere is refused before your share is used.",
            vec![
                A::pos(
                    "session",
                    "The recovery session id (from the initiator's `recover-space`).",
                ),
                A::multi(
                    "to",
                    "The actor id you expect the space to re-root to (repeatable).",
                )
                .required(),
            ],
            |m| {
                Ok(Request::SpaceRecoverApprove {
                    session: req_str(m, "session"),
                    expect: multi(m, "to"),
                })
            },
        ),
        Spec::req(
            "elevate-approve",
            "Co-sign a proposed change to the recovery arrangement, as a holder \
             of the current group key. You must name the proposal you expect \
             (`--proposal`); a request authorizing a different one is refused \
             before your share is used.",
            vec![
                A::pos(
                    "session",
                    "The request id (from the proposer's `elevate-recovery`).",
                ),
                A::val(
                    "proposal",
                    "The proposal id you expect this to authorize.",
                )
                .required(),
            ],
            |m| {
                Ok(Request::SpaceElevateApprove {
                    session: req_str(m, "session"),
                    proposal: req_str(m, "proposal"),
                })
            },
        ),
        Spec::req(
            "custody-export",
            "Export your share of the group recovery key as a portable, \
             passphrase-protected package, and verify it by reopening it. An \
             all-holders arrangement will NOT install until every custodian has \
             done this — a share that only your Windows account can open is one \
             profile loss from gone. Store the file where the passphrase cannot \
             also be found.",
            vec![
                A::pos("path", "Where to write the package."),
                A::val("passphrase", "Passphrase protecting the package (min 12 chars).")
                    .required(),
            ],
            |m| {
                Ok(Request::SpaceCustodyExport {
                    path: req_str(m, "path"),
                    passphrase: req_str(m, "passphrase"),
                })
            },
        ),
        Spec::req(
            "custody-import",
            "Restore your share of the group recovery key from a package written \
             by `custody-export` — after losing the account or machine that held \
             it. Refuses to overwrite a share this device can already read unless \
             you pass `--force`.",
            vec![
                A::pos("path", "The package to restore from."),
                A::val("passphrase", "The passphrase the package was written with.").required(),
                A::flag("force", "Replace a share this device can already read."),
            ],
            |m| {
                Ok(Request::SpaceCustodyImport {
                    path: req_str(m, "path"),
                    passphrase: req_str(m, "passphrase"),
                    force: flag(m, "force"),
                })
            },
        ),
        Spec::req(
            "elevate-recovery",
            "Elevate the space recovery authority from your solo bootstrap key \
             to a K-of-N group key (dealer-free FROST DKG), sharing the recovery \
             burden with co-founders. Run where space-recovery.key lives; the \
             co-founders must already be admitted members.",
            vec![
                A::pos_multi(
                    "cofounders",
                    "Co-founder device keys to share the recovery authority with.",
                ),
                A::val(
                    "threshold",
                    "Signatures required to recover (K). Defaults to all holders (N-of-N).",
                )
                .default("0"),
            ],
            |m| {
                Ok(Request::SpaceElevate {
                    cofounders: multi(m, "cofounders"),
                    k: u64_arg(m, "threshold")? as u16,
                })
            },
        ),
        Spec {
            subs: vec![
                Spec::req(
                    "show",
                    "One role's pinned definition (revision, capabilities, scope).",
                    vec![A::pos("role", "The role id (built-in or role_<ULID>).")],
                    |m| {
                        Ok(Request::RoleShow {
                            role: req_str(m, "role"),
                        })
                    },
                ),
                Spec::req(
                    "create",
                    "Create a custom role from registered capability ids. Space-scoped \
                     by default; -p makes it Project-scoped.",
                    vec![
                        A::pos("name", "Display name."),
                        A::multi("cap", "A registered capability id (repeatable).").required(),
                        A::val("project", "Make it a Project role, scoped for this project.")
                            .short('p'),
                        A::val("description", "What the role is for."),
                    ],
                    |m| {
                        Ok(Request::RoleCreate {
                            name: req_str(m, "name"),
                            description: opt_str(m, "description"),
                            project: opt_str(m, "project"),
                            capabilities: multi(m, "cap"),
                        })
                    },
                ),
                Spec::req(
                    "edit",
                    "Edit a custom role at an exact expected revision (a new revision \
                     becomes the head; existing assignments keep their original grant).",
                    vec![
                        A::pos("role", "The role id."),
                        A::val("expect-revision", "The head revision this edit builds on.")
                            .required(),
                        A::val("name", "Replacement display name."),
                        A::val("description", "Replacement description."),
                        A::multi("cap", "Replacement capability set (repeatable)."),
                    ],
                    |m| {
                        let caps = multi(m, "cap");
                        Ok(Request::RoleEdit {
                            role: req_str(m, "role"),
                            expect_revision: req_str(m, "expect-revision"),
                            name: opt_str(m, "name"),
                            description: opt_str(m, "description"),
                            capabilities: if caps.is_empty() { None } else { Some(caps) },
                        })
                    },
                ),
                Spec::req(
                    "delete",
                    "Tombstone a custom role at an exact expected revision.",
                    vec![
                        A::pos("role", "The role id."),
                        A::val("expect-revision", "The head revision this delete builds on.")
                            .required(),
                    ],
                    |m| {
                        Ok(Request::RoleDelete {
                            role: req_str(m, "role"),
                            expect_revision: req_str(m, "expect-revision"),
                        })
                    },
                ),
                Spec::req(
                    "resolve",
                    "Resolve concurrent role heads with a complete replacement body.",
                    vec![
                        A::pos("role", "The role id."),
                        A::multi("expect-head", "Every current head (repeatable).").required(),
                        A::val("file", "Path to the canonical JSON body.").required(),
                    ],
                    |m| {
                        let path = req_str(m, "file");
                        let body_json = std::fs::read_to_string(&path)
                            .map_err(|e| anyhow!("read {path}: {e}"))?;
                        Ok(Request::RoleResolve {
                            role: req_str(m, "role"),
                            expect_heads: multi(m, "expect-head"),
                            body_json,
                        })
                    },
                ),
                Spec::req("ls", "List every role definition.", vec![], |_| {
                    Ok(Request::RoleList)
                }),
            ],
            ..Spec::req(
                "role",
                "Author product roles (Catalog definitions). `role` lists.",
                vec![],
                |_| Ok(Request::RoleList),
            )
        },
        Spec {
            subs: vec![
                Spec::req(
                    "grant",
                    "Expand a role's pinned definition and install the exact scoped \
                     assignments (authority-first, all-or-nothing).",
                    vec![
                        A::pos("actor", "The member's actor id or petname."),
                        A::val("role", "The role to expand.").required(),
                        A::val("project", "The project scope, for a Project role.").short('p'),
                    ],
                    |m| {
                        Ok(Request::AccessGrant {
                            actor: req_str(m, "actor"),
                            role: req_str(m, "role"),
                            project: opt_str(m, "project"),
                        })
                    },
                ),
                Spec::req(
                    "revoke",
                    "Revoke one effective assignment by its grant id.",
                    vec![A::pos("grant_id", "The 64-hex grant id (from `access ls`).")],
                    |m| {
                        Ok(Request::AccessRevoke {
                            grant_id: req_str(m, "grant_id"),
                        })
                    },
                ),
                Spec::req(
                    "ls",
                    "Effective scoped assignments (Mechanics authority history).",
                    vec![A::val("actor", "Only this member's assignments.")],
                    |m| {
                        Ok(Request::AccessList {
                            actor: opt_str(m, "actor"),
                        })
                    },
                ),
            ],
            ..Spec::req(
                "access",
                "Effective scoped capability assignments. `access` lists.",
                vec![],
                |_| Ok(Request::AccessList { actor: None }),
            )
        },
        Spec {
            subs: vec![
                Spec::req(
                    "show",
                    "A project's workflow revision head(s).",
                    vec![A::pos("project", "The project (key or prj_ id).")],
                    |m| {
                        Ok(Request::WorkflowShow {
                            project: req_str(m, "project"),
                        })
                    },
                ),
                Spec::req(
                    "validate",
                    "Validate a canonical workflow JSON body without committing.",
                    vec![A::val("file", "Path to the canonical JSON body.").required()],
                    |m| {
                        let path = req_str(m, "file");
                        let body_json = std::fs::read_to_string(&path)
                            .map_err(|e| anyhow!("read {path}: {e}"))?;
                        Ok(Request::WorkflowValidate { body_json })
                    },
                ),
                Spec::req(
                    "set",
                    "Replace a project's workflow at exactly the current heads.",
                    vec![
                        A::pos("project", "The project (key or prj_ id)."),
                        A::multi("expect-head", "Every current head (repeatable).").required(),
                        A::val("file", "Path to the canonical JSON body.").required(),
                    ],
                    |m| {
                        let path = req_str(m, "file");
                        let body_json = std::fs::read_to_string(&path)
                            .map_err(|e| anyhow!("read {path}: {e}"))?;
                        Ok(Request::WorkflowSet {
                            project: req_str(m, "project"),
                            expect_heads: multi(m, "expect-head"),
                            body_json,
                        })
                    },
                ),
            ],
            ..Spec::req(
                "workflow",
                "Author deterministic workflow gates. Subcommand required.",
                vec![],
                |_| Err(anyhow!("workflow needs a subcommand: show | validate | set")),
            )
        },
        Spec::req(
            "reshare-recovery",
            "Reshare the group recovery key onto a new K-of-N arrangement \
             WITHOUT changing the key — replace or add holders. The current \
             holders authorize it (`elevate-approve`) and then threshold-sign \
             the installation. Note resharing is not a revocation: a removed \
             holder's old share still exists; to revoke, rotate the key with \
             `elevate-recovery` instead.",
            vec![
                A::pos_multi(
                    "participants",
                    "The COMPLETE new holder set (device keys), replacing the current one.",
                ),
                A::val(
                    "threshold",
                    "Signatures required to recover (K). Defaults to all holders (N-of-N).",
                )
                .default("0"),
            ],
            |m| {
                Ok(Request::SpaceReshare {
                    participants: multi(m, "participants"),
                    k: u64_arg(m, "threshold")? as u16,
                })
            },
        ),
        Spec::req(
            "activity",
            "Space-wide recent transitions.",
            vec![A::val("since", "Only events after this seq.").default("0")],
            |m| {
                Ok(Request::Activity {
                    since: u64_arg(m, "since")?,
                })
            },
        ),
        Spec::special(
            "serve",
            // `--json` is a global flag, so it needs no entry here — but it needs
            // *saying*, because the token is the reason anyone scripts this and a
            // long-running command that prints a machine line first is unusual
            // enough to be worth one clause.
            "Open your spaces in a browser (local, loopback-only). --json prints {url, token, port}, then serves.",
            vec![
                A::val("port", "Port to bind on 127.0.0.1 (default 7717)."),
                A::flag("open", "Open the URL in your default browser."),
            ],
            Special::Serve,
        ),
        Spec::req(
            "doctor",
            "Guided-join verifier: diagnose why you can't get to work yet.",
            vec![],
            |_| {
                Ok(Request::Diagnose {
                    expected_space: None,
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
                    Special::Spaces,
                ),
                Spec::special(
                    "forget",
                    "Deregister a space (registry only — never touches the store on disk).",
                    vec![A::pos("sel", "A store path, ws_ id, or unique id prefix.")],
                    Special::SpacesForget,
                ),
                Spec::special(
                    "prune",
                    "Drop registry entries whose store no longer exists on disk.",
                    vec![],
                    Special::SpacesPrune,
                ),
            ],
            ..Spec::special(
                "spaces",
                "Every space on this machine: name, id, origin, status, projects, path.",
                vec![],
                Special::Spaces,
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
        Spec::req(
            "rename",
            "Rename this space (a mutable display label — the seed id is unchanged). Admin only.",
            vec![A::pos("name", "New space name.")],
            |m| {
                Ok(Request::SpaceRename {
                    name: req_str(m, "name"),
                })
            },
        ),
        Spec::req(
            "describe",
            "Set this space's overview description (empty string clears it). Admin only.",
            vec![A::pos("description", "The space overview text (or \"\" to clear).")],
            |m| {
                Ok(Request::SpaceDescribe {
                    description: req_str(m, "description"),
                })
            },
        ),
        Spec {
            subs: vec![Spec::req(
                "revoke",
                "Revoke an invite so it can no longer admit anyone (admin only).",
                vec![A::pos(
                    "invite",
                    "The invite ticket, or its 32-hex nonce.",
                )],
                |m| {
                    Ok(Request::InviteRevoke {
                        invite: req_str(m, "invite"),
                    })
                },
            )],
            ..Spec::special(
                "invite",
                "Print a base32 ticket (+ QR) others use to join your space.",
                vec![
                    A::val(
                        "email",
                        "Open your mail client with a prefilled invite to this address.",
                    ),
                    A::val(
                        "role",
                        "The role the invite admits as: viewer | contributor | administrator.",
                    )
                    .long("role")
                    .value_name("ROLE"),
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
            )
        },
        Spec::special(
            "join",
            "Join a space from an invite link (creates the store here, or at --dir).",
            vec![
                A::pos("ticket", "The invite link / ticket from `lait invite`."),
                A::val("nick", "Set your display name as you join."),
                A::val("dir", "Create the joined space's store under this directory."),
            ],
            Special::Join,
        ),
        Spec::req(
            "connect",
            "Nudge the daemon to contact a peer now (a station id, or an invite link \
             whose host to reach). Joining a new space is `lait join`.",
            vec![A::pos(
                "target",
                "A station/device id, or an invite link for this space.",
            )],
            |m| {
                Ok(Request::Connect {
                    ticket: req_str(m, "target"),
                })
            },
        ),
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
            | "move" | "assign" | "label" | "comment" | "delete" | "restore" | "link"
            | "unlink" | "parent" | "graph" | "history" | "activity" | "serve" => ORDER_DAILY,
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
