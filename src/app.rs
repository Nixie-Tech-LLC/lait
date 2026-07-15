//! Binary entry point logic: parse the CLI and dispatch. Lives in the lib (not
//! `main.rs`) so integration tests and doctests can drive the same command
//! surface the binary exposes. `main.rs` is a thin shim over [`run`].
//!
//! The command surface follows UI.md §2: flat verbs act on **issues**, plural
//! nouns manage **registries** (`label <ref> +bug` vs `labels new`), and every
//! `<ref>` is resolved daemon-side (UI.md §3). Each verb maps to exactly one
//! Layer-B `Request` (S§7), which keeps one command = one commit = one activity
//! row (S§7.1).
//!
//! The surface is defined as **data** in [`crate::cmdspec`] — a `Vec<Spec>` turned
//! into a `clap::Command` at runtime — not a `#[derive(Parser)]` enum. This module
//! resolves the parsed args to a leaf spec and either builds its `Request` or runs
//! its bespoke `Special` handler (below). Completions/man still generate from the
//! same live tree (`cmdspec::build_cli`).

use anyhow::{anyhow, Result};
use clap::ArgMatches;
use clap_complete::{generate, Shell};

use crate::{
    cli::Out,
    cmdspec::{self, Dispatch, Special},
    config::{self, load_or_create_identity},
    control::Request,
    ids::{SystemUlidSource, UserId},
    install::{self, Client, Scope},
    mcp, node,
    store::Store,
    workspaces,
};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve a `-w <SEL>` workspace selector to a store path via the registry:
/// a path (containing a separator or naming an existing dir), a `ws_` id or
/// unique prefix, or a case-insensitive display-name match.
fn resolve_workspace_selector(sel: &str) -> Result<std::path::PathBuf> {
    use std::path::{Path, PathBuf};
    // Path form: explicit separators or an existing directory. Accept either
    // the `.lait` dir itself or its parent.
    if sel.contains('/') || sel.contains('\\') || Path::new(sel).is_dir() {
        let p = Path::new(sel);
        let store = if crate::store::initialized_at(p) {
            p.to_path_buf()
        } else if crate::store::initialized_at(&p.join(".lait")) {
            p.join(".lait")
        } else {
            return Err(anyhow!(
                "no initialized space store at '{sel}' (or under '{sel}/.lait')"
            ));
        };
        return Ok(store);
    }
    let entries = workspaces::list();
    let matches: Vec<_> = if sel.starts_with("ws_") {
        entries
            .iter()
            .filter(|e| e.workspace == sel || e.workspace.starts_with(sel))
            .collect()
    } else {
        entries
            .iter()
            .filter(|e| e.name.eq_ignore_ascii_case(sel))
            .collect()
    };
    match matches.len() {
        1 => {
            let e = matches[0];
            if workspaces::presence(e) == workspaces::StorePresence::Missing {
                return Err(anyhow!(
                    "space '{}' is registered at {} but the store is gone — run `lait spaces prune`",
                    sel,
                    e.path
                ));
            }
            Ok(PathBuf::from(&e.path))
        }
        0 => {
            let known: Vec<String> = entries
                .iter()
                .map(|e| {
                    if e.name.is_empty() {
                        e.workspace.clone()
                    } else {
                        e.name.clone()
                    }
                })
                .collect();
            Err(anyhow!(
                "no space matches '{sel}' — known: {} (see `lait spaces`)",
                if known.is_empty() {
                    "(none)".to_string()
                } else {
                    known.join(", ")
                }
            ))
        }
        _ => {
            let cands: Vec<String> = matches
                .iter()
                .map(|e| format!("{} ({})", e.workspace, e.path))
                .collect();
            eprintln!("'{sel}' is ambiguous:\n  {}", cands.join("\n  "));
            std::process::exit(2);
        }
    }
}

/// Parse arguments and run.
pub async fn run() -> Result<()> {
    let specs = cmdspec::specs();
    let cli = cmdspec::build_cli(&specs);
    // `try_get_matches` (not `get_matches`) so a usage/parse error exits `1` — the
    // documented code (UI.md §2.3) — instead of clap's default `2`, which collides
    // with `2 = ref not found / ambiguous`. `--help`/`--version` still exit `0`.
    let matches = match cli.try_get_matches() {
        Ok(m) => m,
        Err(e) => {
            e.print().ok();
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp
                | clap::error::ErrorKind::DisplayVersion
                | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => 0,
                _ => 1,
            };
            std::process::exit(code);
        }
    };
    let resolved = cmdspec::resolve(&specs, &matches);

    if !resolved.as_ref().is_some_and(|(l, _)| l.service) {
        reset_sigpipe();
    }

    // Effective color, computed once: honour --no-color, the $NO_COLOR
    // convention, --json (machine output is never styled), and whether stdout is
    // an interactive terminal (so `lait ls | cat` / redirects stay clean).
    use std::io::IsTerminal;
    let json = matches.get_flag("json");
    let out = Out {
        json,
        color: !matches.get_flag("no_color")
            && !json
            && std::env::var_os("NO_COLOR").is_none()
            && std::io::stdout().is_terminal(),
    };

    // Bare `lait` = the FOCUS view (inbox + your active issues, UI.md §2): the
    // most valuable keystroke answers "what's addressed to me / what am I on",
    // not help. Global flags (--home/-w/--json) still apply.
    let Some((leaf, m)) = resolved else {
        if let Some(h) = matches.get_one::<String>("home") {
            std::env::set_var("LAIT_HOME", h);
        }
        if let Some(sel) = matches.get_one::<String>("workspace") {
            let store = resolve_workspace_selector(sel)?;
            std::env::set_var("LAIT_STORE", &store);
        }
        let home = match config::resolve_existing_store(None) {
            Ok(h) => h,
            Err(e) if e.downcast_ref::<config::NoStoreHere>().is_some() => {
                crate::cli::err_no_store_here(out);
                std::process::exit(1);
            }
            Err(e) => return Err(e),
        };
        return crate::cli::run_focus(&home, out).await;
    };

    // Stateless install surfaces (completions / man): generated from the live
    // command tree and dispatched *before* home/identity/workspace resolution, so
    // a packager running them in a clean sandbox never mints a key or store.
    match &leaf.dispatch {
        Dispatch::Special(Special::Completions) => {
            let shell = *m.get_one::<Shell>("shell").expect("shell is required");
            let mut cmd = cmdspec::build_cli(&specs);
            let name = cmd.get_name().to_string();
            generate(shell, &mut cmd, name, &mut std::io::stdout());
            return Ok(());
        }
        Dispatch::Special(Special::Man) => {
            clap_mangen::Man::new(cmdspec::build_cli(&specs)).render(&mut std::io::stdout())?;
            return Ok(());
        }
        _ => {}
    }

    // Home resolution honours an explicit --home over the session registry.
    // Applied before ANY store-touching dispatch (including `config`, whose
    // store layer resolves through the same env).
    if let Some(h) = matches.get_one::<String>("home") {
        std::env::set_var("LAIT_HOME", h);
    }
    // `-w <SEL>`: resolve the selector to a store path and pin it, so every
    // command below binds that exact store from any directory. The pin rides
    // the same env the daemon spawn uses (`LAIT_STORE`), so the plumbing is
    // shared with cwd binding. `--home`/`$LAIT_HOME` still outrank it (and
    // clap already rejects combining the two flags).
    if let Some(sel) = matches.get_one::<String>("workspace") {
        let store = resolve_workspace_selector(sel)?;
        std::env::set_var("LAIT_STORE", &store);
    }

    // Registry-level commands that operate across identities (no store/daemon).
    match &leaf.dispatch {
        Dispatch::Special(Special::Profiles) => {
            let names = config::list_identities()?;
            if out.json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({ "identities": names }))
                        .unwrap_or_else(|_| "{}".into())
                );
            } else if names.is_empty() {
                println!("no identities yet — one is created on first use");
            } else {
                for n in names {
                    println!("{n}");
                }
            }
            return Ok(());
        }
        Dispatch::Special(Special::Resume) => {
            let name = m.get_one::<String>("name").cloned().unwrap_or_default();
            let home = config::bind_session(&name)?;
            // A named identity is a self-contained home: pin it as LAIT_HOME so the
            // daemon we spawn uses it for both identity and store, not the global
            // identity + repo-discovered store (DUR-5).
            std::env::set_var("LAIT_HOME", &home);
            load_or_create_identity(&home)?;
            // Under --json only the Status DTO is emitted — no human line ahead.
            if !out.json {
                println!("resumed identity '{name}'");
            }
            // A fresh identity home holds no workspace yet — say so instead of
            // spawning a daemon that can only fail to open the store.
            if !crate::store::initialized_at(&home) {
                crate::cli::emit_ok(
                    &format!(
                        "identity '{name}' has no space yet — `lait init` to found one, or `lait join <link>`"
                    ),
                    out,
                );
                return Ok(());
            }
            return crate::cli::run(&home, Request::Status, out).await;
        }
        // The workspace registry + config: pure local state, no store/daemon.
        Dispatch::Special(Special::Workspaces) => {
            crate::cli::print_workspaces(out).await;
            return Ok(());
        }
        Dispatch::Special(Special::WorkspacesForget) => {
            let sel = m.get_one::<String>("sel").cloned().unwrap_or_default();
            let removed = workspaces::forget(&sel)?;
            if removed.is_empty() {
                eprintln!("nothing in the registry matches '{sel}'");
                std::process::exit(2);
            }
            for e in &removed {
                crate::cli::emit_ok(
                    &format!("forgot {} at {} (store untouched)", e.workspace, e.path),
                    out,
                );
            }
            return Ok(());
        }
        Dispatch::Special(Special::WorkspacesPrune) => {
            let removed = workspaces::prune()?;
            crate::cli::emit_ok(
                &format!(
                    "pruned {} missing entr{}",
                    removed.len(),
                    if removed.len() == 1 { "y" } else { "ies" }
                ),
                out,
            );
            return Ok(());
        }
        Dispatch::Special(
            Special::ConfigGet | Special::ConfigSet | Special::ConfigUnset | Special::ConfigList,
        ) => {
            return run_config(&leaf.dispatch, m, out).await;
        }
        _ => {}
    }

    // `update` swaps the binary; it must not resolve/create a workspace store.
    if matches!(leaf.dispatch, Dispatch::Special(Special::Update)) {
        return run_update().await;
    }
    // The two creation verbs resolve (and may create) their own store.
    match &leaf.dispatch {
        Dispatch::Special(Special::Init) => return run_init(m, out).await,
        Dispatch::Special(Special::Join) => return run_join_cli(m, out).await,
        _ => {}
    }
    // Everything else binds an existing store or gets the guided error —
    // nothing is ever created implicitly (the decoy-store trap is gone by
    // construction, not by guard).
    let home = match config::resolve_existing_store(None) {
        Ok(h) => h,
        Err(e) if e.downcast_ref::<config::NoStoreHere>().is_some() => {
            crate::cli::err_no_store_here(out);
            std::process::exit(1);
        }
        Err(e) => return Err(e),
    };

    match &leaf.dispatch {
        // The uniform path: build one Request and round-trip the daemon.
        Dispatch::Request(f) => {
            let req = f(m)?;
            use std::io::IsTerminal;
            // `new --start` chains the create into the work loop: file it, then
            // claim it (two honest commits = two activity rows, S§7.1).
            if leaf.name == "new" && m.get_flag("start") {
                crate::cli::run_new_start(&home, req, out).await?;
            } else if leaf.name == "members" && !out.json && std::io::stdout().is_terminal() {
                // Bare `lait members` in an interactive terminal opens the modal
                // picker (browse/approve); `--json` and piped/redirected output
                // keep the plain roster dump so scripts and agents are unaffected.
                crate::members_ui::run(&home).await?
            } else {
                crate::cli::run(&home, req, out).await?;
            }
        }
        Dispatch::Special(s) => match s {
            Special::Start => {
                let reff = cmdspec::resolve_reff(m)?;
                crate::cli::run_start(&home, reff, m.get_flag("no_branch"), out).await?
            }
            Special::Done => {
                let reff = cmdspec::resolve_reff(m)?;
                crate::cli::run_workstate(&home, Request::IssueDone { reff }, out).await?
            }
            Special::Stop => {
                let reff = cmdspec::resolve_reff(m)?;
                crate::cli::run_workstate(&home, Request::IssueStop { reff }, out).await?
            }
            Special::Id => {
                let key = load_or_create_identity(&config::identity_dir()?)?;
                crate::cli::emit_text(&key.public().to_string(), out);
            }
            Special::Daemon => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "lait=info,warn".into()),
                    )
                    .init();
                node::run_daemon(home, m.get_flag("seed")).await?;
            }
            Special::Mcp => {
                mcp::run_mcp(&home).await?;
            }
            Special::InstallMcp => {
                let client = *m.get_one::<Client>("client").expect("has default");
                let scope = m.get_one::<Scope>("scope").copied();
                let name = m
                    .get_one::<String>("name")
                    .cloned()
                    .unwrap_or_else(|| "lait".into());
                let print = m.get_flag("print");
                let out_s = install::install_mcp(client, scope, &name, print)?;
                println!("{out_s}");
            }
            Special::Tui => crate::tui::run(&home).await?,
            Special::Invite => {
                let email = m.get_one::<String>("email").cloned();
                let require_approval = m.get_flag("require_approval");
                let reusable = m.get_flag("reusable");
                // The clap layer keeps everything a String; the ≥1 range that the
                // derive enforced with `value_parser!(u64).range(1..)` is validated
                // here instead (same exit code, clearer message).
                let ttl_hours = match m.get_one::<String>("ttl_hours") {
                    Some(s) => {
                        let h: u64 = s
                            .parse()
                            .map_err(|_| anyhow!("--ttl-hours must be a positive integer"))?;
                        if h < 1 {
                            return Err(anyhow!("--ttl-hours must be at least 1"));
                        }
                        Some(h)
                    }
                    None => None,
                };
                crate::cli::run_invite(&home, email, require_approval, reusable, ttl_hours, out)
                    .await?
            }
            Special::Watch => {
                let since = match m.get_one::<String>("since") {
                    Some(s) => Some(
                        s.parse::<u64>()
                            .map_err(|_| anyhow!("--since must be a non-negative integer"))?,
                    ),
                    None => None,
                };
                let exec = m.get_one::<String>("exec").cloned();
                let notify = m.get_flag("notify");
                crate::cli::watch(&home, since, exec, notify).await?
            }
            Special::Completions
            | Special::Man
            | Special::Profiles
            | Special::Resume
            | Special::Workspaces
            | Special::WorkspacesForget
            | Special::WorkspacesPrune
            | Special::ConfigGet
            | Special::ConfigSet
            | Special::ConfigUnset
            | Special::ConfigList
            | Special::Init
            | Special::Join
            | Special::Update => {
                unreachable!("handled before home resolution")
            }
        },
    }

    Ok(())
}

/// `lait init`: found a workspace rooted at `cwd/.lait` (or `$LAIT_HOME`).
/// Explicit creation is the ONLY way a workspace comes into existence besides
/// `join` — nothing is minted as a side effect of other commands.
async fn run_init(m: &ArgMatches, out: Out) -> Result<()> {
    // Refuse when discovery already binds an initialized store: one directory
    // (tree) holds one workspace.
    if let Some(existing) = config::existing_home() {
        if crate::store::initialized_at(&existing) {
            eprintln!(
                "already inside a space — its store is at {}",
                existing.display()
            );
            eprintln!("to found another space, run `lait init` in a different directory.");
            std::process::exit(1);
        }
    }
    let cwd = std::env::current_dir()?;
    let home = config::store_dir_for_init(&cwd)?;
    // Display name: --name, else the directory the store lives in.
    let name = match m.get_one::<String>("name") {
        Some(n) => n.clone(),
        None => dir_display_name(&home),
    };
    // `--nick` is sugar for `lait config set user.nick` at the store layer.
    if let Some(n) = m.get_one::<String>("nick") {
        let p = config::store_config_path(&home);
        let mut cfg = config::ConfigMap::load(&p);
        cfg.set("user.nick", n);
        cfg.save(&p)?;
    }
    let key = load_or_create_identity(&config::identity_dir()?)?;
    let me = UserId::from_key_string(key.public().to_string());
    let store = Store::open(&home)?;
    let (ws, project) = crate::tracker::found_workspace(&store, &me, &name, &SystemUlidSource)?;
    // Register the founder — this is what makes `lait workspaces` complete.
    if let Err(e) = workspaces::upsert(workspaces::WorkspaceEntry {
        workspace: ws.to_string(),
        name: name.clone(),
        path: home.display().to_string(),
        origin: workspaces::Origin::Founded,
        host_nick: String::new(),
        last_opened: now_secs(),
        projects: vec![workspaces::ProjectBrief {
            key: project.key.clone(),
            name: project.name.clone(),
        }],
    }) {
        eprintln!("(space registry update failed: {e:#})");
    }
    if out.json {
        crate::cli::emit_ok(
            &format!(
                "founded space '{name}' ({ws}) with project {} at {}",
                project.key,
                home.display()
            ),
            out,
        );
    } else {
        println!("founded space '{name}' ({ws})");
        println!("id:      {}", key.public());
        println!(
            "project: {} ({}) — `lait new \"...\"` files into it",
            project.name, project.key
        );
        println!("home:    {}", home.display());
        println!();
        println!("invite someone: `lait invite`");
    }
    Ok(())
}

/// The human name of the directory a store serves: the store dir's parent for a
/// `.lait`, else the dir itself (self-contained homes).
fn dir_display_name(home: &std::path::Path) -> String {
    let dir = if home.file_name().is_some_and(|f| f == ".lait") {
        home.parent().unwrap_or(home)
    } else {
        home
    };
    dir.file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("space")
        .to_string()
}

/// `lait join`: client-orchestrated store creation from a ticket, then the
/// daemon transport leg + guided-join verifier tail. The store is bootstrapped
/// *before* the daemon spawns, so the daemon only ever opens a well-formed
/// store bound to the ticket's workspace — the old adopt-or-split-brain
/// heuristic has nothing left to do.
async fn run_join_cli(m: &ArgMatches, out: Out) -> Result<()> {
    let ticket_str = m.get_one::<String>("ticket").cloned().unwrap_or_default();
    let ticket: crate::proto::WorkspaceTicket = ticket_str.parse()?;

    // Resolve the target store: --dir, else the discoverable store, else a
    // fresh `cwd/.lait` (with a guard against homedir/root litter).
    let target = if let Some(d) = m.get_one::<String>("dir") {
        config::store_dir_under(std::path::Path::new(d))?
    } else if let Some(existing) = config::existing_home() {
        existing
    } else {
        let cwd = std::env::current_dir()?;
        let is_home = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .is_some_and(|h| std::path::Path::new(&h) == cwd);
        if is_home || cwd.parent().is_none() {
            eprintln!("refusing to create a space store in {} — pass --dir <path> (or cd into the project directory first).", cwd.display());
            std::process::exit(1);
        }
        config::store_dir_for_init(&cwd)?
    };

    if crate::store::initialized_at(&target) {
        // Bound already: a re-join of the same workspace is fine; a different
        // one is a hard error (never adopt, never wipe).
        let store = Store::open(&target)?;
        match store.genesis()? {
            Some(g) if g.workspace_id.to_string() == ticket.workspace => {}
            Some(g) => {
                eprintln!(
                    "this directory holds space {} — the invite is for {}.",
                    g.workspace_id, ticket.workspace
                );
                eprintln!("run `lait join` from another directory, or pass --dir <path>.");
                std::process::exit(2);
            }
            None => {
                return Err(anyhow!(
                    "corrupt store at {} (catalog without genesis)",
                    target.display()
                ))
            }
        }
    } else {
        let store = Store::open(&target)?;
        crate::tracker::join_workspace_store(&store, &ticket.workspace, &ticket.host.to_string())?;
    }

    // Set the display name before the daemon is auto-spawned so a cold joiner
    // announces the right name on its join request. It stays a self-asserted
    // claim — the admin approves by key, never by this nick (UI.md §8).
    if let Some(n) = m.get_one::<String>("nick") {
        let p = config::store_config_path(&target);
        let mut cfg = config::ConfigMap::load(&p);
        cfg.set("user.nick", n);
        cfg.save(&p)?;
    }

    // Register the joiner store (pre-daemon, so `lait workspaces` sees it even
    // if the transport leg fails below).
    if let Err(e) = workspaces::upsert(workspaces::WorkspaceEntry {
        workspace: ticket.workspace.clone(),
        name: ticket.name.clone(),
        path: target.display().to_string(),
        origin: workspaces::Origin::Joined,
        host_nick: ticket.host_nick.clone(),
        last_opened: now_secs(),
        projects: vec![],
    }) {
        eprintln!("(space registry update failed: {e:#})");
    }

    // Daemon leg: spawn against the exact bootstrapped store, then the guided
    // verifier tail (gate readout instead of a bare "ok").
    std::env::set_var("LAIT_STORE", &target);
    crate::cli::run_join(&target, ticket_str, out).await
}

/// `lait config get|set|unset|ls`: layered local settings. Daemon-free by
/// construction — binds via `existing_home()` only (never creates a store,
/// never spawns); a daemon-read key change is pushed to a *running* daemon via
/// `ConfigReload`, else it applies on next start (and says so).
async fn run_config(dispatch: &Dispatch, m: &ArgMatches, out: Out) -> Result<()> {
    use crate::config::{key_spec, ConfigMap, KeyLayers, Settings, KEYS};
    let home = config::existing_home().filter(|h| crate::store::initialized_at(h));
    let which = match dispatch {
        Dispatch::Special(s) => *s,
        _ => unreachable!(),
    };
    match which {
        Special::ConfigList => {
            let settings = Settings::load(home.as_deref());
            for spec in KEYS {
                let (value, origin) = match (
                    settings.store.get(spec.name),
                    settings.global.get(spec.name),
                ) {
                    (Some(v), _) => (v.to_string(), "store"),
                    (None, Some(v)) => (v.to_string(), "global"),
                    (None, None) => match (spec.built_in)() {
                        Some(v) => (v, "default"),
                        None => ("(unset)".to_string(), "default"),
                    },
                };
                if out.json {
                    println!(
                        "{}",
                        serde_json::json!({ "key": spec.name, "value": value, "origin": origin })
                    );
                } else {
                    println!("{} = {}  ({origin}) — {}", spec.name, value, spec.help);
                }
            }
            Ok(())
        }
        Special::ConfigGet => {
            let key = m.get_one::<String>("key").cloned().unwrap_or_default();
            let spec = key_spec(&key)?;
            let settings = Settings::load(home.as_deref());
            match settings.get(&key) {
                Some(v) => crate::cli::emit_text(v, out),
                None => match (spec.built_in)() {
                    Some(v) => crate::cli::emit_text(&format!("{v} (default)"), out),
                    None => {
                        eprintln!("'{key}' is unset");
                        std::process::exit(2);
                    }
                },
            }
            Ok(())
        }
        Special::ConfigSet | Special::ConfigUnset => {
            let key = m.get_one::<String>("key").cloned().unwrap_or_default();
            let spec = key_spec(&key)?;
            let global = m.get_flag("global");
            if global && spec.layers == KeyLayers::StoreOnly {
                return Err(anyhow!("'{key}' is a per-store key — drop --global"));
            }
            let path = if global {
                config::global_config_path()?
            } else {
                let h = home.ok_or_else(|| {
                    anyhow!("not inside a space — cd into one, use -w, or pass --global")
                })?;
                config::store_config_path(&h)
            };
            let mut cfg = ConfigMap::load(&path);
            let message = if which == Special::ConfigSet {
                let value = m.get_one::<String>("value").cloned().unwrap_or_default();
                cfg.set(&key, &value);
                cfg.save(&path)?;
                format!("{key} = {value}")
            } else {
                if !cfg.unset(&key) {
                    eprintln!("'{key}' was not set in that layer");
                    std::process::exit(2);
                }
                cfg.save(&path)?;
                format!("unset {key}")
            };
            // Daemon-read keys: never a silent wait-for-restart. Bare
            // `control::request` (NOT `cli::client`) so we never auto-spawn a
            // daemon just to tell it about a config change.
            let mut applied = String::new();
            if spec.daemon_read {
                if let Some(h) = config::existing_home() {
                    applied = match crate::control::request(&h, &Request::ConfigReload).await {
                        Ok(_) => " (applied to the running daemon)".to_string(),
                        Err(_) => " (applies when the daemon next starts)".to_string(),
                    };
                }
            }
            crate::cli::emit_ok(&format!("{message}{applied}"), out);
            Ok(())
        }
        _ => unreachable!(),
    }
}

/// `lait update`: update the installed binary in place from the latest GitHub
/// release — natively, in-process, with no external updater binary. Best-effort
/// stops a running daemon first, so it isn't left on stale code and — on Windows —
/// isn't holding the executable open while it is swapped. Then it queries the
/// `Nixie-Tech-LLC/lait` releases, downloads this platform's asset, verifies it,
/// and self-replaces the running executable (all pure-Rust: `ureq` + rustls,
/// gzip/zip extraction, atomic self-replace).
async fn run_update() -> Result<()> {
    if let Some(home) = config::existing_home() {
        if crate::control::request(&home, &Request::Stop).await.is_ok() {
            println!("stopped the running daemon");
            // let the OS release the file handle before the binary is swapped
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        }
    }

    // The update is blocking (HTTP + archive extract + file swap); run it off the
    // async runtime so it doesn't stall the reactor.
    let status = tokio::task::spawn_blocking(move || {
        self_update::backends::github::Update::configure()
            .repo_owner("Nixie-Tech-LLC")
            .repo_name("lait")
            .bin_name("lait")
            .bin_path_in_archive(update_bin_path_in_archive())
            .current_version(env!("CARGO_PKG_VERSION"))
            .show_download_progress(true)
            .no_confirm(true)
            .build()
            .and_then(|updater| updater.update())
    })
    .await
    .map_err(|e| anyhow!("update task panicked: {e}"))?
    .map_err(|e| anyhow!("self-update failed: {e}"))?;

    if status.updated() {
        println!(
            "updated {} -> v{}. run any lait command to start the daemon on the new version.",
            env!("CARGO_PKG_VERSION"),
            status.version()
        );
    } else {
        println!("already up to date (v{})", status.version());
    }
    Ok(())
}

/// The in-archive path to the `lait` binary for `self_update`, matching
/// cargo-dist's **per-OS** release layout (verified against the published
/// assets): the unix `.tar.gz` archives nest the binary under a
/// `lait-<target-triple>/` directory, while the Windows `.zip` is flat with
/// `lait.exe` at the archive root. `{{ target }}`/`{{ bin }}` are expanded by
/// self_update; the Windows path needs the explicit `.exe` that `{{ bin }}`
/// does not add. Getting this wrong fails extraction with "specified file not
/// found in archive" — which is exactly what a single nested template did on
/// Windows (it only worked on unix, where it was tested).
fn update_bin_path_in_archive() -> &'static str {
    #[cfg(windows)]
    {
        "{{ bin }}.exe"
    }
    #[cfg(not(windows))]
    {
        "lait-{{ target }}/{{ bin }}"
    }
}

/// Restore the default `SIGPIPE` disposition on unix. Rust ignores `SIGPIPE` by
/// default, which turns a closed downstream pipe (`lait board | head`,
/// `| grep -q`, `| less` then quit) into a panic on the next stdout write
/// (`failed printing to stdout: Broken pipe`) instead of a clean exit. Resetting
/// to `SIG_DFL` makes the process terminate normally when the reader goes away —
/// the expected CLI behavior. No-op on Windows (no `SIGPIPE`).
///
/// **Only for short-lived, output-printing CLI commands.** The `daemon` and the
/// `mcp` stdio server must NOT reset it (they are the `service` specs): they are
/// long-running and do network / socket I/O (iroh, tokio), which relies on
/// `SIGPIPE` staying ignored so a write to a closed socket returns `EPIPE` instead
/// of *killing the process*. Resetting it there makes a dropped relay/socket write
/// terminate the daemon.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: setting a signal handler to the default disposition is async-signal
    // -safe and is the standard fix for Rust CLIs (see rust-lang/rust#46016).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}
#[cfg(not(unix))]
fn reset_sigpipe() {}

#[cfg(test)]
mod tests {
    use super::update_bin_path_in_archive;

    #[test]
    fn update_bin_path_matches_cargo_dist_per_os_layout() {
        // Regression guard: cargo-dist nests the binary under `lait-<target>/` in
        // the unix tarballs but ships a FLAT Windows zip with `lait.exe` at the
        // root. A single nested template silently broke every Windows self-update
        // ("specified file not found in archive"). Pin the per-OS contract.
        let path = update_bin_path_in_archive();
        if cfg!(windows) {
            // flat + explicit `.exe`; never nested under a target dir on Windows.
            assert_eq!(path, "{{ bin }}.exe");
            assert!(!path.contains('/'), "Windows zip is flat: {path}");
        } else {
            // nested under the per-target directory cargo-dist emits.
            assert_eq!(path, "lait-{{ target }}/{{ bin }}");
            assert!(
                path.contains("{{ target }}"),
                "unix archive is nested: {path}"
            );
        }
    }
}
