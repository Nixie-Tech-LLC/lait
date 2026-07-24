//! Binary entry point logic: parse the CLI and dispatch. Lives in the lib (not
//! `main.rs`) so integration tests and doctests can drive the same command
//! surface the binary exposes. `main.rs` is a thin shim over [`run`].
//!
//! Flat verbs act on **issues**, while plural
//! nouns manage **registries** (`label <ref> +bug` vs `labels new`), and every
//! `<ref>` is resolved daemon-side. Each verb maps to exactly one control
//! `Request`, preserving one command = one commit = one activity row.
//!
//! The surface is defined as **data** in [`crate::cmdspec`] — a `Vec<Spec>` turned
//! into a `clap::Command` at runtime — not a `#[derive(Parser)]` enum. This module
//! resolves the parsed args to a leaf spec and either builds its `Request` or runs
//! its bespoke `Special` handler (below). Completions/man still generate from the
//! same live tree (`cmdspec::build_cli`).

use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;
use clap_complete::{generate, Shell};

use crate::{
    cli::Out,
    cmdspec::{self, Dispatch, Special},
    config::{self, load_or_create_identity},
    control::{Request, Response},
    install::{self, Client, Scope},
    mcp, spaces,
};

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve a `-w <SEL>` space selector to a store path via the registry:
/// a path (containing a separator or naming an existing dir), a `ws_` id or
/// unique prefix, or a case-insensitive display-name match.
fn resolve_space_selector(sel: &str) -> Result<std::path::PathBuf> {
    use std::path::{Path, PathBuf};
    // Path form: explicit separators or an existing directory. Accept either
    // the `.lait` dir itself or its parent.
    if sel.contains('/') || sel.contains('\\') || Path::new(sel).is_dir() {
        let p = Path::new(sel);
        let has_space = |h: &Path| crate::orbital::space_store_present(h);
        let store = if has_space(p) {
            p.to_path_buf()
        } else if has_space(&p.join(".lait")) {
            p.join(".lait")
        } else {
            return Err(anyhow!(
                "no initialized space store at '{sel}' (or under '{sel}/.lait')"
            ));
        };
        return Ok(store);
    }
    let entries = spaces::list();
    let matches: Vec<_> = if sel.starts_with("ws_") {
        entries
            .iter()
            .filter(|e| e.space == sel || e.space.starts_with(sel))
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
            if spaces::presence(e) == spaces::StorePresence::Missing {
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
                        e.space.clone()
                    } else {
                        e.name.clone()
                    }
                })
                .collect();
            // A selector that resolved to nothing: exit `2`, the same answer the
            // daemon already gives for a missing ref / user / label.
            Err(crate::cli::CliError::not_found(format!(
                "no space matches '{sel}' — known: {} (see `lait spaces`)",
                if known.is_empty() {
                    "(none)".to_string()
                } else {
                    known.join(", ")
                }
            ))
            .into())
        }
        _ => {
            let cands: Vec<String> = matches
                .iter()
                .map(|e| format!("{} ({})", e.space, e.path))
                .collect();
            eprintln!("'{sel}' is ambiguous:\n  {}", cands.join("\n  "));
            std::process::exit(2);
        }
    }
}

/// A minimal extension→MIME map for attachments — enough for the common
/// cases; anything else is an honest octet-stream.
fn mime_for(name: &str) -> String {
    let ext = name
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "log" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "csv" => "text/csv",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Parse arguments, run, and report any failure the way the CLI contract says.
///
/// Returns the process exit code rather than a `Result`: handing an error back to
/// `main` means handing it to anyhow's `Termination` impl, which Debug-prints the
/// cause chain and always exits `1`. Every client-side failure funnels through
/// [`crate::cli::report_error`] instead — see there for what that buys.
pub async fn run() -> std::process::ExitCode {
    // Before anything can spawn — every command, service or not.
    disinherit_stdio();
    let specs = cmdspec::specs();
    let cli = cmdspec::build_cli(&specs);
    // `try_get_matches` (not `get_matches`) so a usage/parse error exits `1` — the
    // documented code — instead of clap's default `2`, which collides
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

    if !cmdspec::resolve(&specs, &matches).is_some_and(|(l, _)| l.service) {
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
        yes: matches.get_flag("yes"),
    };

    // `out` has to exist before a failure can be reported the right way (the
    // `--json` DTO vs a prose line), which is why the sink sits here and not in
    // `main`.
    let mut result = dispatch(&specs, &matches, out).await;
    // A daemon this build can't talk to blocks every verb, and clearing it is
    // usually one keystroke — so offer, then retry once. Driven off the error
    // rather than a probe before dispatch: the overwhelmingly common case is a
    // daemon that works, and it must not pay a round trip for this. A retry is
    // safe precisely because the failure means we never reached the daemon, so
    // nothing was written.
    if let Err(e) = &result {
        if crate::cli::is_replaceable_foreign(e) {
            match crate::cli::heal_from_error(e, out).await {
                Ok(()) => result = dispatch(&specs, &matches, out).await,
                Err(e) => return crate::cli::report_error(&e, out),
            }
        }
    }
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => crate::cli::report_error(&e, out),
    }
}

/// Resolve the parsed args to a leaf spec and run it.
async fn dispatch(specs: &[cmdspec::Spec], matches: &ArgMatches, out: Out) -> Result<()> {
    let resolved = cmdspec::resolve(specs, matches);

    // Bare `lait` = the FOCUS view (inbox + your active issues): the
    // most valuable keystroke answers "what's addressed to me / what am I on",
    // not help. Global flags (--home/-w/--json) still apply.
    let Some((leaf, m)) = resolved else {
        if let Some(h) = matches.get_one::<String>("home") {
            std::env::set_var("LAIT_HOME", h);
        }
        if let Some(sel) = matches.get_one::<String>("space") {
            let store = resolve_space_selector(sel)?;
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
    // command tree and dispatched *before* home/identity/space resolution, so
    // a packager running them in a clean sandbox never mints a key or store.
    match &leaf.dispatch {
        Dispatch::Special(Special::Completions) => {
            let shell = *m.get_one::<Shell>("shell").expect("shell is required");
            let mut cmd = cmdspec::build_cli(specs);
            let name = cmd.get_name().to_string();
            generate(shell, &mut cmd, name, &mut std::io::stdout());
            return Ok(());
        }
        Dispatch::Special(Special::Man) => {
            clap_mangen::Man::new(cmdspec::build_cli(specs)).render(&mut std::io::stdout())?;
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
    if let Some(sel) = matches.get_one::<String>("space") {
        let store = resolve_space_selector(sel)?;
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
            // A fresh identity home holds no space yet — say so instead of
            // spawning a daemon that can only fail to open the store.
            if !crate::orbital::space_store_present(&home) {
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
        // `serve` is global to the machine, not bound to one store: it reads the
        // space registry and attaches each space's daemon lazily, so it must
        // not resolve (or demand) a store in the cwd — running it from anywhere
        // is the point.
        Dispatch::Special(Special::Serve) => {
            let port = m
                .get_one::<String>("port")
                .map(|p| p.parse::<u16>())
                .transpose()
                .context("--port must be a number 0-65535")?
                .unwrap_or(crate::serve::DEFAULT_PORT);
            return crate::serve::run(port, m.get_flag("open"), out.json).await;
        }
        // The space registry + config: pure local state, no store/daemon.
        Dispatch::Special(Special::Spaces) => {
            crate::cli::print_spaces(out).await;
            return Ok(());
        }
        Dispatch::Special(Special::SpacesForget) => {
            let sel = m.get_one::<String>("sel").cloned().unwrap_or_default();
            let removed = spaces::forget(&sel)?;
            if removed.is_empty() {
                eprintln!("nothing in the registry matches '{sel}'");
                std::process::exit(2);
            }
            for e in &removed {
                crate::cli::emit_ok(
                    &format!("forgot {} at {} (store untouched)", e.space, e.path),
                    out,
                );
            }
            return Ok(());
        }
        Dispatch::Special(Special::SpacesPrune) => {
            let removed = spaces::prune()?;
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

    // `update` swaps the binary; it must not resolve/create a space store.
    if matches!(leaf.dispatch, Dispatch::Special(Special::Update)) {
        return run_update().await;
    }
    // The two creation verbs resolve (and may create) their own store.
    match &leaf.dispatch {
        Dispatch::Special(Special::Init) => return run_init(m, out).await,
        Dispatch::Special(Special::Join) => return run_join_cli(m, out).await,
        Dispatch::Special(Special::DeviceAccept) => return run_device_accept(m, out),
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
            // Ask before destroying (delete / member remove / key rotate). Gated
            // on the Request, so the list lives in one place; everything else
            // passes straight through.
            if !crate::cli::confirm_destructive(&home, &req, out).await {
                std::process::exit(1);
            }
            // `new --start` chains the create into the work loop: file it, then
            // claim it (two honest commits produce two activity rows).
            //
            // Ask for `start` in a way that can answer "there is no such arg".
            // `leaf.name` is only the *last* path segment, so `labels new` answers
            // to "new" as much as the top-level verb does — and `get_flag` on a
            // leaf that never declared the arg is a panic, not a `false`. That is
            // exactly what `lait labels new <name>` did.
            let wants_start = m
                .try_get_one::<bool>("start")
                .ok()
                .flatten()
                .copied()
                .unwrap_or(false);
            if leaf.name == "new" && wants_start {
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
                let seed = load_or_create_identity(&config::identity_dir()?)?;
                crate::cli::emit_text(crate::crypto::device_from_seed(&seed).as_str(), out);
                // The actor line (GOV-11): a pending joiner must be able to
                // name their own actor to the approving admin, and the daemon
                // resolves it from the actor plane even before admission.
                // Best-effort: no running daemon, no line — the device id
                // above stays the stable first line either way.
                if !out.json {
                    if let Ok(Response::Ok { message: Some(m) }) =
                        crate::control::request(&home, &Request::Id).await
                    {
                        if let Some(actor_line) = m.lines().nth(1) {
                            println!("{actor_line}");
                        }
                    }
                }
            }
            Special::Attach => {
                let reff = m.get_one::<String>("reff").cloned().unwrap_or_default();
                let path = m.get_one::<String>("file").cloned().unwrap_or_default();
                let bytes =
                    std::fs::read(&path).map_err(|e| anyhow!("could not read {path}: {e}"))?;
                if bytes.is_empty() {
                    return Err(anyhow!("{path} is empty — nothing to attach"));
                }
                if bytes.len() > crate::world::contract::MAX_ATTACHMENT_BYTES {
                    return Err(anyhow!(
                        "{path} is {} KiB — attachments are capped at {} KiB (they ride \
                         the issue's replicated document). Link large files instead.",
                        bytes.len() / 1024,
                        crate::world::contract::MAX_ATTACHMENT_BYTES / 1024
                    ));
                }
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                let mime = mime_for(&name);
                let req = Request::Attach {
                    reff,
                    name,
                    mime: Some(mime),
                    data_b64: data_encoding::BASE64.encode(&bytes),
                    comment: m.get_one::<String>("comment").cloned(),
                };
                crate::cli::run(&home, req, out).await?
            }
            Special::AttachmentGet => {
                let reff = m.get_one::<String>("reff").cloned().unwrap_or_default();
                let id = m.get_one::<String>("id").cloned().unwrap_or_default();
                if reff.is_empty() || id.is_empty() {
                    return Err(anyhow!(
                        "usage: lait attachment get <reff> <att_id> [--out <path>]"
                    ));
                }
                let resp = crate::cli::client(&home, Request::AttachmentGet { reff, id }).await?;
                match resp {
                    Response::Attachment {
                        name,
                        mime: _,
                        data_b64,
                    } => {
                        let bytes = data_encoding::BASE64
                            .decode(data_b64.as_bytes())
                            .map_err(|_| anyhow!("stored attachment did not decode"))?;
                        let dest = m
                            .get_one::<String>("out")
                            .cloned()
                            .unwrap_or_else(|| name.clone());
                        std::fs::write(&dest, &bytes)
                            .map_err(|e| anyhow!("could not write {dest}: {e}"))?;
                        if out.json {
                            crate::cli::emit_ok(
                                &format!("saved {} bytes to {dest}", bytes.len()),
                                out,
                            );
                        } else {
                            println!("saved {} bytes to {dest}", bytes.len());
                        }
                    }
                    other => {
                        let code = crate::cli::print_response(&other, out);
                        if code != 0 {
                            std::process::exit(code);
                        }
                    }
                }
            }
            Special::Daemon => {
                tracing_subscriber::fmt()
                    .with_env_filter(
                        tracing_subscriber::EnvFilter::try_from_default_env()
                            .unwrap_or_else(|_| "lait=info,warn".into()),
                    )
                    .init();
                // The orbital daemon is the only daemon. `open` runs the preflight
                // legacy detector: a pre-orbital (v0.x) store is refused with
                // recreation guidance before anything binds, and an uninitialized
                // home is told to run `lait init` — never a silent fallback to a
                // legacy node.
                crate::orbital::run_orbital_daemon(home, &crate::transport::DefaultFactory).await?;
                std::process::exit(0);
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
            Special::Invite => {
                let email = m.get_one::<String>("email").cloned();
                let role = m.get_one::<String>("role").cloned();
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
                crate::cli::run_invite(&home, email, role, reusable, ttl_hours, out).await?
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
            | Special::Spaces
            | Special::SpacesForget
            | Special::SpacesPrune
            | Special::ConfigGet
            | Special::ConfigSet
            | Special::ConfigUnset
            | Special::ConfigList
            | Special::Init
            | Special::Join
            | Special::DeviceAccept
            | Special::Serve
            | Special::Update => {
                unreachable!("handled before home resolution")
            }
        },
    }

    Ok(())
}

/// `lait init`: found a space rooted at `cwd/.lait` (or `$LAIT_HOME`).
/// Explicit creation is the ONLY way a space comes into existence besides
/// `join` — nothing is minted as a side effect of other commands.
async fn run_init(m: &ArgMatches, out: Out) -> Result<()> {
    // Refuse when discovery already binds an initialized store: one directory
    // (tree) holds one space — legacy or orbital.
    if let Some(existing) = config::existing_home() {
        if crate::orbital::space_store_present(&existing)
            || crate::orbital::unsupported_store_at(&existing).is_some()
        {
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
    let seed = load_or_create_identity(&config::identity_dir()?)?;
    let me = crate::crypto::device_from_seed(&seed);
    // Orbital formation: mechanics material + Runtime Orbit store + a seeded
    // default project, so `lait new` works on the next command.
    let (ws, project) = crate::orbital::found_space_cli(&home, &seed, &name)?;
    // Register the founder — this is what makes `lait spaces` complete.
    if let Err(e) = spaces::upsert(spaces::SpaceEntry {
        space: ws.to_string(),
        name: name.clone(),
        path: home.display().to_string(),
        origin: spaces::Origin::Founded,
        host_nick: String::new(),
        last_opened: now_secs(),
        projects: vec![project.clone()],
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
        println!("id:      {}", me);
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

/// New-machine side of device enrollment (no daemon, no store): consume a
/// `device invite` token (`<actor_id> <space_id>`), sign this identity's
/// consent to join that actor, and print the blob to hand back to `device add`.
fn run_device_accept(m: &ArgMatches, out: Out) -> Result<()> {
    let token = m.get_one::<String>("token").cloned().unwrap_or_default();
    let mut parts = token.split_whitespace();
    let actor = parts
        .next()
        .and_then(crate::ids::ActorId::parse)
        .ok_or_else(|| anyhow!("invalid device token (expected `<actor_id> <space_id>`)"))?;
    let space = parts
        .next()
        .filter(|w| w.starts_with("ws_"))
        .ok_or_else(|| anyhow!("invalid device token (missing space id)"))?
        .to_string();
    let seed = load_or_create_identity(&config::identity_dir()?)?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("getrandom: {e}"))?;
    let binding = crate::actor::consent_sign(
        &seed,
        &space,
        nonce,
        &crate::actor::ConsentCtx::Member { actor: &actor },
    );
    let blob = data_encoding::HEXLOWER.encode(&postcard::to_stdvec(&binding)?);
    if out.json {
        crate::cli::emit_ok(&blob, out);
    } else {
        println!("{blob}");
        eprintln!("hand this to `lait device add <blob>` on a device already in the actor.");
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

/// `lait join <coordinates>`: the orbital join path. Bootstrap the joiner's
/// orbital store from the invite link (`orbital::enter_space`), spawn the
/// orbital daemon, then drive Contact to the invite's approach Station until
/// admission lands. The joiner's Contact registers it as a pending Neighbor on
/// the inviter, whose driver reciprocally dials back to redeem the admission —
/// so repeated joiner-side Connects converge to membership without a manual
/// admin step (for an auto-approving invite).
async fn run_join_orbital(m: &ArgMatches, link: &str, out: Out) -> Result<()> {
    let coords = runtime::SignedCoordinates::parse_link(link.trim())
        .map_err(|e| anyhow!("invalid invite link: {e}"))?;
    let verified = coords.verify().map_err(|e| anyhow!("invite: {e}"))?;
    let space = verified.space.as_str().to_string();
    let approach = verified.approach_station.as_str().to_string();

    // Resolve the target store home (same policy as the legacy path).
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

    // A pre-orbital store at the resolved home is a wrong-directory signal for
    // a JOINER, not a migration problem (LOCAL-10): a bare `lait join` lands
    // wherever home resolution points (an unset LAIT_HOME turns it into the
    // cwd), so name the aim and the ways to re-aim instead of dead-ending on
    // clean-break guidance meant for the store's owner.
    if let Some(err) = crate::orbital::unsupported_store_at(&target) {
        eprintln!("{err}");
        eprintln!(
            "this join was aimed at {} — if that is not where you keep this space, \
             set LAIT_HOME, pass --dir <path>, or cd elsewhere and retry. The old \
             store there was not touched.",
            target.display()
        );
        std::process::exit(2);
    }

    // Refuse to re-bind a directory that already holds a different space.
    if crate::orbital::space_store_present(&target) {
        match crate::orbital::discover_space_id(&target) {
            Some(existing) if existing.as_str() == space => {}
            Some(existing) => {
                eprintln!("this directory holds space {existing} — the invite is for {space}.");
                eprintln!("run `lait join` from another directory, or pass --dir <path>.");
                std::process::exit(2);
            }
            None => {}
        }
    }

    let seed = load_or_create_identity(&config::identity_dir()?)?;
    // `--nick` is a self-asserted claim before the daemon spawns.
    if let Some(n) = m.get_one::<String>("nick") {
        let p = config::store_config_path(&target);
        let mut cfg = config::ConfigMap::load(&p);
        cfg.set("user.nick", n);
        cfg.save(&p)?;
    }

    // Bootstrap the orbital store from the invite (idempotent for a re-join).
    if !crate::orbital::space_store_present(&target) {
        crate::orbital::enter_space(&target, &seed, link)?;
    }

    // Register the joiner store pre-daemon so `lait spaces` sees it.
    if let Err(e) = spaces::upsert(spaces::SpaceEntry {
        space: space.clone(),
        name: verified.approach_nick_hint.clone(),
        path: target.display().to_string(),
        origin: spaces::Origin::Joined,
        host_nick: verified.approach_nick_hint.clone(),
        last_opened: now_secs(),
        projects: vec![],
    }) {
        eprintln!("(space registry update failed: {e:#})");
    }

    // Spawn the daemon (the orbital Station is the only daemon).
    crate::cli::ensure_daemon(&target).await?;

    // Drive Contact to the approach Station until admitted (or a deadline). The
    // inviter's driver reciprocates to redeem the admission.
    if !out.json {
        println!("joining space {space} — reaching the inviter…");
    }
    let started = tokio::time::Instant::now();
    let deadline = started + std::time::Duration::from_secs(30);
    let mut admitted = false;
    // Progress beats (GOV-9): a first-time joiner must be able to tell "slow
    // handshake" from "hung forever" — say when the inviter answered, and keep
    // a heartbeat with the last failure while they haven't.
    let mut contacted = false;
    let mut last_err: Option<String> = None;
    let mut last_beat = started;
    while tokio::time::Instant::now() < deadline {
        match crate::control::request(
            &target,
            &Request::Connect {
                ticket: approach.clone(),
            },
        )
        .await
        {
            Ok(Response::Ok { .. }) => {
                if !contacted && !out.json {
                    println!("· contacted the inviter — waiting for the admission to seal…");
                }
                contacted = true;
            }
            Ok(Response::Error { message, .. }) => last_err = Some(message),
            _ => {}
        }
        if let Ok(Response::Status(info)) = crate::control::request(&target, &Request::Status).await
        {
            if info.membership == "member" {
                admitted = true;
                break;
            }
        }
        if !out.json && last_beat.elapsed() >= std::time::Duration::from_secs(8) {
            last_beat = tokio::time::Instant::now();
            let secs = started.elapsed().as_secs();
            if contacted {
                println!("· still waiting for the admission to seal… ({secs}s)");
            } else if let Some(e) = &last_err {
                println!("· still reaching the inviter ({secs}s) — last attempt: {e}");
            } else {
                println!("· still reaching the inviter… ({secs}s)");
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }

    if admitted {
        if out.json {
            crate::cli::emit_ok(&format!("joined space {space}"), out);
        } else {
            println!("joined — you now hold standing in {space}.");
            println!("home: {}", target.display());
        }
    } else if out.json {
        crate::cli::emit_ok(
            &format!("entered space {space}; admission still pending"),
            out,
        );
    } else {
        println!("entered space {space}, but admission has not completed yet.");
        println!("the inviter may need to be online (or to approve you): retry with");
        println!("  lait connect {approach}");
        println!("home: {}", target.display());
    }
    Ok(())
}

/// `lait join`: client-orchestrated store creation from a ticket, then the
/// daemon transport leg + guided-join verifier tail. The store is bootstrapped
/// *before* the daemon spawns, so the daemon only ever opens a well-formed
/// store bound to the ticket's space — the old adopt-or-split-brain
/// heuristic has nothing left to do.
async fn run_join_cli(m: &ArgMatches, out: Out) -> Result<()> {
    let ticket_str = m.get_one::<String>("ticket").cloned().unwrap_or_default();

    // Orbital is the only join path: a Coordinates v1 link joins. Anything else
    // — a pre-carve join ticket, an older/newer link, malformed bytes — is
    // refused with the typed [`CoordinatesError`] (a pre-carve ticket surfaces
    // as `UnsupportedVersion`), never a fallback to a legacy code path.
    match runtime::SignedCoordinates::parse_link(ticket_str.trim()) {
        Ok(_) => run_join_orbital(m, &ticket_str, out).await,
        Err(runtime::coordinates::CoordinatesError::UnsupportedVersion(v)) => Err(anyhow!(
            "this invite is not a lait Coordinates link (version {v} — it looks like a \
             legacy space ticket from an older lait). Ask the inviter for a fresh \
             `lait invite` link."
        )),
        Err(runtime::coordinates::CoordinatesError::BadLink) => Err(anyhow!(
            "this invite does not decode as a lait Coordinates link: it contains \
             characters outside the ticket alphabet. Both the lait://join/<ticket> \
             form and the bare ticket work — the usual cause is a partial copy, so \
             re-copy the whole link (line breaks are fine)."
        )),
        Err(e) => Err(anyhow!(
            "this invite could not be read as a lait Coordinates link ({e:?}). \
             Re-copy the whole link; if it still fails, ask the inviter for a fresh \
             `lait invite` link."
        )),
    }
}

/// `lait config get|set|unset|ls`: layered local settings. Daemon-free by
/// construction — binds via `existing_home()` only (never creates a store,
/// never spawns); a daemon-read key change is pushed to a *running* daemon via
/// `ConfigReload`, else it applies on next start (and says so).
async fn run_config(dispatch: &Dispatch, m: &ArgMatches, out: Out) -> Result<()> {
    use crate::config::{key_spec, ConfigMap, KeyLayers, Settings, KEYS};
    let home = config::existing_home().filter(|h| crate::orbital::space_store_present(h));
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
        // Only claim to have stopped something if something was there, and only
        // after watching it go. The old check was `request(Stop).is_ok()`, which
        // is true for any *decodable* reply — including an error, and including
        // the "shutting down" a pre-`signal_shutdown` daemon sends and then
        // ignores. That printed a stop that never happened and left a daemon on
        // stale code: the exact skew `heal_foreign_daemon` now has to clean up.
        if !matches!(
            crate::control::probe(&home).await,
            crate::control::Probe::Absent
        ) {
            match crate::cli::stop_daemon_verified(&home).await {
                Ok(()) => {
                    println!("stopped the running daemon");
                    // let the OS release the file handle before the binary is swapped
                    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                }
                // Worth saying out loud rather than swallowing: a daemon left
                // running is on stale code the moment the swap lands, and on
                // Windows it may still hold the executable open.
                Err(e) => eprintln!(
                    "warning: could not stop the running daemon: {e:#}\n\
                     continuing; run `lait shutdown` after the update."
                ),
            }
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
            // Clean-semver version (build.rs): a dev build reports `X.Y.Z-dev.<sha>`,
            // which sorts below stable `X.Y.Z`, so `lait update` heals a dev node
            // onto the stable release instead of seeing "already up to date".
            .current_version(env!("LAIT_VERSION_SEMVER"))
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
            env!("LAIT_VERSION_LONG"),
            status.version()
        );
    } else {
        println!("already up to date (v{})", status.version());
    }
    Ok(())
}

/// The in-archive path to the `lait` binary for `self_update`, matching
/// cargo-dist's **per-OS** release layout: the unix `.tar.gz` archives nest
/// everything under a `lait-<target-triple>/` directory, while the Windows
/// `.zip` is flat with `lait.exe` at the archive root.
///
/// `{{ target }}` / `{{ bin }}` are expanded by self_update. The trap is
/// `{{ bin }}`: it expands to `bin_name` *after* the crate has appended
/// `EXE_SUFFIX` (see `Update::bin_name`), so it is already `lait.exe` on
/// Windows. Spelling the suffix again yields `lait.exe.exe` and extraction
/// fails with "specified file not found in archive" — which is exactly what
/// shipped in v0.4.8/v0.5.0. Getting it wrong is invisible on the host that
/// builds the release and fatal on the host that runs it.
///
/// Takes `target` rather than reading `#[cfg(windows)]` so that **every**
/// platform's answer is computable from any host — a `cfg` split can only ever
/// be tested on the platform it selects, which is why the Windows arm went
/// unexercised through two releases. The real caller passes
/// [`self_update::get_target`], the same string self_update substitutes for
/// `{{ target }}`, so there is no skew between what we plan and what it does.
fn update_bin_path_in_archive_for(target: &str) -> &'static str {
    if target.contains("-windows-") {
        // flat zip; `{{ bin }}` already carries `.exe`.
        "{{ bin }}"
    } else {
        "lait-{{ target }}/{{ bin }}"
    }
}

/// The in-archive binary path for the target this binary was built for.
fn update_bin_path_in_archive() -> &'static str {
    update_bin_path_in_archive_for(self_update::get_target())
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
/// long-running and do network / socket I/O, which relies on
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

/// Stop our own stdio from leaking into processes we never handed it to.
///
/// On Windows `CreateProcess` is called with `bInheritHandles=TRUE`, and that is
/// all-or-nothing: a child inherits *every* inheritable handle in this process,
/// not just the three named in `STARTUPINFO`. When our stdout/stderr are pipes
/// (any captured run — `Command::output()`, `$(lait ...)`, a test harness) those
/// pipe handles are inheritable, so a child that outlives us keeps our caller's
/// stdout open and it never sees the EOF it is reading for. Unix is immune: those
/// fds are `CLOSE_ON_EXEC`.
///
/// The daemon — the child that outlives us by design, and the one this actually
/// bit — is handled precisely in [`crate::daemon_spawn`], which names the handles
/// it may inherit. This is the blanket for everything else we spawn without that
/// ceremony: the Windows notification balloon outlives the `watch` that raised it
/// by ~6s, and a `hook` runs whatever the user wrote. Neither should be able to
/// hold `lait watch | tee`'s pipe open.
///
/// Clearing `HANDLE_FLAG_INHERIT` on our end costs nothing we want: for
/// `Stdio::inherit()` std duplicates the handle with `bInheritHandle=TRUE` into
/// the child's `STARTUPINFO`, so a child we *do* hand stdio to still lands its
/// output on ours.
///
/// Unlike [`reset_sigpipe`], this runs for the services too — `lait mcp` speaks
/// its protocol over stdio pipes, and its client is reading for that same EOF.
#[cfg(windows)]
fn disinherit_stdio() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};

    let handles = [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ];
    for h in handles {
        if h.is_null() {
            continue;
        }
        // SAFETY: `h` is a live std handle we own, borrowed for this call only.
        // Best-effort: a std stream can be closed or invalid (a detached service),
        // and failing to clear a handle we never had is not an error.
        unsafe {
            SetHandleInformation(h as _, HANDLE_FLAG_INHERIT, 0);
        }
    }
}
#[cfg(not(windows))]
fn disinherit_stdio() {}

#[cfg(test)]
mod tests {
    use super::update_bin_path_in_archive_for;

    #[test]
    fn updater_version_is_clean_semver() {
        // The self-updater compares `current_version` as semver, so the string it
        // gets (LAIT_VERSION_SEMVER) must be valid semver — never the ` (<date>)`
        // form of LAIT_VERSION_LONG. In a non-dev build (no LAIT_BUILD_SHA, as in
        // CI/test) it equals the crate version exactly; a dev build appends a
        // `-dev.<sha>` prerelease that sorts below stable.
        let v = env!("LAIT_VERSION_SEMVER");
        assert!(
            !v.contains(' ') && !v.contains('('),
            "updater version must be valid semver, got {v:?}"
        );
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    /// Expand a `bin_path_in_archive` template the way self_update does, for an
    /// arbitrary target — mirroring `Update::bin_name` (which appends
    /// `EXE_SUFFIX` to the configured name) and `update.rs`'s `{{ var }}`
    /// substitution. Modelling it here is what lets a single host check the
    /// answer for platforms it isn't running on.
    fn expand(target: &str) -> String {
        let exe_suffix = if target.contains("-windows-") {
            ".exe"
        } else {
            ""
        };
        let bin_name = format!("{}{}", "lait".trim_end_matches(exe_suffix), exe_suffix);
        update_bin_path_in_archive_for(target)
            .replace("{{ bin }}", &bin_name)
            .replace("{{ target }}", target)
    }

    #[test]
    fn update_bin_path_matches_the_published_archive_layout_for_every_target() {
        // Ground truth, read off the real v0.5.0 release artifacts and their
        // dist-manifest.json: the unix `.tar.gz` archives nest everything under
        // `lait-<target>/`, and the Windows `.zip` is FLAT with `lait.exe` at the
        // root. Assert the EXPANDED path — the old test pinned the template
        // string verbatim, so it merely restated the code and cheerfully asserted
        // `{{ bin }}.exe`, letting the `lait.exe.exe` bug ship twice.
        //
        // Every shipped target is checked from any host: `update_bin_path_in_archive_for`
        // takes the target instead of branching on `#[cfg(windows)]`, so the
        // Windows arm is no longer invisible to CI's Linux runners.
        assert_eq!(expand("x86_64-pc-windows-msvc"), "lait.exe");
        for target in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
        ] {
            assert_eq!(expand(target), format!("lait-{target}/lait"));
        }
    }

    #[test]
    fn update_bin_path_never_doubles_the_exe_suffix() {
        // The exact v0.4.8/v0.5.0 defect, named: `{{ bin }}` already carries
        // `EXE_SUFFIX`, so any template that also spells `.exe` produces
        // `lait.exe.exe` and every Windows self-update dies on extraction.
        let win = expand("x86_64-pc-windows-msvc");
        assert!(!win.contains(".exe.exe"), "doubled EXE_SUFFIX: {win}");
        assert_eq!(win.matches(".exe").count(), 1, "expected one `.exe`: {win}");
    }

    /// Every target cargo-dist ships, and the archive extension it ships it as.
    const RELEASE_TARGETS: &[(&str, &str)] = &[
        ("x86_64-pc-windows-msvc", "zip"),
        ("aarch64-apple-darwin", "tar.gz"),
        ("x86_64-apple-darwin", "tar.gz"),
        ("aarch64-unknown-linux-gnu", "tar.gz"),
        ("x86_64-unknown-linux-gnu", "tar.gz"),
    ];

    /// The paths inside a real release archive.
    fn entries(archive: &std::path::Path, ext: &str) -> Vec<String> {
        let f = std::fs::File::open(archive).unwrap_or_else(|e| panic!("open {archive:?}: {e}"));
        if ext == "zip" {
            let mut z = zip::ZipArchive::new(f).expect("read zip");
            (0..z.len())
                .map(|i| z.by_index(i).unwrap().name().to_string())
                .collect()
        } else {
            let mut t = tar::Archive::new(flate2::read::GzDecoder::new(f));
            t.entries()
                .expect("read tar")
                .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
                .collect()
        }
    }

    /// The check the unit tests above structurally cannot make: that our path is
    /// really in the archive users download. Everything else in this file models
    /// cargo-dist's layout and self_update's substitution — and a model is exactly
    /// what shipped `lait.exe.exe` twice. This one reads the bytes.
    ///
    /// `#[ignore]` because it needs the archives on disk; CI's `updater-contract`
    /// job fetches the latest release into `$LAIT_RELEASE_ARCHIVES` and runs it
    /// with `--ignored`. Missing archives fail loudly rather than skipping —
    /// a check that silently passes when its input is absent is worse than none.
    #[test]
    #[ignore = "needs $LAIT_RELEASE_ARCHIVES; run in CI's updater-contract job"]
    fn update_bin_path_is_a_real_entry_in_the_published_archives() {
        let dir = std::env::var("LAIT_RELEASE_ARCHIVES")
            .expect("set $LAIT_RELEASE_ARCHIVES to a dir of downloaded lait-<target>.{zip,tar.gz}");
        let dir = std::path::Path::new(&dir);
        for (target, ext) in RELEASE_TARGETS {
            let archive = dir.join(format!("lait-{target}.{ext}"));
            assert!(archive.is_file(), "missing release archive {archive:?}");
            let want = expand(target);
            let found = entries(&archive, ext);
            assert!(
                found.contains(&want),
                "self_update would extract {want:?} from lait-{target}.{ext}, \
                 but that archive contains: {found:?}"
            );
        }
    }
}
