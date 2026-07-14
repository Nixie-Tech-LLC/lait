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
use clap_complete::{generate, Shell};

use crate::{
    cli::Out,
    cmdspec::{self, Dispatch, Special},
    config::{self, load_or_create_identity, Profile},
    control::Request,
    install::{self, Client, Scope},
    mcp, node,
};

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
    let (leaf, m) =
        cmdspec::resolve(&specs, &matches).ok_or_else(|| anyhow!("no subcommand given"))?;

    if !leaf.service {
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
            return crate::cli::run(&home, Request::Status, out).await;
        }
        // The joined-workspace registry: pure navigation state, no store/daemon.
        Dispatch::Special(Special::Workspaces) => {
            crate::cli::print_workspaces(out);
            return Ok(());
        }
        _ => {}
    }

    // Home resolution honours an explicit --home over the session registry.
    if let Some(h) = matches.get_one::<String>("home") {
        std::env::set_var("LAIT_HOME", h);
    }
    // `update` swaps the binary; it must not resolve/create a workspace store.
    if matches!(leaf.dispatch, Dispatch::Special(Special::Update)) {
        return run_update().await;
    }
    // Directory-trap guard (docs/GUIDED-JOIN.md §B): a *read-only* command run in a
    // directory with no discoverable `.lait/` must NOT silently create a decoy
    // store. When we know of workspaces they've joined, point them there and exit
    // instead of manufacturing an empty one. `init`/`join` (and writes) still
    // create; an explicit `--home`/`$LAIT_HOME` opts out.
    if leaf.read_only && config::existing_home().is_none() {
        let known = crate::workspaces::list();
        if !known.is_empty() {
            crate::cli::warn_no_workspace_here(&known, out);
            std::process::exit(2);
        }
    }
    let home = config::resolve_home(None)?;

    match &leaf.dispatch {
        // The uniform path: build one Request and round-trip the daemon.
        Dispatch::Request(f) => {
            let req = f(m)?;
            crate::cli::run(&home, req, out).await?;
        }
        Dispatch::Special(s) => match s {
            Special::Init => {
                let key = load_or_create_identity(&config::identity_dir()?)?;
                let mut profile = Profile::load(&home)?;
                if let Some(n) = m.get_one::<String>("nick") {
                    profile.nick = n.clone();
                }
                if let Some(r) = m.get_one::<String>("room") {
                    profile.room = r.clone();
                }
                profile.save(&home)?;
                if out.json {
                    crate::cli::emit_ok(
                        &format!(
                            "initialized id={} nick={} room={}",
                            key.public(),
                            profile.nick,
                            profile.room
                        ),
                        out,
                    );
                } else {
                    println!("initialized.");
                    println!("id:   {}", key.public());
                    println!("nick: {}", profile.nick);
                    println!("room: {}", profile.room);
                    println!("home: {}", home.display());
                }
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
            Special::Join => {
                // Set the display name before the daemon is auto-spawned (via
                // ensure_daemon) so a cold joiner announces the right name on its
                // join request. It stays a self-asserted claim — the admin approves
                // by key, never by this nick (UI.md §8).
                if let Some(n) = m.get_one::<String>("nick") {
                    let mut profile = Profile::load(&home)?;
                    profile.nick = n.clone();
                    profile.save(&home)?;
                }
                let ticket = m.get_one::<String>("ticket").cloned().unwrap_or_default();
                // `join` runs the guided-join verifier as its tail so the joiner
                // sees the gate readout — including a directory/store mismatch —
                // instead of a bare "ok".
                crate::cli::run_join(&home, ticket, out).await?
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
            | Special::Update => {
                unreachable!("handled before home resolution")
            }
        },
    }

    Ok(())
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
