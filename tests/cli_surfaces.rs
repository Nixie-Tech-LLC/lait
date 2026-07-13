//! Hardening guards for the stateless install-surface commands
//! (`lait completions <shell>`, `lait man`).
//!
//! These back the distribution/packaging story: shell completions and the man
//! page are generated at runtime from the clap command tree (`app.rs`), so
//! packagers (Homebrew/Scoop/winget/etc.) can emit them during install with no
//! separate spec to drift. The tests assert three contracts:
//!
//! 1. **Every advertised shell works** — each `Shell` value produces non-empty,
//!    well-formed output and exits `0`; an unknown shell fails cleanly (`!= 0`).
//! 2. **The man page renders** — valid roff naming lait(1).
//! 3. **They are truly stateless** — dispatched *before* home/identity/workspace
//!    resolution (`app.rs::run`), so they never spawn a daemon, mint a key, or
//!    create a store. A packager running them in a clean sandbox must not leave a
//!    `$LAIT_HOME` behind. This is the regression guard for that early dispatch.

use std::process::Command;

fn lait() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lait"))
}

/// The shells lait advertises (README/`docs/INSTALL.md`) and a marker string that
/// must appear in each generator's output, so a silently-empty or wrong-shell
/// generation fails loudly.
const SHELLS: &[(&str, &str)] = &[
    ("bash", "_lait()"),
    ("zsh", "#compdef lait"),
    ("fish", "complete -c lait"),
    ("powershell", "Register-ArgumentCompleter"),
    ("elvish", "edit:completion"),
];

#[test]
fn completions_generate_for_every_advertised_shell() {
    for (shell, marker) in SHELLS {
        let out = lait()
            .args(["completions", shell])
            .output()
            .unwrap_or_else(|e| panic!("spawn `lait completions {shell}`: {e}"));
        assert!(
            out.status.success(),
            "`lait completions {shell}` exited {:?}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr),
        );
        let script = String::from_utf8_lossy(&out.stdout);
        assert!(
            !script.trim().is_empty(),
            "`lait completions {shell}` produced empty output",
        );
        assert!(
            script.contains(marker),
            "`lait completions {shell}` output is missing the expected marker `{marker}`",
        );
        // Completions should reference real subcommands, proving they were built
        // from the live command tree rather than a stub.
        assert!(
            script.contains("daemon") && script.contains("completions"),
            "`lait completions {shell}` does not mention known subcommands",
        );
    }
}

#[test]
fn completions_reject_an_unknown_shell() {
    let out = lait()
        .args(["completions", "borkshell"])
        .output()
        .expect("spawn lait completions borkshell");
    assert!(
        !out.status.success(),
        "an unknown shell should be a usage error (non-zero exit)",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("borkshell") || stderr.contains("possible values"),
        "the error should name the bad value / list valid shells; got: {stderr}",
    );
}

#[test]
fn man_page_renders_valid_roff() {
    let out = lait().arg("man").output().expect("spawn lait man");
    assert!(
        out.status.success(),
        "`lait man` exited {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    let roff = String::from_utf8_lossy(&out.stdout);
    // .TH is the roff title header; the man page must name lait(1).
    assert!(
        roff.contains(".TH lait 1"),
        "man output is missing the `.TH lait 1` title header",
    );
    assert!(
        roff.contains(".SH NAME") && roff.contains("lait"),
        "man output is missing a NAME section",
    );
}

/// The invariant that makes these safe for packagers: they resolve no workspace.
/// Point `$LAIT_HOME` at a fresh empty dir, generate completions + the man page,
/// and assert the dir is *still* empty — no `secret.key`, `profile.json`, or
/// `repo/` was created, and no daemon was spawned.
#[test]
fn install_surfaces_are_stateless() {
    let dir = std::env::temp_dir().join(format!(
        "lait-stateless-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&dir).expect("create temp LAIT_HOME");

    for args in [vec!["completions", "fish"], vec!["man"]] {
        let out = lait()
            .env("LAIT_HOME", &dir)
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("spawn lait {args:?}: {e}"));
        assert!(
            out.status.success(),
            "`lait {args:?}` failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );
    }

    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .expect("read temp LAIT_HOME")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        leftovers.is_empty(),
        "install-surface commands must not touch $LAIT_HOME, but created: {leftovers:?}",
    );
}
