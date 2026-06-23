# Install Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `groupchat doctor` (converge to a single binary + diagnose PATH + stop stale daemons) and `groupchat prune` (remove abandoned per-session identities), plus installer/startup wiring, so reinstalling always lands a clean install.

**Architecture:** A new `src/doctor.rs` holds pure decision functions (keeper selection, removal set, PATH-shadow detection, updater-sibling derivation, prune selection) separated from thin side-effecting wrappers (fs discovery/removal, daemon stop). Two new registry-level subcommands are dispatched in `main.rs` before `resolve_home` (like `Agents`/`Resume`), since they act on the machine, not one resolved home.

**Tech Stack:** Rust 2021, clap 4 (derive), anyhow, directories 5, serde_json, tokio. Tests are `#[cfg(test)]` modules using `std::env::temp_dir()` (the pattern already used in `config.rs`).

## Global Constraints

- Crate/binary name: `groupchat`; binary built from `src/main.rs`.
- Never remove `std::env::current_exe()` — the running binary is always the keeper.
- Destructive steps (binary removal, identity removal) require confirmation; skip the prompt only with `--yes`. With no TTY and no `--yes`, refuse and exit non-zero.
- Permission-denied removing a path is reported, not fatal — continue the run.
- Never edit the user's shell rc; PATH problems are warnings only.
- Identity/state is never touched by `doctor`; only `prune` removes identity homes, and only when explicitly asked.
- Follow existing module style: `//!` module doc, `///` item docs, `anyhow::Result`, tests in a `#[cfg(test)] mod tests`.

---

### Task 1: Pure decision functions in `doctor.rs`

**Files:**
- Create: `src/doctor.rs`
- Modify: `src/main.rs:8-17` (add `mod doctor;` to the module list)
- Test: inline `#[cfg(test)] mod tests` in `src/doctor.rs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `pub fn removal_set(found: &[PathBuf], keeper: &Path) -> Vec<PathBuf>`
  - `pub fn dir_on_path(path_dirs: &[PathBuf], keeper_dir: &Path) -> bool`
  - `pub fn shadowed_by(path_dirs: &[PathBuf], keeper_dir: &Path, binary_dirs: &[PathBuf]) -> Option<PathBuf>`
  - `pub fn updater_sibling(binary: &Path) -> PathBuf`

- [ ] **Step 1: Add the module declaration**

In `src/main.rs`, add `mod doctor;` alphabetically in the `mod` block (after `mod control;`):

```rust
mod call;
mod cli;
mod config;
mod control;
mod doctor;
mod install;
mod mcp;
mod node;
mod presence;
mod proto;
mod registry;
```

- [ ] **Step 2: Write the failing tests**

Create `src/doctor.rs`:

```rust
//! `groupchat doctor` / `groupchat prune`: install hygiene.
//!
//! Pure decision functions (which binaries to remove, is the keeper on PATH,
//! which identities to prune) live here, separated from the thin fs/daemon
//! side-effecting wrappers so the risky "what to delete" logic is unit-tested.

use std::path::{Path, PathBuf};

/// Every found binary except the keeper (compared by canonical path).
pub fn removal_set(found: &[PathBuf], keeper: &Path) -> Vec<PathBuf> {
    found.iter().filter(|p| p.as_path() != keeper).cloned().collect()
}

/// Whether the keeper's directory is present anywhere on PATH.
pub fn dir_on_path(path_dirs: &[PathBuf], keeper_dir: &Path) -> bool {
    path_dirs.iter().any(|d| d.as_path() == keeper_dir)
}

/// If some PATH entry *earlier* than the keeper's dir also contains a groupchat
/// binary, the keeper is shadowed; return that earlier dir. `binary_dirs` is the
/// set of dirs known to hold a groupchat binary.
pub fn shadowed_by(
    path_dirs: &[PathBuf],
    keeper_dir: &Path,
    binary_dirs: &[PathBuf],
) -> Option<PathBuf> {
    let keeper_idx = path_dirs.iter().position(|d| d.as_path() == keeper_dir)?;
    path_dirs
        .iter()
        .take(keeper_idx)
        .find(|d| binary_dirs.iter().any(|b| b.as_path() == d.as_path()))
        .cloned()
}

/// The cargo-dist self-updater that sits next to a binary.
pub fn updater_sibling(binary: &Path) -> PathBuf {
    binary.with_file_name("groupchat-update")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_set_excludes_only_the_keeper() {
        let a = PathBuf::from("/a/groupchat");
        let b = PathBuf::from("/b/groupchat");
        let c = PathBuf::from("/c/groupchat");
        let out = removal_set(&[a.clone(), b.clone(), c.clone()], &b);
        assert_eq!(out, vec![a, c]);
    }

    #[test]
    fn dir_on_path_detects_presence() {
        let dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/home/me/.cargo/bin")];
        assert!(dir_on_path(&dirs, Path::new("/home/me/.cargo/bin")));
        assert!(!dir_on_path(&dirs, Path::new("/home/me/.local/bin")));
    }

    #[test]
    fn shadowed_by_finds_earlier_dir_with_binary() {
        let path = vec![
            PathBuf::from("/home/me/.local/bin"),
            PathBuf::from("/home/me/.cargo/bin"),
        ];
        let binary_dirs = vec![PathBuf::from("/home/me/.local/bin")];
        // keeper is in .cargo/bin, but .local/bin (earlier) also has one
        assert_eq!(
            shadowed_by(&path, Path::new("/home/me/.cargo/bin"), &binary_dirs),
            Some(PathBuf::from("/home/me/.local/bin"))
        );
        // no earlier dir holds a binary -> not shadowed
        assert_eq!(
            shadowed_by(&path, Path::new("/home/me/.local/bin"), &binary_dirs),
            None
        );
    }

    #[test]
    fn updater_sibling_is_next_to_binary() {
        assert_eq!(
            updater_sibling(Path::new("/home/me/.cargo/bin/groupchat")),
            PathBuf::from("/home/me/.cargo/bin/groupchat-update")
        );
    }
}
```

- [ ] **Step 3: Run tests to verify they pass (logic is in the same step as the test here)**

Run: `cargo test --lib doctor::tests 2>/dev/null || cargo test doctor::tests`
Expected: 4 tests pass. (The functions are written alongside the tests; the gate is they compile and pass.)

- [ ] **Step 4: Commit**

```bash
git add src/main.rs src/doctor.rs
git commit -m "feat(doctor): pure decision functions for install hygiene"
```

---

### Task 2: Binary discovery + removal (side-effecting)

**Files:**
- Modify: `src/doctor.rs`
- Test: inline tests in `src/doctor.rs`

**Interfaces:**
- Consumes: `removal_set`, `updater_sibling` from Task 1.
- Produces:
  - `pub fn candidate_dirs() -> Vec<PathBuf>` — PATH entries + known install dirs.
  - `pub fn discover_binaries(dirs: &[PathBuf]) -> Vec<PathBuf>` — canonicalized, deduped paths to existing `groupchat` files.
  - `pub fn remove_binaries(paths: &[PathBuf]) -> Vec<(PathBuf, std::io::Result<()>)>` — removes each binary and its updater sibling; returns per-path outcome.

- [ ] **Step 1: Write the failing test**

Add to `src/doctor.rs` (inside `mod tests`):

```rust
    #[test]
    fn discover_finds_groupchat_files_and_dedupes() {
        let base = std::env::temp_dir().join(format!("gc-discover-{}", std::process::id()));
        let d1 = base.join("a");
        let d2 = base.join("b");
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        std::fs::write(d1.join("groupchat"), b"x").unwrap();
        std::fs::write(d2.join("groupchat"), b"x").unwrap();
        std::fs::write(d2.join("other"), b"x").unwrap();

        let found = discover_binaries(&[d1.clone(), d2.clone(), d1.clone()]);
        assert_eq!(found.len(), 2, "two groupchat files, dir listed twice deduped");
        assert!(found.iter().all(|p| p.ends_with("groupchat")));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn remove_binaries_deletes_targets_and_updater() {
        let base = std::env::temp_dir().join(format!("gc-remove-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let bin = base.join("groupchat");
        let upd = base.join("groupchat-update");
        std::fs::write(&bin, b"x").unwrap();
        std::fs::write(&upd, b"x").unwrap();

        let outcomes = remove_binaries(&[bin.clone()]);
        assert!(outcomes.iter().all(|(_, r)| r.is_ok()));
        assert!(!bin.exists(), "binary removed");
        assert!(!upd.exists(), "sibling updater removed");

        let _ = std::fs::remove_dir_all(&base);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test doctor::tests::discover_finds doctor::tests::remove_binaries`
Expected: FAIL — `discover_binaries` / `remove_binaries` not found.

- [ ] **Step 3: Implement**

Add to `src/doctor.rs` (above the tests module):

```rust
use std::fs;

/// Directories worth scanning for a groupchat binary: everything on `$PATH`
/// plus the install locations our two installers use, even if not on PATH.
pub fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    if let Some(home) = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()) {
        for sub in [".cargo/bin", ".local/bin", "bin"] {
            dirs.push(home.join(sub));
        }
    }
    dirs.push(PathBuf::from("/usr/local/bin"));
    dirs.push(PathBuf::from("/opt/homebrew/bin"));
    dirs
}

/// Existing `groupchat` files in `dirs`, canonicalized and deduped.
pub fn discover_binaries(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        let candidate = dir.join("groupchat");
        if !candidate.is_file() {
            continue;
        }
        let canon = candidate.canonicalize().unwrap_or(candidate);
        if !out.contains(&canon) {
            out.push(canon);
        }
    }
    out
}

/// Remove each binary and its `groupchat-update` sibling (if present). Returns
/// the outcome per binary path so callers can report permission errors without
/// aborting the run.
pub fn remove_binaries(paths: &[PathBuf]) -> Vec<(PathBuf, std::io::Result<()>)> {
    let mut outcomes = Vec::new();
    for p in paths {
        let res = fs::remove_file(p);
        if res.is_ok() {
            let upd = updater_sibling(p);
            if upd.exists() {
                let _ = fs::remove_file(&upd);
            }
        }
        outcomes.push((p.clone(), res));
    }
    outcomes
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test doctor::tests`
Expected: all doctor tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/doctor.rs
git commit -m "feat(doctor): binary discovery and removal"
```

---

### Task 3: Daemon-stop helper across identity homes

**Files:**
- Modify: `src/config.rs` (add `identity_homes`)
- Modify: `src/doctor.rs` (add async `stop_running_daemons`)
- Test: inline test in `src/config.rs`

**Interfaces:**
- Consumes: `config::registry()` (existing), `control::Request::Stop`, `cli::run` (existing async client).
- Produces:
  - `pub fn identity_homes() -> Result<Vec<PathBuf>>` in `config.rs`
  - `pub async fn stop_running_daemons() -> usize` in `doctor.rs` (returns count stopped)

- [ ] **Step 1: Write the failing test (config helper)**

Add to `src/config.rs` `mod tests`:

```rust
    #[test]
    fn identity_homes_lists_agent_dirs() {
        let root = std::env::temp_dir().join(format!("gc-homes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        std::env::set_var("GROUPCHAT_CONFIG_ROOT", &root);
        let (reg, _) = registry().unwrap();
        let h = reg.home_for("agent-aaaaaa");
        fs::create_dir_all(&h).unwrap();

        let homes = identity_homes().unwrap();
        assert!(homes.iter().any(|p| p.ends_with("agent-aaaaaa")));

        std::env::remove_var("GROUPCHAT_CONFIG_ROOT");
        let _ = fs::remove_dir_all(&root);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test config::tests::identity_homes_lists_agent_dirs`
Expected: FAIL — `identity_homes` not found.

- [ ] **Step 3: Implement the config helper**

Add to `src/config.rs` (near `list_identities`):

```rust
/// Home directories of all registered identities (each is a node home with its
/// own socket/state). Used by `doctor` to find daemons to stop.
pub fn identity_homes() -> Result<Vec<PathBuf>> {
    let (reg, _) = registry()?;
    Ok(reg.list().into_iter().map(|n| reg.home_for(&n)).collect())
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test config::tests::identity_homes_lists_agent_dirs`
Expected: PASS.

- [ ] **Step 5: Implement the daemon-stop wrapper**

Add to `src/doctor.rs`:

```rust
use crate::{cli, config, control::Request};

/// Best-effort: send `Stop` to every identity home with a live control socket,
/// so after a binary swap no stale-version daemon keeps running. Failures
/// (no socket, daemon already down) are ignored. Returns the number stopped.
pub async fn stop_running_daemons() -> usize {
    let homes = match config::identity_homes() {
        Ok(h) => h,
        Err(_) => return 0,
    };
    let mut stopped = 0;
    for home in homes {
        if config::socket_path(&home).exists() && cli::run(&home, Request::Stop).await.is_ok() {
            stopped += 1;
        }
    }
    stopped
}
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo build`
Expected: builds with no errors.

- [ ] **Step 7: Commit**

```bash
git add src/config.rs src/doctor.rs
git commit -m "feat(doctor): stop stale daemons across identity homes"
```

---

### Task 4: `doctor` orchestration + `Doctor` subcommand

**Files:**
- Modify: `src/doctor.rs` (add `run_doctor`)
- Modify: `src/main.rs` (add `Doctor` variant + dispatch before `resolve_home`)
- Test: manual (orchestration ties together unit-tested parts; covered by `--dry-run`)

**Interfaces:**
- Consumes: `candidate_dirs`, `discover_binaries`, `removal_set`, `remove_binaries`, `dir_on_path`, `shadowed_by`, `stop_running_daemons`.
- Produces: `pub async fn run_doctor(dry_run: bool, yes: bool, keep: Option<PathBuf>, stop_daemon: bool) -> anyhow::Result<()>`

- [ ] **Step 1: Implement `run_doctor`**

Add to `src/doctor.rs`:

```rust
use anyhow::{Context, Result};
use std::io::IsTerminal;

/// Converge the machine to a single groupchat binary. Non-destructive to
/// identity/state. With `dry_run`, only report. The keeper defaults to the
/// running binary (`current_exe`).
pub async fn run_doctor(
    dry_run: bool,
    yes: bool,
    keep: Option<PathBuf>,
    stop_daemon: bool,
) -> Result<()> {
    let keeper = match keep {
        Some(p) => p.canonicalize().unwrap_or(p),
        None => {
            let exe = std::env::current_exe().context("locate current binary")?;
            exe.canonicalize().unwrap_or(exe)
        }
    };
    let dirs = candidate_dirs();
    let found = discover_binaries(&dirs);
    let to_remove = removal_set(&found, &keeper);

    println!("keeper: {}", keeper.display());
    println!("found {} groupchat binar{}", found.len(), if found.len() == 1 { "y" } else { "ies" });

    if to_remove.is_empty() {
        println!("no duplicates to remove.");
    } else {
        for p in &to_remove {
            println!("  will remove: {}", p.display());
        }
        if dry_run {
            println!("(dry run — nothing removed)");
        } else {
            if !yes {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("refusing to remove without --yes in a non-interactive context");
                }
                eprint!("Remove the above {} binar(y/ies)? [y/N] ", to_remove.len());
                use std::io::Write;
                std::io::stderr().flush().ok();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).ok();
                if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
                    println!("aborted.");
                    return Ok(());
                }
            }
            for (p, res) in remove_binaries(&to_remove) {
                match res {
                    Ok(()) => println!("  removed: {}", p.display()),
                    Err(e) => eprintln!("  could not remove {} ({e}) — skipped", p.display()),
                }
            }
        }
    }

    // PATH diagnosis (warn only).
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if let Some(keeper_dir) = keeper.parent() {
        if !dir_on_path(&path_dirs, keeper_dir) {
            println!("note: {} is not on your PATH. Add this line to your shell rc:", keeper_dir.display());
            println!("  export PATH=\"{}:$PATH\"", keeper_dir.display());
        }
    }

    if stop_daemon && !dry_run {
        let n = stop_running_daemons().await;
        if n > 0 {
            println!("stopped {n} running daemon(s) so the kept binary takes over.");
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Add the `Doctor` subcommand**

In `src/main.rs`, add to the `Command` enum (after `Stop`):

```rust
    /// Converge to a single clean install: remove duplicate/old groupchat
    /// binaries, diagnose PATH, and stop stale daemons. Never touches identity.
    Doctor {
        /// Report what would change without removing anything.
        #[arg(long)]
        dry_run: bool,
        /// Don't prompt before removing (used by installers).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Keep this binary instead of the currently-running one.
        #[arg(long)]
        keep: Option<std::path::PathBuf>,
        /// Don't stop running daemons.
        #[arg(long)]
        no_stop_daemon: bool,
    },
```

- [ ] **Step 3: Dispatch it before `resolve_home`**

In `src/main.rs`, add a match arm in the pre-resolution `match &args.command` block (alongside `Agents`/`Resume`):

```rust
        Command::Doctor { dry_run, yes, keep, no_stop_daemon } => {
            return doctor::run_doctor(*dry_run, *yes, keep.clone(), !*no_stop_daemon).await;
        }
```

Add `use crate::doctor;` if not already imported (the `mod doctor;` makes `crate::doctor` available; no extra `use` is strictly required since the arm uses the full path).

- [ ] **Step 4: Keep the by-value match exhaustive**

Adding `Doctor` to the enum makes the second `match args.command` (the one after `resolve_home`) non-exhaustive. Extend the existing unreachable arm in `src/main.rs` to include it:

```rust
        Command::Agents | Command::Resume { .. } | Command::Doctor { .. } => {
            unreachable!("handled before resolution")
        }
```

- [ ] **Step 5: Verify build + dry-run behavior**

Run:
```bash
cargo build
./target/debug/groupchat doctor --dry-run
```
Expected: builds; prints the keeper, the found binaries, and "(dry run — nothing removed)". No files change.

- [ ] **Step 6: Commit**

```bash
git add src/doctor.rs src/main.rs
git commit -m "feat(doctor): groupchat doctor subcommand"
```

---

### Task 5: Startup duplicate-detection hint

**Files:**
- Modify: `src/doctor.rs` (add `duplicate_hint`)
- Modify: `src/main.rs` (call it once near the top of `main`)
- Test: inline test in `src/doctor.rs`

**Interfaces:**
- Consumes: `discover_binaries`, `candidate_dirs`.
- Produces: `pub fn duplicate_hint() -> Option<String>` (the hint text, or None when clean).

- [ ] **Step 1: Write the failing test**

Add to `src/doctor.rs` `mod tests`:

```rust
    #[test]
    fn hint_text_mentions_doctor_when_multiple() {
        // We test the pure formatter, not the live environment.
        let msg = super::format_duplicate_hint(2);
        assert!(msg.contains("groupchat doctor"));
        assert!(super::format_duplicate_hint(1).is_empty());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test doctor::tests::hint_text_mentions_doctor_when_multiple`
Expected: FAIL — `format_duplicate_hint` not found.

- [ ] **Step 3: Implement**

Add to `src/doctor.rs`:

```rust
/// The hint shown when more than one groupchat binary is installed. Empty when
/// `count < 2`.
pub fn format_duplicate_hint(count: usize) -> String {
    if count < 2 {
        String::new()
    } else {
        format!("note: {count} groupchat installs detected — run `groupchat doctor` to clean up.")
    }
}

/// A one-line hint to stderr if the machine has duplicate installs, else None.
pub fn duplicate_hint() -> Option<String> {
    let found = discover_binaries(&candidate_dirs());
    let msg = format_duplicate_hint(found.len());
    if msg.is_empty() { None } else { Some(msg) }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test doctor::tests::hint_text_mentions_doctor_when_multiple`
Expected: PASS.

- [ ] **Step 5: Wire the hint into `main` (skip it for the doctor command itself)**

In `src/main.rs`, immediately after `let args = Cli::parse();`:

```rust
    // Cheap nudge: if duplicate installs exist, mention doctor once. Never for
    // the doctor command itself (it does the real work).
    if !matches!(args.command, Command::Doctor { .. }) {
        if let Some(hint) = doctor::duplicate_hint() {
            eprintln!("{hint}");
        }
    }
```

- [ ] **Step 6: Verify build**

Run: `cargo build`
Expected: builds with no errors.

- [ ] **Step 7: Commit**

```bash
git add src/doctor.rs src/main.rs
git commit -m "feat(doctor): startup hint when duplicate installs exist"
```

---

### Task 6: `prune` selection + identity-home listing

**Files:**
- Modify: `src/doctor.rs` (add `IdentityHome`, `prune_set`, `list_identity_homes`, `remove_identity_home`)
- Test: inline tests in `src/doctor.rs`

**Interfaces:**
- Consumes: `config::registry()`, `config::config_root()` (existing).
- Produces:
  - `pub struct IdentityHome { pub name: String, pub path: PathBuf, pub mapped: bool, pub modified_secs_ago: u64 }`
  - `pub fn prune_set(homes: &[IdentityHome], unmapped_only: bool, older_than_secs: Option<u64>) -> Vec<usize>` (indices into `homes`)
  - `pub fn list_identity_homes() -> anyhow::Result<Vec<IdentityHome>>`
  - `pub fn remove_identity_home(h: &IdentityHome) -> std::io::Result<()>`

- [ ] **Step 1: Write the failing test for the pure selector**

Add to `src/doctor.rs` `mod tests`:

```rust
    fn home(name: &str, mapped: bool, age: u64) -> IdentityHome {
        IdentityHome { name: name.into(), path: PathBuf::from("/x").join(name), mapped, modified_secs_ago: age }
    }

    #[test]
    fn prune_set_filters_unmapped_and_old() {
        let homes = vec![
            home("a", true, 100),    // mapped -> kept when unmapped_only
            home("b", false, 10),    // unmapped but young
            home("c", false, 1000),  // unmapped and old
        ];
        // unmapped only
        assert_eq!(prune_set(&homes, true, None), vec![1, 2]);
        // older than 500s only
        assert_eq!(prune_set(&homes, false, Some(500)), vec![2]);
        // unmapped AND older than 500s
        assert_eq!(prune_set(&homes, true, Some(500)), vec![2]);
        // no filters -> all
        assert_eq!(prune_set(&homes, false, None), vec![0, 1, 2]);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test doctor::tests::prune_set_filters_unmapped_and_old`
Expected: FAIL — `IdentityHome` / `prune_set` not found.

- [ ] **Step 3: Implement the struct + pure selector**

Add to `src/doctor.rs`:

```rust
/// A per-session identity home, with the metadata `prune` decides on.
#[derive(Debug, Clone)]
pub struct IdentityHome {
    pub name: String,
    pub path: PathBuf,
    /// Present in `sessions.json` (some session still recalls it).
    pub mapped: bool,
    /// Seconds since the home was last modified.
    pub modified_secs_ago: u64,
}

/// Indices of homes to prune given the filters. No filters = all.
pub fn prune_set(
    homes: &[IdentityHome],
    unmapped_only: bool,
    older_than_secs: Option<u64>,
) -> Vec<usize> {
    homes
        .iter()
        .enumerate()
        .filter(|(_, h)| !(unmapped_only && h.mapped))
        .filter(|(_, h)| older_than_secs.map_or(true, |t| h.modified_secs_ago >= t))
        .map(|(i, _)| i)
        .collect()
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test doctor::tests::prune_set_filters_unmapped_and_old`
Expected: PASS.

- [ ] **Step 5: Implement listing + removal (side-effecting)**

Add to `src/doctor.rs`:

```rust
use std::time::SystemTime;

/// All identity homes with metadata, reading the registry and `sessions.json`.
pub fn list_identity_homes() -> Result<Vec<IdentityHome>> {
    let (reg, sessions_path) = config::registry()?;
    let mapped_names: std::collections::HashSet<String> = fs::read_to_string(&sessions_path)
        .ok()
        .and_then(|s| serde_json::from_str::<std::collections::BTreeMap<String, String>>(&s).ok())
        .map(|m| m.into_values().collect())
        .unwrap_or_default();

    let mut out = Vec::new();
    for name in reg.list() {
        let path = reg.home_for(&name);
        let modified_secs_ago = fs::metadata(&path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mapped = mapped_names.contains(&name);
        out.push(IdentityHome { name, path, mapped, modified_secs_ago });
    }
    Ok(out)
}

/// Remove an identity home directory (and everything under it).
pub fn remove_identity_home(h: &IdentityHome) -> std::io::Result<()> {
    fs::remove_dir_all(&h.path)
}
```

- [ ] **Step 6: Verify build**

Run: `cargo build`
Expected: builds with no errors.

- [ ] **Step 7: Commit**

```bash
git add src/doctor.rs
git commit -m "feat(prune): identity-home listing and prune selection"
```

---

### Task 7: `prune` orchestration + `Prune` subcommand

**Files:**
- Modify: `src/doctor.rs` (add `run_prune`)
- Modify: `src/main.rs` (add `Prune` variant + dispatch before `resolve_home`)
- Test: manual via `--unmapped` against a throwaway `GROUPCHAT_CONFIG_ROOT`

**Interfaces:**
- Consumes: `list_identity_homes`, `prune_set`, `remove_identity_home`.
- Produces: `pub fn run_prune(unmapped: bool, older_than_secs: Option<u64>, yes: bool) -> anyhow::Result<()>`

- [ ] **Step 1: Implement `run_prune`**

Add to `src/doctor.rs`:

```rust
/// List accumulated per-session identities and remove the selected ones. Always
/// confirms unless `yes`. Never automatic.
pub fn run_prune(unmapped: bool, older_than_secs: Option<u64>, yes: bool) -> Result<()> {
    let homes = list_identity_homes()?;
    if homes.is_empty() {
        println!("no identities to prune.");
        return Ok(());
    }
    let idxs = prune_set(&homes, unmapped, older_than_secs);
    if idxs.is_empty() {
        println!("nothing matches the prune filters.");
        return Ok(());
    }
    for &i in &idxs {
        let h = &homes[i];
        println!(
            "  {}  ({}, last active {}s ago)",
            h.name,
            if h.mapped { "mapped" } else { "unmapped" },
            h.modified_secs_ago
        );
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!("refusing to prune without --yes in a non-interactive context");
        }
        eprint!("Remove the above {} identit(y/ies) and their state? [y/N] ", idxs.len());
        use std::io::Write;
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        if !matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
            println!("aborted.");
            return Ok(());
        }
    }
    for &i in &idxs {
        let h = &homes[i];
        match remove_identity_home(h) {
            Ok(()) => println!("  removed {}", h.name),
            Err(e) => eprintln!("  could not remove {} ({e}) — skipped", h.name),
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Add the `Prune` subcommand**

In `src/main.rs` `Command` enum (after `Doctor`):

```rust
    /// Remove accumulated per-session identities you no longer use. Manual and
    /// confirmed — never automatic, never run by reinstall.
    Prune {
        /// Only identities not mapped to any session.
        #[arg(long)]
        unmapped: bool,
        /// Only identities inactive for at least this many seconds.
        #[arg(long)]
        older_than_secs: Option<u64>,
        /// Don't prompt before removing.
        #[arg(long, short = 'y')]
        yes: bool,
    },
```

- [ ] **Step 3: Dispatch it before `resolve_home`**

In the pre-resolution `match &args.command` block in `src/main.rs`:

```rust
        Command::Prune { unmapped, older_than_secs, yes } => {
            return doctor::run_prune(*unmapped, *older_than_secs, *yes);
        }
```

- [ ] **Step 4: Keep the by-value match exhaustive**

Extend the same unreachable arm in `src/main.rs` to also list `Prune` (it now reads):

```rust
        Command::Agents | Command::Resume { .. } | Command::Doctor { .. } | Command::Prune { .. } => {
            unreachable!("handled before resolution")
        }
```

- [ ] **Step 5: Verify build + behavior on an empty throwaway root**

Run:
```bash
cargo build
GROUPCHAT_CONFIG_ROOT=/tmp/gc-prune-test ./target/debug/groupchat prune --unmapped
```
Expected: builds; prints "no identities to prune." (the throwaway root is empty).

- [ ] **Step 6: Commit**

```bash
git add src/doctor.rs src/main.rs
git commit -m "feat(prune): groupchat prune subcommand"
```

---

### Task 8: Installer integration (GitLab install.sh)

**Files:**
- Modify: `.gitlab-ci.yml` (the section that generates/publishes `install.sh`) — append a `doctor --yes` call to the generated installer.
- Test: manual review of the generated `install.sh` body.

**Interfaces:**
- Consumes: the `groupchat doctor --yes` CLI from Task 4.
- Produces: an `install.sh` whose final step self-converges the install.

- [ ] **Step 1: Locate the install.sh generation**

Run: `grep -n "install.sh\|\.local/bin\|PATH" .gitlab-ci.yml`
Expected: find the heredoc/echo block that writes `install.sh`.

- [ ] **Step 2: Append the doctor call to the generated installer**

In the generated `install.sh` body (after it places the binary on PATH and prints success), add:

```sh
# Converge to a single clean install (remove any older/duplicate binaries).
if command -v groupchat >/dev/null 2>&1; then
  groupchat doctor --yes || true
fi
```

(The `|| true` keeps a cleanup hiccup from failing the install.)

- [ ] **Step 3: Validate the CI file**

Run: `groupchat validate_project_ci_lint` is not available locally; instead sanity-check YAML:
```bash
ruby -ryaml -e "YAML.load_file('.gitlab-ci.yml')" 2>/dev/null && echo "YAML ok" || python3 -c "import yaml,sys; yaml.safe_load(open('.gitlab-ci.yml')); print('YAML ok')"
```
Expected: "YAML ok".

- [ ] **Step 4: Commit**

```bash
git add .gitlab-ci.yml
git commit -m "ci: run groupchat doctor --yes after install to converge"
```

---

### Task 9: Final integration check + docs

**Files:**
- Modify: `README.md` (add `doctor` and `prune` to the CLI reference table)
- Test: full `cargo test` + `cargo build`

- [ ] **Step 1: Add the two commands to the README CLI table**

In `README.md`'s "CLI reference" table, add rows:

```markdown
| `doctor [--dry-run] [--keep PATH] [--no-stop-daemon] [-y]` | Converge to one clean install: remove duplicate/old binaries, diagnose PATH, stop stale daemons |
| `prune [--unmapped] [--older-than-secs N] [-y]` | Remove accumulated per-session identities you no longer use |
```

- [ ] **Step 2: Run the full test suite**

Run: `cargo test`
Expected: all tests pass, including the existing `config::tests` and `node::tests`.

- [ ] **Step 3: Build release and smoke-test**

Run:
```bash
cargo build
./target/debug/groupchat doctor --dry-run
./target/debug/groupchat prune --unmapped --older-than-secs 999999
```
Expected: `doctor` reports the current install (likely just the one keeper); `prune` reports nothing matches or no identities.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document groupchat doctor and prune"
```
