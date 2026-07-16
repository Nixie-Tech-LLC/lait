//! Build-time version stamping, and the one thing cargo cannot work out for itself:
//! that the embedded web bundle is a compile-time **input**.
//!
//! Exposes `LAIT_VERSION_LONG` — the string `lait --version` prints — as a
//! compile-time env the CLI reads via `env!`.
//!
//! Stable/release builds print a clean semver (`0.4.5`). A **dev-channel** build
//! (the `Dev Release` workflow, or any build that sets `LAIT_BUILD_SHA`) appends a
//! `-dev+<sha> (<date>)` suffix so a nightly binary is unmistakable from a tagged
//! release. We deliberately read **only** explicit env vars — never shell out to
//! git — so a normal `cargo install` / cargo-dist release stays clean and
//! reproducible, and only the dev workflow opts into the suffix.

use std::env;
use std::path::Path;

/// The bundle `serve::shell` embeds. Relative to `CARGO_MANIFEST_DIR`.
const ASSETS: &str = "src/serve/assets";

fn main() {
    // Re-run only when the stamping inputs change (not on every source edit).
    println!("cargo:rerun-if-env-changed=LAIT_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=LAIT_BUILD_DATE");
    // Emitting any `rerun-if-*` replaces cargo's default "re-run when anything in
    // the package changed", so build.rs has to name itself or edits to this file
    // stop taking effect.
    println!("cargo:rerun-if-changed=build.rs");

    track_assets();

    let base = env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let sha = env::var("LAIT_BUILD_SHA").unwrap_or_default();
    let date = env::var("LAIT_BUILD_DATE").unwrap_or_default();

    // Human-facing version for `lait --version`.
    let long = if sha.is_empty() {
        base.clone()
    } else if date.is_empty() {
        format!("{base}-dev+{sha}")
    } else {
        format!("{base}-dev+{sha} ({date})")
    };

    // A VALID-semver form for the self-updater's version comparison. A dev build
    // uses a PRERELEASE identifier (`X.Y.Z-dev.<sha>`), which semver orders BELOW
    // the stable `X.Y.Z` — so `lait update` on a dev node correctly sees the
    // stable release as newer and heals onto it. LAIT_VERSION_LONG can't be used
    // here: its ` (<date>)` suffix is not valid semver, and the bare
    // CARGO_PKG_VERSION would make a dev node report itself as the stable version
    // (so `lait update` saw "already up to date" and stranded it on the dev build).
    let semver = if sha.is_empty() {
        base
    } else {
        format!("{base}-dev.{sha}")
    };

    println!("cargo:rustc-env=LAIT_VERSION_LONG={long}");
    println!("cargo:rustc-env=LAIT_VERSION_SEMVER={semver}");
}

/// Tell cargo that `src/serve/assets` is a source input.
///
/// **The bug this fixes:** `serve::shell` embeds the bundle with `include_dir!`,
/// which reads those files while the macro expands. `include_str!`/`include_bytes!`
/// are handled by rustc itself, which records them in the dep-info file — but a
/// *proc macro* cannot do that on stable (`proc_macro::tracked_path` is unstable).
/// So cargo has never known those files exist.
///
/// The symptom is the worst kind: `npm run build` writes a new `app.js`, `cargo
/// build` prints **Finished** without recompiling, and `lait serve` cheerfully
/// serves the previous bundle. Nothing errors. It looks exactly like your change not
/// working, and the folk remedy — `touch src/serve/shell.rs` — is a ritual nobody
/// should have to learn.
///
/// **Why per file, not the directory.** `rerun-if-changed=<dir>` looks tempting and
/// is half-broken: cargo stats the directory, and a directory's mtime changes when an
/// entry is added or removed but *not* when a file's contents change. Editing
/// `app.js` in place — which is every rebuild — would go unnoticed. So we walk and
/// name each file. The directory is emitted too, because that half *is* the half that
/// catches a new or deleted asset.
///
/// Missing directory is not an error: `cargo package` builds from a pruned tree, and
/// `shell.rs` already has a test and a runtime message for "built without a UI".
fn track_assets() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(ASSETS);
    if !root.exists() {
        return;
    }
    println!("cargo:rerun-if-changed={}", root.display());
    track_dir(&root);
}

fn track_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        // Unreadable is not fatal — worst case we under-track and the developer is
        // back where they started. Failing the build over it would be worse.
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            println!("cargo:rerun-if-changed={}", path.display());
            track_dir(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
