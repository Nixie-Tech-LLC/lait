//! The served client — the React app, compiled into the binary.
//!
//! `include_dir!` reads `src/serve/assets` at **compile time**, which is why that
//! directory holds *build output* and is *committed*. Three facts force it:
//! `Cargo.toml` excludes `viewer/` from the published crate, `publish-crates.yml`
//! is Rust-only, and `build.rs` deliberately never shells out to git so a plain
//! `cargo install lait` stays reproducible with no external toolchain. Building
//! the bundle during `cargo build` would need npm; leaving it in `viewer/` would
//! mean crates.io users get a `lait serve` with no UI. So it lives here, in git.
//!
//! The honest cost is build output under version control, kept fresh by
//! `npm run build` (which writes straight here) and guarded by CI diffing a
//! rebuild. See `docs/UI.md`, web surface.
//!
//! Serving it from the daemon — rather than from a dev server or a CDN — is also
//! what makes the client **same-origin**, which is the precondition for the
//! `Origin` allowlist in [`super::auth`] meaning anything at all.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use include_dir::{include_dir, Dir};

static ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/serve/assets");

/// Content types for what a vite build actually emits.
///
/// Hand-rolled rather than pulling `mime_guess`: this is a closed set we produce
/// ourselves, not arbitrary user files. The default is deliberately
/// `application/octet-stream` — an unknown asset should download inertly rather
/// than be sniffed and executed as something we didn't intend.
fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

/// Serve one asset by path, or the SPA entry when nothing matches.
///
/// The fallback is what makes client-side routing work: an unknown path is a
/// route for the app to resolve, not a 404 — the app is the only thing that knows
/// its own routes. Paths that escape the bundle simply miss and fall back too;
/// `include_dir` resolves against an embedded tree, not the filesystem, so there
/// is no directory to traverse out of.
pub fn asset(path: &str) -> Response {
    let path = path.trim_start_matches('/');
    if let Some(file) = ASSETS.get_file(path) {
        return (
            [(header::CONTENT_TYPE, content_type(path))],
            file.contents(),
        )
            .into_response();
    }
    index()
}

/// The SPA entry.
pub fn index() -> Response {
    match ASSETS.get_file("index.html") {
        Some(f) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            f.contents(),
        )
            .into_response(),
        // Only reachable if someone ships a build with an empty assets dir.
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "lait was built without its web client (src/serve/assets is empty — run `npm run build` in viewer/)",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_is_actually_embedded() {
        // The failure this catches is a build that silently ships no UI — the
        // whole point of committing the bundle.
        assert!(
            ASSETS.get_file("index.html").is_some(),
            "index.html missing"
        );
        assert!(ASSETS.get_file("app.js").is_some(), "app.js missing");
    }

    #[test]
    fn content_types_cover_what_vite_emits() {
        assert_eq!(content_type("app.js"), "text/javascript; charset=utf-8");
        assert_eq!(content_type("index.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        // Unknown extensions must not be guessed into something executable.
        assert_eq!(content_type("weird.xyz"), "application/octet-stream");
        assert_eq!(content_type("noext"), "application/octet-stream");
    }
}
