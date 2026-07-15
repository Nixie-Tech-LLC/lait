//! `lait serve` — the local HTTP surface, and the browser's Layer-B client.
//!
//! The engine's contract has always been [`crate::control`]: a versioned,
//! hand-maintained imperative façade over the CRDT, spoken over a Unix socket or
//! a named pipe. Every client so far (CLI, TUI, MCP) is a local process, so that
//! transport cost them nothing. A browser cannot speak a named pipe. This module
//! is the *one* adapter that closes that gap — the same `Request`/`Response`
//! types, the same `Doorbell` stream, re-bound to a loopback TCP socket and SSE.
//!
//! Two things follow, and they are the whole design:
//!
//! **This is a supervisor, not a client.** The control channel is keyed by home,
//! so there is one daemon per space. A CLI invocation resolves exactly one store
//! and talks to exactly one daemon; the browser is a picker over *all* of them,
//! so it holds N. See [`spaces::Supervisor`].
//!
//! **The socket was the authentication.** Binding the same façade to a TCP port
//! removes the OS permission check that made auth unnecessary, and adds a caller
//! that never existed before: the web pages the user visits. See [`auth`].
//!
//! The browser is deliberately *not* a peer. It holds no key, has no entry in the
//! ACL, and is never invited: it is a lens on a device's replica, exactly like
//! the TUI was, and the device remains the only network identity.

pub mod auth;
pub mod policy;
pub mod spaces;

mod shell;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Redirect, Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use tokio_stream::StreamExt;

use crate::control::{ErrorKind, Request};
use auth::{Guard, Refusal};
use spaces::Supervisor;

/// The default port. Fixed rather than ephemeral so the URL is predictable and
/// the `Origin` allowlist has something stable to name; a collision is reported
/// rather than silently worked around, because a `lait serve` that lands on a
/// *different* port than it was asked for is a footgun for anything that
/// bookmarked it.
pub const DEFAULT_PORT: u16 = 7717;

/// The cookie the browser trades its one-time URL token for.
///
/// Named per-port, because **cookies ignore the port**: `127.0.0.1:7717` and
/// `127.0.0.1:7801` are the same cookie origin, so a fixed name would have two
/// concurrent `lait serve` runs silently clobbering each other's credential —
/// whichever loaded last wins, and the other tab starts 401ing. The port is not a
/// security boundary here (the token is); it is what keeps two runs from being the
/// same jar entry.
fn cookie_name(port: u16) -> String {
    format!("lait_token_{port}")
}

struct App {
    guard: Guard,
    sup: Supervisor,
    cookie: String,
}

/// Run the local server until interrupted.
pub async fn run(port: u16, open: bool) -> Result<()> {
    // Identity scoping, resolved once at startup — see `spaces::scope` for why
    // `$LAIT_HOME` is the axis that matters.
    let identity = crate::config::identity_dir()?;
    let self_contained = std::env::var_os("LAIT_HOME").is_some();
    let agents_base = crate::registry::agents_base(&crate::config::config_root()?);

    // Loopback only. Not `0.0.0.0`: that would hand the LAN an unauthenticated-
    // by-default view of every space on this machine, and the token is the only
    // thing that would stand between them and it.
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .with_context(|| {
            format!("bind 127.0.0.1:{port} (is another `lait serve` already running?)")
        })?;
    let bound = listener.local_addr().context("read bound address")?;

    let token = mint_token();
    let app = Arc::new(App {
        guard: Guard::new(token.clone(), bound.port()),
        sup: Supervisor::new(identity, agents_base, self_contained),
        cookie: cookie_name(bound.port()),
    });

    let url = format!("http://127.0.0.1:{}/?token={}", bound.port(), token);
    println!("lait serve — your spaces at:\n  {url}");
    println!("(loopback only; this link carries a one-time token for this run)");
    if open {
        open_browser(&url);
    }

    axum::serve(listener, router(app)).await.context("serve")?;
    Ok(())
}

fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/spaces", get(list_spaces))
        .route("/api/spaces/{id}/rpc", post(rpc))
        .route("/api/events", get(events))
        .layer(axum::middleware::from_fn_with_state(app.clone(), gate))
        .with_state(app)
}

/// A 32-byte hex token, minted per run and never persisted.
fn mint_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("getrandom");
    data_encoding::HEXLOWER.encode(&buf)
}

/// The gate every request passes: rebinding guard first, credential second.
///
/// Ordering is deliberate. `check_origin` is what survives a successful rebind
/// (at which point the browser *will* hand over our cookie), so it must not be
/// reachable-past by anything the attacker controls. The token is checked only
/// once we already believe the request is addressed to us by a loopback name.
async fn gate(State(app): State<Arc<App>>, req: axum::extract::Request, next: Next) -> Response {
    let headers = req.headers();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if let Err(r) = app.guard.check_origin(host, origin) {
        return refuse(r);
    }

    // Three ways to present the token, one meaning. The query form exists only
    // for the opening navigation — `index` immediately trades it for the cookie
    // and redirects, so it never lingers in history or a Referer.
    //
    // Precedence is load-bearing: **query beats cookie**. The token is per-run,
    // but the cookie outlives the run that set it, so after a restart the jar
    // holds a stale credential. Consulting it first would shadow the fresh token
    // the user was just handed and 401 them out of the link they legitimately
    // clicked — with no way back, since nothing in the UI can clear a cookie it
    // cannot read. An explicit token in the URL is a deliberate handoff and wins.
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| auth::cookie_value(c, &app.cookie));
    let query = req.uri().query().and_then(|q| query_param(q, "token"));
    let presented = bearer.or(query.as_deref()).or(cookie);

    if let Err(r) = app.guard.check_token(presented) {
        return refuse(r);
    }
    next.run(req).await
}

fn refuse(r: Refusal) -> Response {
    let code = match r {
        Refusal::BadToken => StatusCode::UNAUTHORIZED,
        _ => StatusCode::FORBIDDEN,
    };
    (code, err_json(r.reason(), ErrorKind::Error)).into_response()
}

/// Errors go out in the same envelope `--json` emits, so a browser client and a
/// CLI client are reading one contract rather than two.
fn err_json(message: &str, error_kind: ErrorKind) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "kind": "error",
        "message": message,
        "error_kind": error_kind,
    }))
}

/// Minimal `application/x-www-form-urlencoded` lookup — one key, no allocation
/// beyond the hit. Avoids a query-string crate for a single parameter.
fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

#[derive(Deserialize)]
struct IndexQuery {
    token: Option<String>,
}

/// The shell — and the one-time token handoff.
///
/// Arriving with `?token=` means this is the opening navigation: set the cookie
/// and redirect to a clean `/`. The token is then out of the URL bar, out of
/// history, and out of any `Referer` the page might later emit. `HttpOnly` keeps
/// it out of reach of script in our own page; `SameSite=Strict` keeps the browser
/// from attaching it to anyone else's request.
async fn index(State(app): State<Arc<App>>, Query(q): Query<IndexQuery>) -> Response {
    if let Some(token) = q.token {
        // Overwrites whatever this port's previous run left behind — the gate let
        // us here on the query token, so this is the credential that is current.
        let cookie = format!("{}={token}; Path=/; HttpOnly; SameSite=Strict", app.cookie);
        return ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response();
    }
    axum::response::Html(shell::HTML).into_response()
}

async fn list_spaces(State(app): State<Arc<App>>) -> Response {
    Json(serde_json::json!({ "spaces": app.sup.list().await })).into_response()
}

#[derive(Deserialize)]
struct RpcQuery {
    /// The client has already asked [`crate::cli::destructive_question`] and been
    /// told yes. See [`rpc`].
    #[serde(default)]
    confirm: bool,
}

/// The control plane, verbatim: `POST /api/spaces/{id}/rpc` with a [`Request`],
/// back a [`crate::control::Response`].
///
/// One endpoint rather than a REST surface, because the REST surface would be a
/// second, hand-maintained projection of a façade that is *already* the stable,
/// versioned, hand-maintained projection (S§7). Two of those drift; the viewer
/// branch is the proof — it still calls `projects new --key`, a shape that stopped
/// existing. This cannot drift: it is the same enum the CLI, TUI and MCP send.
///
/// Selecting a space is what attaches its daemon, so this is also the first point
/// at which anything is started.
///
/// Three gates, in order:
///
/// 1. **`Subscribe` is refused.** It is a stream, not a one-shot: `control::request`
///    writes and reads exactly one line, so a subscribe here would decode a
///    `Doorbell` as a `Response` and fail confusingly. `GET /api/events` is the door.
/// 2. **An agent's space is observable, not operable.** Writes are refused with the
///    agent's name in the message. Reads through an agent's daemon are exactly the
///    observability they were scoped in for; a *write* would be signed by the agent
///    and land under its name. If you are a member of that workspace, write through
///    your own space and sign as yourself — see [`spaces::scope`].
/// 3. **Destructive verbs keep the CLI's question.** `confirm_destructive` is a TTY
///    affordance: it refuses under `--json` because a pipe cannot be asked. A browser
///    can — it has a modal — so rather than bypass the gate or inherit the pipe's
///    refusal, the question comes back as a `409 confirm_required` and the UI asks
///    it. The string is `cli::destructive_question`'s, not a paraphrase, so the two
///    surfaces cannot disagree about what is dangerous.
///
/// Gate 3 protects against an *accident*, not an attacker: anything that can POST
/// `delete` can also POST `?confirm=1`. That is the same guarantee the CLI's prompt
/// gives, and it is worth being honest that it is the whole of it.
async fn rpc(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    Query(q): Query<RpcQuery>,
    Json(req): Json<Request>,
) -> Response {
    if matches!(req, Request::Subscribe { .. }) {
        return (
            StatusCode::BAD_REQUEST,
            err_json(
                "subscribe is a stream, not a request — use GET /api/events",
                ErrorKind::Error,
            ),
        )
            .into_response();
    }

    let identity = match app.sup.resolve(&id) {
        Ok((_, identity)) => identity,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                err_json(&e.to_string(), ErrorKind::NotFound),
            )
                .into_response()
        }
    };

    if let spaces::SpaceIdentity::Agent { name } = &identity {
        if !policy::is_read(&req) {
            return (
                StatusCode::FORBIDDEN,
                err_json(
                    &format!(
                        "{name}'s space is read-only here — a write would be signed as {name}. \
                         Open the same workspace from your own space to write as yourself."
                    ),
                    ErrorKind::Error,
                ),
            )
                .into_response();
        }
    }

    if !q.confirm {
        if let Some(question) = crate::cli::destructive_question(&req) {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "kind": "confirm_required",
                    "question": question,
                })),
            )
                .into_response();
        }
    }

    match app.sup.request(&id, &req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            err_json(&e.to_string(), ErrorKind::Error),
        )
            .into_response(),
    }
}

/// The doorbell multiplex: one `EventSource` over every attached space.
///
/// Carries dirty *flags*, never state — the browser re-reads the authoritative
/// projection for each dirty scope, exactly as the TUI does (UI.md §4.2). A
/// `Lagged` receiver is surfaced rather than hidden: the client's response is the
/// same rebaseline it already performs for `reset`/epoch changes (UI.md §4.1), so
/// dropping frames under load is recoverable by construction.
async fn events(
    State(app): State<Arc<App>>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = BroadcastStream::new(app.sup.subscribe()).map(|r| {
        Ok(match r {
            Ok(sd) => Event::default()
                .event("doorbell")
                .json_data(sd)
                .unwrap_or_else(|_| Event::default().event("lagged").data("encode")),
            Err(BroadcastStreamRecvError::Lagged(n)) => {
                Event::default().event("lagged").data(n.to_string())
            }
        })
    });
    // Keep-alive so an idle space (no doorbells for minutes) doesn't look like a
    // dead connection to an intermediary or to the browser's own reconnect logic.
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Best-effort browser launch. Failure is not an error: the URL is already on
/// stdout, which is the contract; opening a window is a courtesy.
fn open_browser(url: &str) {
    let spawned = if cfg!(windows) {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    if let Err(e) = spawned {
        tracing::debug!(error = %e, "could not open a browser; use the printed URL");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_param_finds_only_an_exact_key() {
        assert_eq!(query_param("token=abc", "token"), Some("abc".into()));
        assert_eq!(
            query_param("a=1&token=abc&b=2", "token"),
            Some("abc".into())
        );
        assert_eq!(query_param("a=1", "token"), None);
        // A key that merely ends with ours must not match.
        assert_eq!(query_param("xtoken=abc", "token"), None);
        assert_eq!(query_param("", "token"), None);
    }

    /// The precedence bug this exists to prevent, reproduced at the unit level.
    ///
    /// Cookies ignore the port, so a previous `lait serve` run leaves a stale
    /// `lait_token_*` in the jar for `127.0.0.1`. If the cookie were consulted
    /// before the query, clicking a freshly-printed URL would 401 — and stay
    /// 401ing, because the page cannot clear an HttpOnly cookie it cannot read.
    /// Found by restarting the server and opening the new link.
    #[test]
    fn a_fresh_url_token_beats_a_stale_cookie() {
        let guard = Guard::new("fresh".into(), 7717);
        let stale = auth::cookie_value("lait_token_7717=stale", "lait_token_7717");
        let query = query_param("token=fresh", "token");

        // The resolution order `gate` uses.
        let presented = None.or(query.as_deref()).or(stale);
        assert_eq!(presented, Some("fresh"));
        assert!(guard.check_token(presented).is_ok());

        // Cookie-first would have picked the stale one and locked the user out.
        let wrong = None.or(stale).or(query.as_deref());
        assert_eq!(wrong, Some("stale"));
        assert!(guard.check_token(wrong).is_err());
    }

    #[test]
    fn cookie_name_is_per_port_so_two_runs_do_not_share_a_jar_entry() {
        assert_ne!(cookie_name(7717), cookie_name(7801));
    }

    #[test]
    fn minted_tokens_are_64_hex_chars_and_not_repeated() {
        let a = mint_token();
        let b = mint_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "a per-run token must not be deterministic");
    }
}
