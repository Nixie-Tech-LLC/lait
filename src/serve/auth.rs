//! Loopback authentication for `lait serve` — re-establishing in userspace what
//! the control socket got from the OS for free.
//!
//! [`crate::control`] has never carried authentication, and correctly so: a Unix
//! socket is gated by filesystem permissions and a Windows named pipe by its
//! DACL, so *being able to open the channel* *is* the credential. Every Layer-B
//! client to date (CLI, TUI, MCP) inherited that for free by being a local
//! process.
//!
//! An HTTP port inherits none of it. Two distinct callers appear the moment the
//! same façade is bound to a socket the network stack will route:
//!
//! 1. **any other process on the machine** — loopback has no peer credential we
//!    check, so a different user's process can connect; and
//! 2. **any web page the user visits** — this is the sharp one. A page cannot
//!    read a cross-origin response, but it can *send* the request, and DNS
//!    rebinding (`evil.com` re-resolving to `127.0.0.1`) is specifically designed
//!    to make the browser treat us as same-origin and hand over the reply.
//!
//! So this module reconstructs the socket's implicit guarantee out of three
//! explicit ones. They are defence in depth: each closes a hole the others leave.
//!
//! - **Bind loopback only.** The caller binds `127.0.0.1`, never `0.0.0.0` —
//!   otherwise the LAN gets a vote. Not enforced here; see [`super::run`].
//! - **A per-run bearer token** ([`Guard::check_token`]). Minted at startup,
//!   never persisted, handed to exactly one browser through the opened URL. This
//!   is what stops the *other local process*, which can reach the port but cannot
//!   guess 32 random bytes.
//! - **A strict `Host`/`Origin` allowlist** ([`Guard::check_origin`]). This is
//!   the part that actually defeats rebinding, and it is worth being precise
//!   about *why* the token alone does not: after a successful rebind the browser
//!   believes `evil.com` *is* our origin, so it will attach our cookie to the
//!   attacker's request. The token stops being a secret the attacker lacks. What
//!   the attacker cannot forge is the `Host` header — the browser derives it from
//!   the URL the attacker had to use, so a rebound request arrives stamped
//!   `Host: evil.com` and we refuse it before the token is ever consulted.
//!
//! Both checks are pure functions over header values precisely so the policy is
//! unit-testable without binding a port — the same shape as
//! [`crate::control::check_control_protocol`] and [`crate::sync`]'s version gate.

/// The loopback origins we answer to, rendered for a given port.
///
/// A browser sends whichever spelling appears in the URL bar, so all three
/// spellings of "this machine" are legitimate; anything else is not us. Note
/// that this is an *allowlist*: the failure mode of a missing entry is a refused
/// request the user can see, whereas the failure mode of a permissive match is
/// silent and remote.
fn loopback_authorities(port: u16) -> [String; 3] {
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
}

/// Why a request was refused. Carries a human reason because these land in the
/// operator's terminal, and "403" alone has taught nobody anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No `Host` header at all — HTTP/1.1 requires one; a client without one is
    /// not a browser we serve.
    MissingHost,
    /// `Host` is not a loopback authority for our port. The rebinding signature.
    ForeignHost,
    /// `Origin` is present and is not us — a cross-origin caller.
    ForeignOrigin,
    /// No credential, or the wrong one.
    BadToken,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Refusal::MissingHost => "request has no Host header",
            Refusal::ForeignHost => {
                "Host is not this server's loopback authority (DNS-rebinding guard)"
            }
            Refusal::ForeignOrigin => "Origin is cross-site; lait serve is same-origin only",
            Refusal::BadToken => "missing or invalid token",
        }
    }
}

/// The per-run loopback credential and origin policy.
pub struct Guard {
    token: String,
    authorities: [String; 3],
}

impl Guard {
    pub fn new(token: String, port: u16) -> Self {
        Self {
            token,
            authorities: loopback_authorities(port),
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Enforce the rebinding guard: the request must be addressed to *us*, by a
    /// loopback name, and must not be initiated by another site.
    ///
    /// `Origin` absent is allowed on purpose. Browsers omit it on same-origin
    /// GETs (including the `EventSource` handshake in some engines), and a
    /// non-browser client like `curl` never sends one — but neither can a
    /// non-browser client be *tricked* into carrying our cookie, which is the
    /// only attack this pair exists to stop. When `Origin` *is* present it is
    /// authoritative and must be us: a cross-origin `fetch` always sends it, so
    /// its presence-and-mismatch is a positive signal, not an absence.
    ///
    /// `Host`, by contrast, is mandatory. It is the single field a rebinding
    /// attacker cannot launder, because the browser fills it in from the URL
    /// they were forced to navigate to.
    pub fn check_origin(&self, host: Option<&str>, origin: Option<&str>) -> Result<(), Refusal> {
        let Some(host) = host else {
            return Err(Refusal::MissingHost);
        };
        if !self.authorities.iter().any(|a| a == host) {
            return Err(Refusal::ForeignHost);
        }
        if let Some(origin) = origin {
            let ok = self
                .authorities
                .iter()
                .any(|a| origin == format!("http://{a}"));
            if !ok {
                return Err(Refusal::ForeignOrigin);
            }
        }
        Ok(())
    }

    /// Check a presented credential against this run's token.
    ///
    /// Compared in constant time. The window is admittedly narrow — an attacker
    /// who can time this can usually also read our stdout — but a token check
    /// that leaks its prefix through early return is the kind of thing that is
    /// free to do right and embarrassing to explain later.
    pub fn check_token(&self, presented: Option<&str>) -> Result<(), Refusal> {
        match presented {
            Some(t) if ct_eq(t.as_bytes(), self.token.as_bytes()) => Ok(()),
            _ => Err(Refusal::BadToken),
        }
    }
}

/// Constant-time byte equality. Length is not secret (the token is fixed-width),
/// so an early length return is fine; the *content* comparison is not allowed to
/// short-circuit.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract our cookie's value from a `Cookie` header.
///
/// Hand-rolled rather than pulling a cookie crate: we need exactly one name out
/// of a `; `-separated list, and the parse is four lines. Tolerates the whitespace
/// browsers actually emit and ignores every other cookie on the jar.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == name).then(|| v.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 7717;

    fn guard() -> Guard {
        Guard::new("s3cret-token".into(), PORT)
    }

    #[test]
    fn accepts_every_loopback_spelling_the_url_bar_can_produce() {
        let g = guard();
        for host in ["127.0.0.1:7717", "localhost:7717", "[::1]:7717"] {
            assert!(
                g.check_origin(Some(host), None).is_ok(),
                "{host} should be accepted"
            );
        }
    }

    #[test]
    fn rebound_host_is_refused_before_any_credential_is_considered() {
        // The DNS-rebinding signature: evil.com has re-resolved to 127.0.0.1, so
        // the packet genuinely arrives on our loopback socket and the browser
        // will happily attach our cookie — but it stamps the attacker's name in
        // Host, which is the one field they cannot launder.
        let g = guard();
        assert_eq!(
            g.check_origin(Some("evil.com"), None),
            Err(Refusal::ForeignHost)
        );
        // Right name, wrong port: a different local service, not us.
        assert_eq!(
            g.check_origin(Some("127.0.0.1:9999"), None),
            Err(Refusal::ForeignHost)
        );
        // A bare loopback host with no port is not our authority either.
        assert_eq!(
            g.check_origin(Some("127.0.0.1"), None),
            Err(Refusal::ForeignHost)
        );
    }

    #[test]
    fn missing_host_is_refused() {
        assert_eq!(guard().check_origin(None, None), Err(Refusal::MissingHost));
    }

    #[test]
    fn cross_origin_caller_is_refused_even_when_it_addresses_us_correctly() {
        // A page on evil.com fetching http://127.0.0.1:7717 directly: Host is
        // legitimately ours, so only Origin distinguishes it.
        let g = guard();
        assert_eq!(
            g.check_origin(Some("127.0.0.1:7717"), Some("http://evil.com")),
            Err(Refusal::ForeignOrigin)
        );
        // https on a loopback authority is still not our origin (we are http).
        assert_eq!(
            g.check_origin(Some("127.0.0.1:7717"), Some("https://127.0.0.1:7717")),
            Err(Refusal::ForeignOrigin)
        );
        // A same-origin Origin is fine.
        assert!(g
            .check_origin(Some("127.0.0.1:7717"), Some("http://127.0.0.1:7717"))
            .is_ok());
    }

    #[test]
    fn absent_origin_is_allowed_so_same_origin_gets_and_curl_still_work() {
        assert!(guard().check_origin(Some("localhost:7717"), None).is_ok());
    }

    #[test]
    fn token_must_match_exactly() {
        let g = guard();
        assert!(g.check_token(Some("s3cret-token")).is_ok());
        assert_eq!(g.check_token(Some("s3cret-toke")), Err(Refusal::BadToken));
        assert_eq!(g.check_token(Some("s3cret-tokeX")), Err(Refusal::BadToken));
        assert_eq!(g.check_token(Some("")), Err(Refusal::BadToken));
        assert_eq!(g.check_token(None), Err(Refusal::BadToken));
    }

    #[test]
    fn cookie_parses_out_of_a_realistic_jar() {
        assert_eq!(
            cookie_value("other=1; lait_token=abc123; third=x", "lait_token"),
            Some("abc123")
        );
        assert_eq!(
            cookie_value("lait_token=abc123", "lait_token"),
            Some("abc123")
        );
        assert_eq!(cookie_value("other=1", "lait_token"), None);
        assert_eq!(cookie_value("", "lait_token"), None);
        // A cookie whose *value* contains our name must not be mistaken for it.
        assert_eq!(cookie_value("x=lait_token=no", "lait_token"), None);
    }

    #[test]
    fn ct_eq_agrees_with_plain_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
