# SERVE — the local HTTP surface (`lait serve`)

Status: **vertical slice**. The two load-bearing parts (the loopback gate and the
N-daemon supervisor) are implemented and tested; the client is a placeholder shell
pending the React app. See [Next](#next).

## Why this exists

lait ships as the **pure engine**. The engine's contract is the Layer-B control
plane ([`src/control.rs`](../src/control.rs), SCHEMA §7): a versioned, hand-maintained
imperative façade over the CRDT, spoken as newline-delimited JSON over a Unix socket
or a Windows named pipe.

Every client to date — CLI, TUI, MCP — is a local Rust process, so that transport
cost them nothing. **A browser cannot speak a named pipe.** `lait serve` is the one
adapter that closes the gap: the same `Request`/`Response` types and the same
`Doorbell` stream, re-bound to a loopback TCP socket and SSE.

That is deliberately the *only* thing it adds. Once the control plane is reachable
over HTTP, every frontend becomes possible — the bundled one, a third party's, an
editor plugin — without the engine growing a UI.

## What the browser is (and is not)

The browser is **not a peer**. It holds no key, has no entry in the signed ACL, and
is never invited. It is a lens on a device's replica; the *device* remains the only
network identity. This is why the network model needs no "viewer" role: the browser
is not on the network.

It sits in the same tier as the CLI, the TUI, and the MCP server — a **local client
of the control plane**. That tier already existed; it simply had no member that
wasn't a Rust process.

Consequently the browser renders **your local stores**. It is not a second replica,
it does not sync, and closing the tab loses nothing.

## Two things make this different from every other client

### 1. It is a supervisor, not a client

The control channel is keyed by home (`control::control_name`), so there is **one
daemon per space**. A CLI invocation resolves one store and talks to one daemon. The
browser is a picker over *all* of them, so it holds N — the first thing in the
codebase to do so.

- **Listing never spawns.** `GET /api/spaces` probes each registered store with a
  short-timeout `Status` (mirroring `cli::workspace_status`, so the browser and
  `lait spaces` cannot disagree about what `up` means) and fails closed to `idle`.
  Opening the browser must not wake every daemon you have ever registered.
- **Selecting is what attaches.** `Supervisor::attach` is the only place a daemon is
  started, and it is idempotent.
- **One SSE, N doorbells.** Each attached space's `Subscribe` stream is pumped into
  one broadcast channel, tagged with the space id, and served as a single
  `EventSource`. Frames stay dirty *flags* — the client re-reads the authoritative
  projection per dirty scope, exactly as the TUI does (UI.md §4.2). A lagging
  receiver surfaces as `lagged`, whose contract is the same rebaseline as `reset`.

### 2. The socket was the authentication

`control.rs` has never carried authentication, correctly: a Unix socket is gated by
filesystem permissions and a named pipe by its DACL, so *being able to open the
channel is the credential*.

An HTTP port inherits none of that, and introduces a caller that never existed
before: **the web pages the user visits**. A page cannot read a cross-origin
response, but it can send the request — and DNS rebinding exists specifically to
make the browser believe a hostile origin *is* us.

So [`src/serve/auth.rs`](../src/serve/auth.rs) rebuilds in userspace what the socket
got free, in three layers:

| Layer | Stops | Note |
|---|---|---|
| **Bind `127.0.0.1` only** | the LAN | never `0.0.0.0` |
| **Per-run bearer token** | another local process | 32 random bytes, never persisted, minted per run |
| **Strict `Host`/`Origin` allowlist** | DNS rebinding | the load-bearing one |

The third deserves its rationale spelled out, because the token looks like it should
be sufficient and is not: **after a successful rebind the browser thinks the attacker
is us, so it attaches our cookie.** The token stops being a secret they lack. What
they cannot forge is `Host` — the browser derives it from the URL they were forced to
use — so a rebound request arrives stamped `Host: evil.com` and is refused *before*
the token is consulted. Order matters, and is asserted by test.

The token reaches the browser through the opened URL exactly once and is immediately
traded for an `HttpOnly; SameSite=Strict` cookie, then redirected away: out of the URL
bar, out of history, out of any `Referer`, and out of reach of script in our own page.

Both checks are pure functions over header values so the policy is unit-testable
without binding a port — the same shape as `control::check_control_protocol`.

## Identity scoping — the seam

Identity in lait is **global by default**. `config::identity_dir` puts `secret.key`
under the config root and one key spans every repo-bound store, "like one `git`
`user.email` across many repos". So N ordinary spaces are N daemons signing with the
*same* identity, and listing them side by side crosses nothing.

The exception is a **self-contained home**: `$LAIT_HOME` collapses identity and store
into one directory. Named agents are exactly that shape, living under
`registry::agents_base`, and `registry.rs` isolates them deliberately — "separate
homes mean separate `secret.key`s… one agent can't read another" — under a
never-guess invariant, because a wrong auto-attach is a cross-identity leak.

`workspaces.json` is a single global file that every daemon open upserts into, so it
holds **both kinds**. `spaces::scope` decides who sees what, and the policy is
deliberately **asymmetric**:

- a **global** identity (you) sees its own stores **and every agent's**, each tagged
  `SpaceIdentity::Agent { name }`. Agents are yours; watching them is a reason to have
  a browser at all, and the registry it reads carries no secrets — it is navigation
  state.
- a **self-contained** identity sees exactly its own home. An agent must not enumerate
  your spaces or its siblings. **Observability runs downward only.**

The tag is load-bearing, not decorative. Seeing an agent's space is safe; *acting as*
it is a different grant, and the tag is what lets the layers above tell those apart.

### Identity does not follow the store

The trap, and the reason `cli::ensure_daemon_as` exists: **`identity_dir` reads
`$LAIT_HOME` and nothing else — never `$LAIT_STORE`.** So spawning a daemon at an
agent's store while `LAIT_HOME` is unset opens that store under the *global* key,
silently ignoring the `secret.key` sitting inside it. Verified: the same store yields
identity `53a4…` via `--home` and `1363…` (the human's) via `LAIT_STORE` alone.

That is not a cosmetic mismatch. The workspace key is sealed to the agent's X25519
key, so such a daemon cannot unwrap it — and it would announce **your** identity as a
peer in the agent's workspace.

One process resolving one store never notices, because its own env already says which
identity it is. `lait serve` holds N homes across *two* identity kinds and cannot
express that through a process-global env var, so the choice becomes an argument:
`Supervisor::attach` pins `LAIT_HOME` for `Agent` spaces and inherits for `Own`.

### Listing is free; attaching is not

`list` only probes, so enumerating agents has **no effect on anything**. Starting a
daemon brings that identity *online* — it binds an endpoint and announces presence —
so watching an idle agent is what makes it visible to its workspace. Usually what you
want when you went looking for it, but it is a real consequence of a click, not a
read. The shell therefore auto-selects only your own single space, never an agent.

`scope` is the only place scoping is decided, and `Supervisor::resolve` routes through
it — so a space this identity may not see is indistinguishable from one that does not
exist. **An identity switcher changes only the caller**: it picks a different
`(identity, self_contained)` pair. Nothing threads through the router, the supervisor,
or the endpoints — `--home` already exercises this today.

## Surface

`lait serve [--port N] [--open]` — default port **7717**, loopback only.

| Endpoint | Returns |
|---|---|
| `GET /` | the shell (and the one-time `?token=` → cookie handoff) |
| `GET /api/spaces` | `{ spaces: [...] }`, scoped to this identity, probed, newest-first. Each row carries `identity: {kind:"own"}` or `{kind:"agent",name}` |
| `GET /api/spaces/{id}/board?project=` | `Response::Board` — attaches the space |
| `GET /api/events` | SSE `doorbell` / `lagged`, multiplexed over attached spaces |

Errors use the same `{"kind":"error","message":…}` envelope `--json` emits, so browser
and CLI clients read one contract.

## Next

- **Replace the shell with the React app**, embedded in the binary so `lait serve`
  stays one self-contained artifact and the SPA stays same-origin — which is what
  makes the `Origin` allowlist enforceable in the first place.
- **The rest of the surface**: issues/inbox/members/invite over the endpoints that
  already exist on the control plane.
- **Notifications** belong to the *daemon*, not the tab. `http://localhost` is a
  secure context so the Notification API works, but a tab only fires while it is
  open; the always-on component is the daemon. The browser should badge; the daemon
  should raise the OS toast.
- **`lait serve` currently reads.** Every mutating verb the control plane exposes is
  reachable the same way, but writes should land with `confirm_destructive`'s intent
  preserved — the CLI gates `delete`/`members remove`/`key rotate` behind a prompt,
  and the browser needs an equivalent, not a bypass.
- **Writes into an agent's space need a decision before they are possible.** Reads
  through an agent's daemon are observability. A *write* through it would be signed by
  the agent and land under the agent's name — the human operating a machine as one of
  its agents. `SpaceIdentity::Agent` is the hook: the write path must either refuse it,
  or make the attribution explicit and deliberate. It must not simply inherit the read
  path's permissiveness.
