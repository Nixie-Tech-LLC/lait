# SERVE — the local HTTP surface (`lait serve`)

Status: **API complete, client pending**. The loopback gate, the N-daemon supervisor,
and the full CRUD surface are implemented and tested end to end; the served client is a
placeholder shell pending the React app. See [Next](#next).

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
| `POST /api/spaces/{id}/rpc[?confirm=true]` | the control plane, verbatim: body is a `Request`, reply is a `Response`. Attaches the space |
| `GET /api/events` | SSE `doorbell` / `lagged`, multiplexed over attached spaces |

Errors use the same `{"kind":"error","message":…}` envelope `--json` emits, so browser
and CLI clients read one contract.

### Why one RPC endpoint and not a REST surface

A REST surface would be a second, hand-maintained projection of a façade that is
*already* the stable, versioned, hand-maintained projection (S§7). Two of those drift —
and the `feat/lait-viewer` branch is the proof: its REST router still calls
`projects new --key`, a shape that stopped existing. The RPC endpoint cannot drift,
because it carries the same enum the CLI, TUI, and MCP send. The browser is a Layer-B
client; this is what that sentence means in practice.

The surface is therefore **full CRUD** from day one: every verb the control plane
exposes is reachable, because there is no per-verb handler to write.

### The three gates

1. **`Subscribe` is refused** (400). It is a stream, not a one-shot — `control::request`
   writes and reads exactly one line, so a subscribe here would decode a `Doorbell` as a
   `Response`. `GET /api/events` is the door.
2. **An agent's space is observable, not operable** (403 on writes). Reads through an
   agent's daemon are the observability it was scoped in for; a write would be signed by
   the agent and land under its name. If you are a member of that workspace, write
   through your own space and sign as yourself. `policy::is_read` is an allowlist with an
   exhaustive match, so a verb added later fails to *compile* until classified rather
   than defaulting to permitted — and `Inbox` proves why it can't be a per-variant list:
   `clear: true` advances the read watermark, a write wearing a read's name.
3. **Destructive verbs keep the CLI's question** (409 `confirm_required`).
   `confirm_destructive` is a TTY affordance — it refuses under `--json` because a pipe
   cannot be asked. A browser can: it has a modal. So rather than bypass the gate or
   inherit the pipe's refusal, the question comes back and the UI asks it. The string is
   `cli::destructive_question`'s own, so the two surfaces cannot disagree about what is
   dangerous. This protects against an *accident*, not an attacker — anything that can
   POST `delete` can POST `?confirm=true`, which is exactly the guarantee the CLI's
   prompt gives.

### Credential precedence

`bearer` → **query** → cookie, and the middle one is load-bearing. The token is per-run;
the cookie outlives the run that set it. Cookie-first would let a stale credential shadow
the fresh token in a freshly-printed URL and 401 the user out of a link they legitimately
clicked — permanently, since the page cannot clear an `HttpOnly` cookie it cannot read.
The cookie is also named per-port (`lait_token_<port>`), because **cookies ignore the
port**: a fixed name would have two concurrent `lait serve` runs clobbering each other's
jar entry.

## Next

- **Replace the shell with the React app**, embedded in the binary so `lait serve`
  stays one self-contained artifact and the SPA stays same-origin — which is what
  makes the `Origin` allowlist enforceable in the first place.
- **Notifications** belong to the *daemon*, not the tab. `http://localhost` is a
  secure context so the Notification API works, but a tab only fires while it is
  open; the always-on component is the daemon. The browser should badge; the daemon
  should raise the OS toast.
- **The confirm gate is client-enforced by design.** Worth re-reading before anyone
  "hardens" it: a server-side `confirm` flag cannot distinguish a human clicking a modal
  from a script setting the flag. It buys accident-resistance, which is all the CLI's
  prompt buys either. Adding ceremony there would be theatre; the real boundaries are
  the loopback bind, the token, and the `Host`/`Origin` allowlist.
- **`lait config` and the spaces registry are not on the control plane** — they are
  local state the CLI reads directly (`Special` commands, not `Request`s), so the RPC
  endpoint cannot reach them. A browser settings surface needs supervisor-level
  endpoints beside `/api/spaces`, not a new `Request` variant.
