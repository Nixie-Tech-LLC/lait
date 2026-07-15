# lait docs

Design and operator documentation for **lait**, a local-first, peer-to-peer issue
tracker (Loro CRDTs · git-backed store · iroh P2P). The top-level
[`README.md`](../README.md) deliberately stays plain-language and scenario-driven;
this index is where the technical depth starts. Per-version detail:
[`CHANGELOG.md`](../CHANGELOG.md).

**Current state:** P0–P3 complete and verified multi-node; P4 (release
engineering) shipped, with security review and receipt/tier hardening the main deferrals.

## The system in one screen

One binary, four surfaces, one persistent node per space:

- `lait daemon` — the long-lived node: owns the Loro documents (a per-space
  catalog + one doc per issue) over a git-backed durable store, plus the iroh
  endpoint, a signed-gossip topic for announce/presence, and a local control
  channel. Auto-spawned on first use; only `lait init`/`lait join` create stores.
- `lait <cmd>` — the CLI: flat verbs on issues, plural nouns on registries;
  `--json` emits the stable, versioned DTO (S§7.3).
- `lait tui` — a full-screen board client living off the doorbell stream (U§4).
- `lait mcp` — the same commands as MCP tools for agents, same DTOs.

Issues carry a collision-free short `iss_` handle plus a friendly `KEY-n` alias;
refs resolve daemon-side, and ambiguity returns candidates, not errors. State
lives in a per-repo `.lait/` (or self-contained `$LAIT_HOME`): local
`config.json` + a `repo/` git store; one global `secret.key` identity spans
every store. Only public keys and Loro snapshots touch disk — never secrets.

How the network maps onto iroh:

| Piece | Mechanism |
|---|---|
| Identity / handle | a persistent `EndpointId` (ed25519 public key) |
| The space | an `iroh-gossip` topic (derived from the workspace id) |
| Announce + presence | signed gossip heartbeats + neighbor events + a `Bye` on shutdown |
| Liveness probe | a direct QUIC handshake on a custom ALPN |
| Sync | catalog-first VV-diff, per-doc frames on a custom ALPN (A§8) |
| Signed messages | ed25519 `SignedMessage` sign/verify (+ the signed membership op-graph, S§6) |

Cross-platform is CI-enforced on Linux/macOS/Windows: the control channel is a
Unix socket / named pipe (`interprocess`), the single-instance guard a portable
advisory lock (`fs2`), TLS the `ring` rustls backend (`aws-lc-rs` is banned), and
a per-OS smoke drives the real tracker flow on every change (A§15).

## The three design legs

The architecture is documented as three complementary docs that cross-reference each
other by a short section notation — `A§5` means ARCHITECTURE §5, `S§7` SCHEMA §7, `U§4`
UI §4. They are the design of record, kept in sync with the shipped code.

| Doc | Notation | Covers |
|---|---|---|
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | `A§` | The system: layered design, the git/iroh/Loro split, sync protocol, seed role, E2EE model, decision log. |
| [`SCHEMA.md`](./SCHEMA.md) | `S§` | The data shapes across the three layers (CRDT storage / control protocol / wire) and **what authority each field carries**. |
| [`UI.md`](./UI.md) | `U§` | The three drive surfaces — CLI, TUI, MCP — and the one imperative façade they share over the CRDT. |

## Focused designs

| Doc | Status | Covers |
|---|---|---|
| [`GUIDED-JOIN.md`](./GUIDED-JOIN.md) | shipped (v0.4.7) | The first-invite verifier (`lait doctor`) and the directory-trap fix. |
| [`HARDENING.md`](./HARDENING.md) | proposed (deferred) | Agent-messaging delivery/ack receipts and urgency tiers ("notify anyway"). Not yet built. |

## Operator docs

| Doc | Covers |
|---|---|
| [`INSTALL.md`](./INSTALL.md) | Every install channel (shell/PowerShell installers, Homebrew, Scoop, winget, Cargo, Docker seed), download verification, completions, and the man page. |
| [`ROADMAP.md`](./ROADMAP.md) | The P0→P4 execution plan, the Definition of Done, the CI gate, and per-phase status. |

## Reading order

New to the project: top-level [`README.md`](../README.md) → [`ARCHITECTURE.md`](./ARCHITECTURE.md)
→ [`SCHEMA.md`](./SCHEMA.md) → [`UI.md`](./UI.md). Installing or operating a node:
[`INSTALL.md`](./INSTALL.md). Tracking what's done: [`ROADMAP.md`](./ROADMAP.md) and
[`CHANGELOG.md`](../CHANGELOG.md).
