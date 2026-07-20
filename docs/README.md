# lait documentation

lait is a local-first, peer-to-peer issue tracker. One binary provides a CLI,
a local web application, and MCP tools for agents; every surface talks to the
same per-space daemon and receives the same versioned projections.

Start with the product, then go deeper only when you need to understand a
contract or operate a deployment.

## Use lait

| Need | Read |
|---|---|
| Install lait | [`INSTALL.md`](./INSTALL.md) |
| Learn the commands and client behavior | [`UI.md`](./UI.md) |
| Run the local web application | [`UI.md`](./UI.md#3-web) |
| Diagnose joining and onboarding | [`UI.md`](./UI.md#7-joining) |

The normal product model is deliberately small:

- `lait init` creates a space; `lait join` creates a local replica from an
  invite. Other commands never create stores implicitly.
- `lait <verb>` is the scriptable and interactive CLI. `--json` returns the
  same versioned DTOs used by other clients.
- `lait serve` supervises local space daemons and exposes the product over a
  loopback-only HTTP/SSE surface.
- `lait mcp` exposes the same command contract to agents.
- The daemon is the only owner of live Loro documents. Clients submit intents
  and re-read projections after dirty notifications.

An identity is an actor, not a device. An `ActorId` remains stable while its
device keys are added, revoked, or recovered. Names are local petnames and do
not carry authority.

## Understand lait

| Document | Authority |
|---|---|
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | Current implementation boundaries, trust model, and security posture. |
| [`DATA-CONTRACT.md`](./DATA-CONTRACT.md) | Storage, convergence, authority, and projection invariants. |
| [`PROTOCOL.md`](./PROTOCOL.md) | Network and local-control compatibility contract. |
| [`THREAT-MODEL.md`](./THREAT-MODEL.md) | Assets, adversaries, security claims, and explicit non-goals. |

These documents describe the current branch. Historical phase plans and
superseded alternatives are not normative. Exact Rust APIs live in rustdoc and
the source; these documents describe behavior and invariants rather than
duplicating every type definition.

Source comments state invariants locally and link canonical documents by filename
and topic when more context is necessary. They do not rely on movable section
numbers or historical review labels.

## Operate and release

| Document | Covers |
|---|---|
| [`INSTALL.md`](./INSTALL.md) | Supported installation channels, completions, and verification. |
| [`RELEASES.md`](./RELEASES.md) | Release provenance, current signing status, and consumer verification. |

Per-release changes belong in [`CHANGELOG.md`](../CHANGELOG.md), not in the
current architecture. Vulnerabilities should be reported privately through the
repository's security-reporting channel rather than a public issue.
