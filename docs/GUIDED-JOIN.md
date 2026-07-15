# Guided join — the first-invite verifier

> **Status:** verifier shipped in v0.4.7; the workspace re-architecture (see the
> decision log, A§15) then **removed the directory and room traps at the root**
> rather than guarding them — §B/§C below are kept as the historical record of
> what the guards were compensating for. Covered by `tests/guided_join.rs`.
> Companion to [`ARCHITECTURE.md`](./ARCHITECTURE.md) (A§), [`SCHEMA.md`](./SCHEMA.md)
> (S§), and [`UI.md`](./UI.md) (U§).

## Problem

"Accept the invite and get to work" is the pitch; the reality was a chain of ~10
independent gates, each of which failed **silently** into the same symptom — an
empty or wrong board with a healthy-looking `lait status` on both machines. On a
first invite all the gates are cold at once (no warm daemon, no prior peer dial,
no seed, no directory convention), which is why it was *never* one step. A
returning user already satisfies ~7 of the 10, which is why the problem was
invisible to the people who built it.

The two gates that bit hardest in practice:

1. **The directory trap (removed by design).** A store used to be bound
   per-directory with **silent auto-create**: if no `.lait/` was found walking up
   from the cwd, one was minted there — a full workspace (genesis, catalog, a
   sealed key) as a side effect of any command. A joiner who ran `lait join` in
   one folder and `lait projects` in another landed in a *different*, empty
   workspace with no error; global identity made the decoy look like "theirs."
   Today **nothing creates a store implicitly**: workspaces are born only in
   `lait init` (founding) and `lait join` (bootstrap from the ticket), and every
   other command in a store-less directory errors with guidance (`init` / `join`
   / `-w` / `lait workspaces`). The trap is gone by construction, not by guard.
2. **The convergence fog.** Even when everything is correct, the encrypted board
   backfills *after* membership/presence sync, so an empty board reads as
   "broken" rather than "still syncing / waiting for the inviter." This is what
   the verifier (§A) exists for, and it remains fully live.

## Scope of this change

Two coordinated fixes, validated across all three client surfaces (CLI, MCP, TUI):

### A. The guided-join verifier (`lait doctor`)

A single request — `Request::Diagnose { expected_workspace }` — computes an
ordered list of **gates** from live daemon state and returns a `DiagnosisView`.
The first non-passing gate is the actionable blocker, so a stalled joiner gets
*one legible line* instead of a blank board. It surfaces as:

- **CLI:** `lait doctor`, and an automatic tail of `lait join` (the join passes
  the ticket's workspace as `expected_workspace`, so a directory/store mismatch
  is caught the instant it happens). The tail **polls** rather than snapshotting:
  right after `join` returns, admission (Pattern A's auto-seal) and the gossip
  handshake are still in flight, so a t=0 readout says "waiting on a peer"
  moments before everything passes — the verifier itself becoming an unreliable
  reporter. The tail re-diagnoses (500 ms, ≤15 s) until the gates settle: all
  pass, a `workspace` Fail (time won't clear it), or — on a pass-less ticket —
  a pending `membership` (a human has to act; don't stall the readout).
- **MCP:** a `doctor` tool (enforced by the `tests/mcp_parity.rs` gate).
- **TUI:** a keybound diagnosis panel.

The five daemon-side gates (ordered):

| id | Pass | Wait | Fail |
|----|------|------|------|
| `workspace` | store bound; `expected` matches (or none given) | — | `expected` ≠ bound workspace (wrong directory/store) |
| `daemon`    | responding | — | (unreachable is surfaced by the client, exit 3) |
| `membership`| `admin`/`member` | `pending` — waiting for an admin to approve | — |
| `peer`      | ≥1 peer online | no peer online yet — board syncs when the inviter is online | — |
| `synced`    | member **and** catalog present (≥1 project/issue) | member but nothing synced yet — syncing… | — (Skip while `pending`: board stays encrypted) |

`blocked_on` = the id of the first `Wait`/`Fail` gate (`None` when all pass).

### B. The directory trap — from guarded to removed

The v0.4.7 mitigation was a **workspace registry** (`workspaces.json` under
`config_root`, written only on `Join`) plus a read-only-command guard that
refused to auto-create a decoy store when the registry was non-empty. The
re-architecture replaced both halves with structure:

- **No implicit creation, anywhere.** `config::resolve_existing_store` never
  creates; only `lait init` / `lait join` do (`store_dir_for_init`). Every
  store-needing command in a bare directory gets one universal error naming the
  fixes — the guard flag, the exit-2-for-reads special case, and the
  "non-empty registry" precondition are all deleted.
- **The registry is complete.** `{ workspace, name, path, origin:
  founded|joined, host_nick, last_opened, projects }` is upserted by `init`,
  by `join`, and by **every daemon open** — founders finally register, names and
  advisory project keys refresh on use. It powers `lait workspaces` (with live
  missing/up/idle status, plus `forget`/`prune`) and the global `-w <SEL>`
  selector (name / `ws_` prefix / path → store path via the `LAIT_STORE` pin).
  It remains pure navigation state: no secrets, no trust, stale-tolerant.

### C. The room trap — removed with the room itself

The trap: a joiner's profile kept its *seeded* room (`"default"`/repo-dir) while
the workspace lived in the ticket's room, so the **next cold boot** subscribed
to the wrong gossip topic — no peers, no presence, a `doctor` waiting on `peer`
forever, and any invite the joiner minted carried the wrong room onward. Two
heal layers (adopt-on-join + a boot-time registry heal) papered over it.

The re-architecture deleted the root cause: **the gossip topic is a pure
function of the `WorkspaceId`** (`topic_for_workspace`), there is no
user-settable network name, and the human-facing name is a synced, cosmetic
catalog register (S§4.1). A cold boot cannot subscribe to the wrong topic; both
heal layers and `profile.json` itself are gone. Joining is now **client-side
store bootstrap** (`tracker::join_workspace_store` from the ticket, before the
daemon spawns) — a daemon only ever opens a store already bound to the right
workspace, and a `join` into a directory bound to a *different* workspace is a
hard exit-2 error instead of the old silent adopt-or-split-brain heuristic.

Still live from the same hardening pass:

- **`stop` means stopped.** The shutdown `Notify` has multiple waiters (the
  accept loop *and* every Subscribe stream); `notify_one` could hand its single
  permit to a subscriber, leaving a daemon that answered "shutting down" running
  forever — its pipe instance accepting connects nobody serves, hanging every
  later client. Shutdown now signals all waiters, bounds the courtesy teardown
  (Bye, router close) with a deadline, and hard-exits. Pinned by
  `tests/guided_join.rs::stop_kills_the_daemon_even_with_a_live_subscriber`.

## Completion criteria (local validation)

The issue is considered resolved when these are green locally and confirmed by
sub-reviewers on every channel:

1. Pure `diagnose()` unit tests: pending→blocked-on-membership, member→all-pass,
   workspace-mismatch→blocked-on-workspace, solo-founder→blocked-on-peer,
   member-not-yet-synced→blocked-on-synced.
2. Two-node integration: a pending joiner's `Diagnose` blocks on `membership`;
   after approval + convergence it flips to all-pass.
3. A joiner's store carries a workspace-registry entry (written by `join` and
   refreshed on every daemon open); founders register too.
4. `Diagnose { expected_workspace }` with a mismatched workspace fails the
   `workspace` gate (wrong directory/store, made legible).
5. No implicit store creation: **any** store-needing command in a bare
   directory errors with guidance and creates **no** `.lait/` — with or without
   registry entries to point at.
6. The `doctor` tool stays wired on the agent surface — a dedicated
   `mcp_parity` test pins `doctor` (and the other onboarding/transport tools)
   into `MCP_TOOL_NAMES`, so dropping it fails the build.
