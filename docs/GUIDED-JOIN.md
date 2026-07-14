# Guided join — the first-invite verifier

> **Status:** shipped in v0.4.7. Both halves below — the `lait doctor` verifier and
> the directory fix — are implemented and covered by `tests/guided_join.rs`. Companion
> to [`ARCHITECTURE.md`](./ARCHITECTURE.md) (A§), [`SCHEMA.md`](./SCHEMA.md) (S§), and
> [`UI.md`](./UI.md) (U§).

## Problem

"Accept the invite and get to work" is the pitch; the reality is a chain of ~10
independent gates, each of which fails **silently** into the same symptom — an
empty or wrong board with a healthy-looking `lait status` on both machines. On a
first invite all the gates are cold at once (no warm daemon, no prior peer dial,
no seed, no directory convention), which is why it is *never* one step. A
returning user already satisfies ~7 of the 10, which is why the problem is
invisible to the people who built it.

The two gates that bite hardest in practice:

1. **The directory trap.** A store is bound per-directory, git-style
   (`config::resolve_home`, case 4). If no `.lait/` is found walking up from the
   cwd, one is **silently created** there. So a joiner who runs `lait join` in
   one folder and `lait projects` / `lait tui` in another lands in a *different*,
   empty workspace — with no error. Global identity makes the decoy store look
   like "theirs," so it never reads as wrong.
2. **The convergence fog.** Even when everything is correct, the encrypted board
   backfills *after* membership/presence sync, so an empty board reads as
   "broken" rather than "still syncing / waiting for the inviter."

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

### B. The directory fix

- **Workspace registry** (`workspaces.json` under `config_root`): the daemon
  upserts `{ workspace, room, path, host_nick, last_seen }` on a successful
  `Join`, so the CLI can always answer "which directory holds the workspace you
  joined?" `lait workspaces` lists them.
- **No silent decoy.** Read commands (`projects`, `list`, `board`, `tui`,
  `activity`, `members`) refuse to auto-create a `.lait/` when none is
  discoverable *and* the registry is non-empty — instead they point at the
  registered workspace(s) and exit non-zero. `init`/`join` still create.

### C. The room trap (post-v0.4.8 hardening)

Two more gates from the same silent-failure family, found by driving the flow:

- **Join adopts the ticket's room.** A joiner's profile kept its *seeded* room
  (`"default"`/repo-dir) while the workspace lives in the ticket's room. Warm,
  everything worked (`join_topic` swaps the live topic); on the **next cold
  boot** the daemon subscribed to the wrong gossip topic — no peers, no
  presence, a `doctor` waiting on `peer` forever, and any invite the joiner
  minted carried the wrong room onward. `Join` now adopts the ticket's room
  live (`status`/`doctor`/`invite` all see it) **and** persists it to
  `profile.json`; on boot the daemon self-heals a stale profile room from the
  workspace registry (which witnessed the join). Pinned by
  `tests/guided_join.rs::join_adopts_the_tickets_room`.
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
3. `Join` writes a workspace-registry entry pointing at the joiner's store.
4. `Diagnose { expected_workspace }` with a mismatched workspace fails the
   `workspace` gate (the directory trap, made legible).
5. CLI guard: a read command in a fresh directory with a non-empty registry
   errors with a pointer and creates **no** decoy `.lait/`.
6. The `doctor` tool stays wired on the agent surface — a dedicated
   `mcp_parity` test pins `doctor` (and the other onboarding/transport tools)
   into `MCP_TOOL_NAMES`, so dropping it fails the build.
