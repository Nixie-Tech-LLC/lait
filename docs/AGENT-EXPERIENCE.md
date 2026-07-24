# Agent Experience — status and design

lait treats an agent as a **member whose identity is sponsored** — not a separate
actor class. There are no `agent-*` verbs: grants, roles, removal, attribution,
and space selection are the *same* member machinery for humans and agents. This
document records what has shipped and the design for the two remaining
optimizations. The full design docket is `docs/plans/09` (untracked).

## Shipped

### The linchpin — a sponsored member holds content authority

A sponsored member (an agent) is no longer grant-less/view-only. It holds the
**existing `Grant::Write`** through the same grant machinery any member uses —
minted at sponsor time (`AclAction::AddAgent { actor, grants }`, default
`Write`). The invariants are preserved by construction and by test
(`crates/mechanics/src/acl.rs`):

- **Dies with the sponsor.** The actor stays in the `agents` map; the sponsor
  cascade (remove-wins + nonce-race) evicts it when its sponsor leaves.
- **No membership authority.** `AddAgent` refuses `Grant::Admin` at replay
  (`is_sponsorable_grant_set`), and the blanket agent-author ban in `judge_op`
  stands — a sponsored member can file/close/comment but cannot add/remove
  members or rotate the key.
- **The E2EE recency fence is untouched.** A grant-less agent *already* held
  every sealed epoch key (read access via `seal_records_for_actor`); the linchpin
  adds *write* standing, not read access, so removal/rotation semantics are
  unchanged.

Because standing is grant-only (`can_write` is agent-blind), the content-authoring
gate (`signer_can_write` → `can_write`) authorizes a sponsored writer with no
special case.

### Identity surface — one surface

- **`did:key` for any member.** `crypto::did_key_from_pubkey` renders any device
  key as a spec-compliant `did:key:z6Mk…` (ed25519 multicodec + base58btc
  multibase) — a pure, offline, self-certifying, *synced-safe* handle. Exposed on
  every `MemberDto` and in `whoami`.
- **The roster renders sponsorship, does not gate on it.** `members()` is one row
  per member; a sponsored member reads as `member`/`viewer` (its grants) with a
  `sponsor` link — the viewer draws a "sponsored · <sponsor>" badge (`Bot` icon).
- **MCP onboarding says "attach, don't rebuild."** `get_info` tells an agent it
  has an identity and to call `whoami`/`sync`, not to treat onboarding as
  invite→connect (the peer-join flow for a *new node*).
- **Structured, actionable errors.** A denied write returns a typed
  `ErrorKind::Denied` with the next step ("ask your sponsor / an admin to grant
  write access"), mapped to an MCP `invalid_request`, not an opaque
  `internal_error(blob)`.

### Observability — no more inference

- **`whoami`** — actor, `did:key`, device, space, role, capabilities, sponsor,
  name, and the loud partial-view signal, in one shot.
- **`sync`** — converges the keyring and reports completeness loudly, naming any
  missing epoch key instead of silently showing fewer issues (the 141-vs-154
  bug).
- **Hard partial-view guard.** A *delegated* identity (a sponsored agent) is
  refused authoring against a known-partial view — it could "close what's done"
  on issues it cannot see. A human acting for themselves gets the loud signal and
  judges; an agent is stopped by construction (`route_issue`).

### Operator friction removed

- **Build isolation.** Agent/test/worktree builds use a separate
  `CARGO_TARGET_DIR`, so they never lock a running node's `lait.exe`.
- **Clean-env test entrypoint.** A `#[ctor]` scrubs ambient `LAIT_HOME`/
  `LAIT_STORE`/`LAIT_CONFIG_ROOT` at unit-test *and* subprocess-spawning
  integration-test load, so a developer's shell `$LAIT_HOME` (pointing at their
  live node) can never poison a run — it previously collided a spawned test
  daemon with the live node's lock.
- **`resume`/`profiles`** are the named-handle selection mechanism; a named
  identity's secret lives under `config_root()` (the platform config dir),
  *outside* a working-directory sandbox — the answer to deterministic-seed
  reconstruction for the common "reset my working dir" case.

## The reframe — attribution already works via the node model

Per-agent *attribution* does not require the multi-tenant daemon. In lait every
identity is a full node: an agent with its **own home** (its own `secret.key`) is
a node like any other; with the linchpin it can **write**, and its writes are
signed by its own seed and therefore **attributed to it**, converging with the
human's node over the existing Contact/sync plane. The seamless bar's remaining
gaps are *storage footprint* (N homes = N copies of the immutable object store)
and *lifecycle* (managing N homes / the sponsor-inception step). Those are what
Architectures A and B optimize — they are not prerequisites for a correct,
attributed sponsored writer.

The one operational seam that remains manual: `members agent <key>` needs the
agent's self-inception to have reached the sponsor once (a Contact round). B's
shared store makes that trivial; today the error names the step.

## Remaining optimizations (designed, not yet shipped — deliberately)

These change the on-disk object format and the signed-write path. They are
**intentionally not shipped half-tested**: a naive shared pool corrupts (the
docket's load-bearing warning), and the user's live space must not be endangered.
The seams below are verified against the code.

### Storage — shared immutable object pool + cross-frontier GC

`orbital/ws_<id>/objects/<hex64>` is immutable, content-addressed (blake3), and
idempotent-on-write (`journal/src/lib.rs` `commit`, the `if !final_path.exists()`
rename). Two members writing the same object converge for free.

- **Seam:** route `object_path` (`journal/src/lib.rs:305`), the commit rename
  loop, and `read_object` through a shared pool root (`orbital/_pool/objects/`),
  linked per member via ReFS block-clone / hardlink / alternates. Two `objects/`
  dirs exist per space (Body + `authority/`); both share the pool since
  `OBJECT_DOMAIN` is common.
- **Load-bearing GC:** the current sweep (`journal/src/lib.rs:462` `recover`) is a
  single-manifest mark-and-sweep — it must **not** run against a shared pool. A
  cross-frontier GC marks the union of every member's Body + authority manifest
  `objects` plus any active journal's `new_objects`, under a new pool-level lock,
  before sweeping. An object is collectable iff no member's frontier names it.

### Runtime — multi-tenant daemon (Architecture B)

One store, one lock, one always-on daemon; members (human + sponsored agents) are
clients. `Session::submit` requires `action.header.actor == docked principal`
(`runtime/src/session.rs`), so B docks a Session per local identity and routes a
request to the right identity's Session, **or** feeds agent-signed actions through
the Contact incorporation path (`contact_driver.rs` `validate_contact` →
`incorporate_bundle`), which already ingests foreign-signed transactions and
preserves their author. The local-submit path must apply the *same* standing
validation the Contact plane applies to peers — no shortcut because it arrived
over the local socket.

### Deterministic seed across a *fully* reset sandbox

`resume` persists a named identity's seed under `config_root()`, outside a
working-directory sandbox. For a sandbox that wipes the config dir too,
deterministic reconstruction needs the seed derived from a stable name **plus a
machine/user secret that lives outside the sandbox** (an OS keyring or an
operator-provided env secret) — an operator policy, specified here, not a
built-in keyring integration.
