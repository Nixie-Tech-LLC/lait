# Product surfaces

lait has three product surfaces: CLI, local web, and MCP. They are clients of
the same daemon and use the same command and projection contract. No surface
opens Replica or Fabric independently; product work reaches a World through a
docked Session.

## 1. Product model

A space is a local replica of a shared issue tracker. Run `lait init` to found one
or `lait join` to create a replica from an invite. Other commands require an
existing space and never create one as a side effect.

Within a space:

- issues have stable `iss_` identifiers and friendly project aliases;
- projects, labels, workflow states, and board order are shared;
- assignments and authors refer to stable actors rather than devices;
- petnames are local and never replace an actor id in authority decisions;
- reads use Manifest-pinned local projections; Contact and convergence happen
  through the active Station.

## 2. CLI

The CLI favors flat verbs for daily issue work and nouns for registries and
administration. Run `lait --help` or `lait <command> --help` for the exact current
grammar; generated help is the command reference.

Common flows:

```text
lait init
lait new "Fix the import path"
lait ls
lait show <ref>
lait edit <ref>
lait start <ref>
lait done <ref>
lait comment <ref> "Reproduced on Windows"
lait board
```

`<ref>` resolution happens in the daemon. Full ids, unique prefixes, friendly
aliases, and supported contextual forms resolve through one grammar. Ambiguity
returns candidates; clients do not guess.

`--json` returns versioned response DTOs suitable for scripts. Error behavior is
classified by type, not by matching message text. Human output may improve
without changing the JSON contract.

Destructive or security-sensitive operations can require explicit confirmation.
Non-interactive clients must use the documented confirmation mechanism rather
than relying on a prompt.

## 3. Web

`lait serve` starts a loopback-only web application that can list locally known
spaces and attach to their daemons. It is a local client and supervisor, not an
iroh peer and not a space member.

The server uses a per-run bearer capability and origin/rebinding checks. A
browser may list navigation metadata without waking every daemon. Attaching to a
space starts or reuses only that space's daemon under the correct local identity.

The web application provides issue lists, boards, detail, inbox, activity,
members, filters, and command actions. Server-side semantics such as reference
resolution, authorization, project selection, and filtering remain in the
daemon; the browser does not reimplement them.

Actor/device management is not yet fully represented in the web members view.
Use the CLI for device enrollment, revocation, and recovery until parity lands.

## 4. MCP

`lait mcp` exposes the daemon command surface as MCP tools for agents. MCP uses
the same request and response types as other clients. A parity test guards the
intentional tool mapping.

Agents do not receive a privileged storage API. They resolve references, submit
commands, encounter the same authorization checks, and receive the same
versioned projections as human clients.

## 5. Live updates

Clients subscribe to dirty notifications. A notification identifies projections
that may have changed; it does not contain authoritative state. Clients re-read
the relevant board, issue, inbox, activity, members, or status projection.

Subscriptions begin with a reset. Clients also rebaseline when the daemon epoch
changes or when their sequence cursor falls behind the retained ring. Dirty
notifications may be coalesced without losing correctness.

Optimistic UI is permitted only as a temporary overlay. The next authoritative
projection always wins. A scalar may have a declared deterministic winner;
causally meaningful concurrent transitions or revisions surface a typed conflict
rather than being silently described as "the CRDT merge."

## 6. Identity, membership, and access

A member is an actor with one or more device keys. Admission carries an exact
expanded assignment set. The shipped roles are viewer, contributor, and
administrator, while effective authority consists of scoped World capabilities
stored and evaluated by Mechanics. Role names are provenance and UX; they are
not flat runtime grants.

Different projects in one Space may use different behavioral RBAC. They remain
inside one membership and encryption boundary; projects requiring distinct
read confidentiality belong in distinct Spaces.

The member surface shows actors. Device commands manage the keys behind the
current actor:

- `device invite` creates an enrollment token;
- `device accept` runs on the new device without a daemon and produces consent;
- `device add` binds that consent and seals held content keys;
- `device revoke` removes a device and rotates when possible;
- `device ls` lists the current actor's devices;
- `recover` resets the actor to the current device using the offline actor
  recovery key.

Space recovery and custody are separate from actor device recovery. Their
commands operate on the space recovery authority and require explicit
expected targets before a device contributes sensitive material.

## 7. Joining

Signed Coordinates carry the Space bootstrap anchor, approach Station and
bounded direct-route hints, plus an optional admission capability. Joining
creates and records a recoverable Orbit before activation and first Contact.

An authorized reusable or single-use invite may admit the joining actor
automatically: accepting the invite is the approval, and redemption completes
on the joiner's first contact with a member — there is no approval queue.
Unadmitted nodes may perform the bounded bootstrap Contact needed for redemption
but cannot dock an Issues Session or read protected Bodies.

`lait doctor` reports onboarding gates in order: Space, Station, admission,
peer reachability, convergence, and key/custody health where applicable. It distinguishes
waiting from failure instead of presenting an empty board as success.

## 8. Presence and names

Presence is online, away, or offline and is advisory. It reflects device
reachability and recent local interaction, not actor authority.

Network nicknames are self-asserted display data. Local petnames are preferred
for familiar rendering, but security-sensitive selection and confirmation show
stable identifiers. A name alone never selects a recovery target or grants
membership.

## 9. Comments, workflow conflicts, and partial state

Comments are addressed by stable identities. When replies, reactions, editing,
or moderation are available, clients treat comments as first-class records:
replies retain their parent id, reactions retain actor membership, and
concurrent edits retain revision heads. A list position is never a comment id.

The canonical workflow model uses predecessor-bound transitions. When the
product exposes concurrent transition heads, clients must present a conflict
requiring authorized resolution rather than inventing a winner from timestamps
or arrival order. The current scalar-status projection does not yet expose that
conflict and is a known product-schema limitation.

Clients must also distinguish:

- a valid value;
- a legitimately unavailable value, such as a provisional catalog row;
- a corrupt stored record.

Healthy JSON shapes remain stable. Where a projection supports corruption
sidecars, malformed records appear there with their locus and reason rather than
vanishing or appearing as typed values with sentinel fields.

## 10. Compatibility

The client performs a daemon handshake before normal commands. A missing,
incompatible, or unintelligible daemon is reported distinctly from an absent
daemon. Clients do not spawn over a process they cannot safely identify.

The exact control-channel compatibility rules are in
[`PROTOCOL.md`](./PROTOCOL.md). Exact command spelling comes from generated CLI
help, avoiding a second handwritten command table that can drift.
