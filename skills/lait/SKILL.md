---
name: lait
description: File and drive issues in a local-first, peer-to-peer issue tracker via the lait MCP server — create/edit/move/assign/label/comment/close issues, read boards and lists, and follow the activity feed. Use when the user asks this agent to track work, file an issue, update a ticket, or work a board in lait.
---

# Lait: a peer-to-peer issue tracker

You have a `lait` MCP server. It drives a local node that owns the space's
Loro-CRDT issue documents over a git-backed store. Every tool returns the same
versioned JSON DTO the CLI `--json` emits.

## Refs
An issue `<ref>` is a short `iss_` handle (canonical, collision-free) or a `KEY-n`
alias like `ENG-142`. A project ref is its key (`ENG`) or a `prj_` id. A who-ref
is `@me` or a 64-hex key. If a ref is ambiguous the tool returns a candidate list —
re-issue with a more specific handle.

## File and drive work
- `project_new {name, key}` / `project_list` — manage projects. Create a project
  before the first issue.
- `issue_new {title, project?, assignees?, priority?, labels?, body?}` — create an
  issue; returns the resolved handle. Priority is none|low|medium|high|urgent.
- `issue_edit {reff, title?, status?, priority?}` — patch fields; all flags in one
  call is one commit = one activity row.
- `issue_move {reff, project?, position?}` — position is `top`|`bottom`|
  `before:<ref>`|`after:<ref>`. Setting a project changes membership (the truth).
- `assign {reff, who:[…], remove?}` · `label {reff, add:[…], remove:[…]}` ·
  `comment {reff, body}` · `issue_delete {reff}` (tombstone; stays in history).

## Read
- `list {project?, mine?, status?, label?, all?}` — rows from the catalog cache
  (fast, no issue-doc loads). `all` includes done/tombstoned.
- `board {project}` — workflow columns × ordered rows.
- `issue_view {reff}` — the full issue: body, comments, metadata.
- `history {reff}` — the issue's derived activity feed.
- `activity {since}` — space-wide recent transitions; pass back `last` to follow.

## Multi-node & E2EE (P2P)
Onboarding across nodes is one step: the host calls `invite_ticket` and shares it;
the other side calls `connect`. Space data is end-to-end encrypted, gated by a
signed membership graph — a joiner sees only ciphertext until an admin admits it:
- `member_add {who, admin?}` — seal the space key to a member (admin-only).
- `member_remove {who}` — revoke + rotate the key (lazy revocation; admin-only).
- `key_rotate` / `members` — rotate the key / list members and roles.
`who` is a presence snapshot; `status` shows the space + issue/project counts.

There is no compare-and-swap: an edit always applies and merges (a CRDT). Read the
current state, act, and let it converge.
