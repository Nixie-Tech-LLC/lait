---
name: verify
description: Build and drive lait end-to-end on this Windows machine — two-node invite/join/watch flows against the debug binary.
---

# Verifying lait changes at the CLI surface

Build: `cargo build` → `target/debug/lait.exe`.

## Two-node harness

Use two `--home` dirs (scratchpad/temp), e.g. `$S/alice` and `$S/bob`:

```bash
lait --home "$S/alice" init --nick alice --room demo
lait --home "$S/alice" invite > invite.txt     # line 1 = bare base32 ticket
                                               # (also prints a lait://join/… URL + QR)
lait --home "$S/bob" join "$(head -1 invite.txt)" --nick bob   # auto-approves (Pattern A)
lait --home "$S/alice" who                     # ● bob …
```

To exercise the live event surface, run `watch` redirected to a log and grep it:

```bash
lait --home "$S/alice" watch --exec 'echo HOOK %LAIT_EVENT_KIND% %LAIT_EVENT_NICK% >> C:\...\hooks.log' > watch.log 2>&1 &
```

Hooks run via `cmd /C` on Windows — use `%VAR%` and **backslash paths** in redirects
(forward slashes make cmd fail with "The filename, directory name, or volume label
syntax is incorrect").

Presence events to trigger: spawn/stop the other node's daemon (`status` auto-spawns;
`stop` emits "left"). Since the shutdown fix, a polite `stop` hard-exits the process
within ~4s and breaks the control pipe, so it works for daemon-restart tests too
(hard-killing the PID with `Stop-Process` remains the most abrupt variant).

## Gotchas

- **Any command may auto-spawn the daemon as a child that inherits the console** —
  a PowerShell/Bash call that triggered a spawn can appear hung after its output.
  Run such commands with `run_in_background` and read state directly instead of
  waiting on task completion.
- Daemons **idle-shutdown and auto-respawn** — take a `Get-CimInstance Win32_Process
  -Filter "Name='lait.exe'"` PID+CreationDate snapshot before/after each step or
  attribution gets impossible. Reset with `Get-Process lait | Stop-Process -Force`.
- Cold rediscovery works since the room-adoption fix (join persists the ticket's
  room; boot self-heals stale profiles from the registry) — allow ~10-30s for the
  gossip mesh to reform after both daemons boot.
- Test suite has a known flake: `index::tests::reconcile_absorbs_a_seq_collision`
  fails ~1 in 7 runs, pre-existing, unrelated to most changes.
