#!/usr/bin/env bash
# Portability guard for the daemon control channel + single-instance lock.
#
# Those paths MUST stay cross-platform: a Unix-domain socket on unix / a named
# pipe on Windows (via `interprocess`), and an advisory lock via `fs2` — never a
# raw `flock(2)`, `UnixStream/UnixListener`, or `std::os::fd`/`std::os::unix`
# import bleeding into portable code. iroh's own transport is exempt (it is
# portable already); this only scans the control/lock/config surface.
#
# Any match of a unix-only primitive that is NOT inside an explicit `#[cfg(unix)]`
# island is a hard failure. The Windows CI job compiling is the primary gate;
# this catches the regression at review time on any OS and explains why.
set -euo pipefail

# Files that make up the portable control/lock surface.
FILES=(src/control.rs src/config.rs)

# Unix-only primitives that must never appear un-cfg'd in the portable surface.
# (`flock` is intentionally not scanned as a bare word: the portable `fs2` lock
# is documented in comments here that mention flock(2)/LockFileEx. We scan for
# type/module imports that would actually pull in a unix-only API.)
PATTERNS='UnixStream|UnixListener|std::os::unix|std::os::fd'

fail=0
for f in "${FILES[@]}"; do
  [ -f "$f" ] || continue
  # Strip lines inside a `#[cfg(unix)]` block is hard in bash; instead we allow
  # matches only on lines that ALSO carry a cfg(unix) guard on the same or the
  # preceding line. Simpler and robust: flag any match, then whitelist the known
  # cfg(unix) socket_path island by requiring the offending line not to be within
  # a cfg(unix) function. We approximate: report matches and let a human confirm.
  while IFS= read -r line; do
    lineno="${line%%:*}"
    content="${line#*:}"
    # Skip comment lines — documentation may name a unix API in prose.
    trimmed="$(printf '%s' "$content" | sed 's/^[[:space:]]*//')"
    case "$trimmed" in
      //*) continue ;;
    esac
    # Look back up to 3 lines for a cfg(unix) guard.
    start=$(( lineno > 3 ? lineno - 3 : 1 ))
    context="$(sed -n "${start},${lineno}p" "$f")"
    if echo "$context" | grep -q '#\[cfg(unix)\]'; then
      continue  # guarded — OK
    fi
    echo "::error file=$f,line=$lineno::unix-only API in portable control/lock path: $content"
    fail=1
  done < <(grep -nE "$PATTERNS" "$f" || true)
done

if [ "$fail" -ne 0 ]; then
  echo "Portability guard failed: the control/lock path must stay cross-platform."
  exit 1
fi
echo "Portability guard passed: control/lock path is cross-platform."
