#!/usr/bin/env bash
# Replica boundary guard: the domain must not speak the client protocol.
#
# `src/replica/` is the domain — it decides what is legitimate, not how to say
# so. Turning an outcome into a wire `Response` belongs to the control adapter
# in `replica/dispatch.rs`, which is the single door between the two. Keeping it
# that way is what lets the domain be lifted out from under the daemon later
# without dragging the control plane along, and what stops error prose from
# scattering back into the modules that detect failures.
#
# `dispatch.rs` is the adapter and `tests.rs` asserts observable output, so both
# are exempt. Everything else under `src/replica/` fails on a mention.
#
# This guards a property the compiler cannot: `mod.rs` no longer imports
# `Request`/`Response`, so a domain module would have to name them through
# `crate::control::` to regress — which compiles fine and is exactly what this
# catches.
set -euo pipefail

# Only these two names. `Filter`, `BoardPos`, and `CatalogScope` are request
# *input* types the domain legitimately takes as parameters; a guard written as
# "no `crate::control::` outside dispatch" would be wrong and would force
# pointless re-wrapping of three input DTOs.
PATTERNS='\b(Response|Request)\b'

EXEMPT='src/replica/dispatch.rs|src/replica/tests.rs'

# Comments are stripped before matching: the doc comments in this module
# explain the boundary and necessarily name the types it excludes. Prose about
# the rule is not a breach of it.
fail=0
for f in src/replica/*.rs; do
  if [[ "$f" =~ $EXEMPT ]]; then
    continue
  fi
  if hits=$(sed 's://.*::' "$f" | grep -nE "$PATTERNS"); then
    echo "error: $f names the control protocol:"
    echo "$hits" | sed 's/^/    /'
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  cat >&2 <<'MSG'

The replica domain must not construct or return `control::Response`, nor match
on `control::Request`. Return a domain value or a `ReplicaError` instead, and
render it in `replica/dispatch.rs` — the one door.

If a domain method needs to report something the adapter cannot express yet,
add a variant to the outcome type or to `ReplicaError`; do not carry a
formatted sentence out of the domain.
MSG
  exit 1
fi

echo "replica boundary: the domain names no control protocol types."
