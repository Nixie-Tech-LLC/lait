#!/usr/bin/env bash
# Build the unix release archive for one target, matching cargo-dist's layout:
# a `.tar.gz` whose contents are nested under `lait-<target>/` (binary + the misc
# docs cargo-dist auto-includes), plus a `<archive>.sha256` sidecar.
#
# Usage: archive-unix.sh <target-triple>   (run from the repo root)
set -euo pipefail

TARGET="${1:?usage: archive-unix.sh <target-triple>}"
NAME="lait-${TARGET}"
BIN="target/${TARGET}/release/lait"
ARCHIVE="${NAME}.tar.gz"

[ -f "$BIN" ] || { echo "::error::binary not found: $BIN"; exit 1; }

rm -rf "$NAME" "$ARCHIVE" "${ARCHIVE}.sha256"
mkdir -p "$NAME"
cp "$BIN" "$NAME/lait"
# The docs cargo-dist auto-includes in each archive (lait does NOT set
# auto-includes=false). Keep this set in sync with the release plan.
cp CHANGELOG.md LICENSE-APACHE LICENSE-MIT README.md "$NAME/"

tar czf "$ARCHIVE" "$NAME"
shasum -a 256 "$ARCHIVE" > "${ARCHIVE}.sha256"

echo "built $ARCHIVE"
tar tzf "$ARCHIVE"
