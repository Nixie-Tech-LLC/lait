# syntax=docker/dockerfile:1

# ── Build stage ──────────────────────────────────────────────────────────────
# Pinned to the crate MSRV (driven by iroh 1.0.0-rc.1). The crypto stack is pure
# Rust (RustCrypto/dalek, rustls+ring), so the only C toolchain need is a linker
# and `cc`/`perl` for ring's assembly — provided by build-essential.
FROM rust:1.91-slim-bookworm AS build
WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config perl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Warm the dependency cache: copy manifests, build a stub, then the real sources.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --locked || true
COPY . .
# Bust the stale stub's fingerprint so the real sources recompile.
RUN touch src/main.rs src/lib.rs && cargo build --release --locked --bin lait

# ── Runtime stage ────────────────────────────────────────────────────────────
# Slim runtime; ca-certificates lets iroh reach its relay/DNS over TLS for NAT
# traversal. Runs as an unprivileged user with the node state on a volume.
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 lait

COPY --from=build /src/target/release/lait /usr/local/bin/lait

# A self-contained node home (identity + git-backed store) lives here; mount a
# volume so the seed keeps its identity and adopted space across restarts.
ENV LAIT_HOME=/data
RUN mkdir -p /data && chown lait:lait /data
VOLUME ["/data"]
USER lait

# Run as an always-on seed: never idle-shuts-down, so it stays reachable to
# serve sync and backfill encrypted history to peers. Adopt a space once with
#   docker exec <container> lait seed add <room-ticket>
# (or `lait connect <ticket>`), then `lait members add <this-node-id>` from an
# admin so the seed can hold the space's history. Get the id with:
#   docker exec <container> lait id
CMD ["lait", "daemon", "--seed"]
