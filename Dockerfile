# syntax=docker/dockerfile:1.7

# ---------- builder ----------
FROM rust:1-slim-bookworm AS builder

WORKDIR /build

# Cache dependencies separately for faster rebuilds
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src target/release/lansight* target/release/deps/lansight*

# Build the real binary
COPY src ./src
RUN cargo build --release \
    && strip target/release/lansight

# ---------- runtime ----------
FROM debian:bookworm-slim

# iproute2 → `ip neigh` (host ARP cache)
# dnsutils → `nslookup` (reverse DNS)
# ca-certificates → outbound HTTPS if you ever add it
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        dnsutils \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/lansight /usr/local/bin/lansight

EXPOSE 8080

# NOTE: container must be run with --network host (or equivalent in Coolify),
# otherwise scanning will see only Docker's internal bridge.
CMD ["lansight"]
