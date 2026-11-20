# syntax=docker/dockerfile:1

# --- Stage 1: Builder (Latest Stable Rust on Debian) ---
FROM rust:1-bookworm AS builder

WORKDIR /usr/src/andesshield

# Cache dependency compilation first
COPY backend/Cargo.toml ./Cargo.toml
RUN mkdir -p src migrations \
    && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Copy actual source code and SQL migrations
COPY backend/src ./src
COPY backend/migrations ./migrations

# Compile final release binary (touch main.rs so Cargo rebuilds it)
RUN touch src/main.rs && cargo build --release

# --- Stage 2: Minimal Hardened Runtime ---
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 andesshield \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin andesshield

WORKDIR /app

COPY --from=builder /usr/src/andesshield/target/release/andesshield-api /usr/local/bin/andesshield-api
COPY index.html /app/static/index.html

RUN chown -R andesshield:andesshield /app

USER 10001:10001

EXPOSE 8080

ENV BIND_ADDR=0.0.0.0:8080 \
    STATIC_INDEX_PATH=/app/static/index.html

ENTRYPOINT ["/usr/local/bin/andesshield-api"]
