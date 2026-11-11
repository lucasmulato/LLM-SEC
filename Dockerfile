# Hermetic Reproducibility Capsule for LLM-SEC Formally Verified Execution Gateway
# Pinned Toolchain Environment: Debian 12 (Bookworm), Rust stable, OpenJDK 21, TLC, Python 3.11
# Conforms to PO-9 (Deterministic Reproducibility & Audit Replay) and AGENTS.md

FROM debian:bookworm-slim AS build-env

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/bin:$PATH \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Install base system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    make \
    openjdk-21-jre-headless \
    pkg-config \
    python3 \
    python3-minimal \
    && rm -rf /var/lib/apt/lists/*

# Install pinned Rust toolchain and wasm32v1-none bare-metal target for Layer 2 PURE WAD18
ENV RUST_VERSION=1.80.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain ${RUST_VERSION} \
    --profile minimal \
    --target wasm32v1-none \
    && cargo --version && rustc --version

WORKDIR /workspace

# Copy workspace source files
COPY Cargo.toml Cargo.lock Makefile deny.toml ./
COPY crates/ ./crates/
COPY tools/ ./tools/
COPY specs/ ./specs/
COPY packs/ ./packs/
COPY docs/ ./docs/
COPY scripts/ ./scripts/
COPY core/ ./core/

# Default target: execute complete verification pipeline and emit machine-readable verdict
CMD ["make", "verify"]
