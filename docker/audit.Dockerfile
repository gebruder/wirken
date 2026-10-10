# Build environment for security review, the image docs/threat-model.md
# describes.
#
# The image is built with the repository as the context and with network
# access, then run with none. Everything `cargo test --workspace` needs is
# fetched and compiled here, so the test suite runs offline in the image.
# Tests that need a live container runtime skip themselves when there is
# none, as there is none here. From a clean checkout:
#
#   docker build -f docker/audit.Dockerfile -t wirken-audit .
#   docker run --rm --network none wirken-audit cargo test --workspace
#
# The base image's Rust version is the channel rust-toolchain.toml pins.
# Move both or neither. On a mismatch the toolchain step below still
# installs the pinned channel, beside an unused one.
FROM rust:1.99.0-trixie

# crates/ipc/build.rs compiles schema/wirken.capnp with the capnp tool.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends capnproto \
    && rm -rf /var/lib/apt/lists/*

# A scan expects the checkout at /src.
COPY . /src
WORKDIR /src

# The toolchain rust-toolchain.toml names, with its components. Installed
# here because rustup fetches a missing component on first use, and that
# fetch fails offline.
RUN rustup toolchain install \
    && rustc --version \
    && cargo --version \
    && capnp --version

# Every crate in Cargo.lock for every target, the one git dependency
# included, then every test target of the workspace compiled, so that
# `cargo test --workspace` in the image only has to run them.
RUN cargo fetch --locked \
    && cargo test --workspace --locked --no-run

# The image runs with no network. Fail at once rather than at an index
# update.
ENV CARGO_NET_OFFLINE=true
