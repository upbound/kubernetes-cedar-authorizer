# This file is used as a base: https://github.com/micahhausler/cedar-access-control-for-k8s/blob/rust-with-schema-rewrite/rust-docker/Dockerfile
FROM rust:1.88-slim AS builder

# Create a new empty shell project
WORKDIR /build
COPY Cargo.toml Cargo.lock ./

# Prefetch dependencies to use docker cache. Add a dummy source file, as it's required for cargo fetch
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo fetch && \
    cargo build --release && \
    rm -rf src/

COPY src/ src/

# Build the application
RUN cargo build --release

# Create a new stage with a minimal image (as per Micah's suggestion)
FROM public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-glibc:latest-al23

# Copy the binary from builder
COPY --from=builder /build/target/release/kubernetes-cedar-authorizer /usr/local/bin/

ENV RUST_BACKTRACE=1
ENV RUST_LOG=debug,h2=error

# Set the startup command
ENTRYPOINT ["/usr/local/bin/kubernetes-cedar-authorizer"]
