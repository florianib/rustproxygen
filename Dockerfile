FROM rust:alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    git \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    perl \
    musl-dev

# Copy the project files
COPY . .

# Build the release binary, statically linked against musl
RUN cargo build --release --target x86_64-unknown-linux-musl

# Final runtime image
FROM dhi.io/alpine-base:3.23-alpine3.23-dev

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates && \
    rm -rf /var/cache/apk/*

# Copy the compiled binary from builder
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/rustproxygen /app/rustproxygen

# Copy assets directory
COPY --from=builder /build/assets /app/assets

# Set the entry point to the binary
ENTRYPOINT ["/app/rustproxygen"]

# Default resources directory to ./assets in the container
CMD ["-r", "/app/assets"]
