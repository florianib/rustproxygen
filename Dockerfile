FROM dhi.io/alpine-base:3.23-alpine3.23-dev AS builder

WORKDIR /build

# Install Rust and dependencies
RUN apk add --no-cache \
    rust \
    cargo \
    musl-dev \
    gcc \
    g++ \
    make \
    pkgconfig

# Copy the project files
COPY . .

# Build the release binary
RUN cargo build --release

# Final stage
FROM dhi.io/alpine-base:3.23-alpine3.23-dev

WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /build/target/release/rustproxygen /app/rustproxygen

# Copy assets directory
COPY --from=builder /build/assets /app/assets

# Set the entry point to the binary
ENTRYPOINT ["/app/rustproxygen"]

# Default resources directory to ./assets in the container
CMD ["-r", "/app/assets"]
