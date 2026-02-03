# Runtime stage - uses pre-built binary from goreleaser
FROM alpine:3.21

# Install CA certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Copy binary (goreleaser places it in the build context)
COPY kijo-agent /kijo-agent

# Run as non-root
USER 65534:65534

ENTRYPOINT ["/kijo-agent"]
