# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Install ca-certificates for HTTPS
RUN apk add --no-cache ca-certificates

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o trix-agent ./cmd/...

# Runtime stage
FROM scratch

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /build/trix-agent /trix-agent

# Run as non-root
USER 65534:65534

ENTRYPOINT ["/trix-agent"]
