# Build stage
FROM golang:1.26-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o loadmaster main.go

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk update && apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 loadmaster && \
    adduser -D -u 1000 -G loadmaster loadmaster

# Create application directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/loadmaster /app/loadmaster

# Create directory for certificates
RUN mkdir -p /certs && \
    chown -R loadmaster:loadmaster /app /certs

# Switch to non-root user
USER loadmaster

# Expose ACME challenge port
EXPOSE 5002

# Run the application
ENTRYPOINT ["/app/loadmaster"]
CMD ["-config", "/config.json", "-domains", "/domains.json", "-port", "5002"]
