# --- Stage 1: Build Go Binary ---
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git and build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build single static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o strikerr cmd/strikerr/main.go

# --- Stage 2: Runtime Environment ---
FROM ubuntu:22.04

WORKDIR /app

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for Playwright / Chromium
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    chromium-browser \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary from stage 1
COPY --from=builder /app/strikerr /app/strikerr
COPY --from=builder /app/config /app/config

# Expose Web Dashboard & API Port
EXPOSE 8080

# Environment Defaults
ENV GIN_MODE=release
ENV SERVER_PORT=8080

CMD ["/app/strikerr"]
