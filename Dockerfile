# --- Stage 1: Build Go Binary (Use latest Go alpine image) ---
FROM golang:alpine AS builder

WORKDIR /app

# Enable CGO_ENABLED=0 and set GOPROXY
ENV CGO_ENABLED=0
ENV GOPROXY=https://proxy.golang.org,direct

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download Go modules
RUN go mod download

# Copy source code
COPY . .

# Build single static binary
RUN go build -ldflags="-w -s" -o strikerr cmd/strikerr/main.go

# --- Stage 2: Runtime Environment ---
FROM ubuntu:22.04

WORKDIR /app

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies for Playwright / Chromium
# Added unzip and required system libraries
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    unzip \
    wget \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libxshmfence1 \
    && rm -rf /var/lib/apt/lists/*

# Copy built binary, config, and web templates from stage 1
COPY --from=builder /app/strikerr /app/strikerr
COPY --from=builder /app/config /app/config
COPY --from=builder /app/internal/web/templates /app/internal/web/templates

# Pre-download Playwright driver and browsers during the Docker build
# This prevents the container from hanging at runtime
RUN /app/strikerr -install-playwright-only

# Expose Web Dashboard & API Port
EXPOSE 8051

# Environment Defaults
ENV GIN_MODE=release
ENV SERVER_PORT=8051

CMD ["/app/strikerr"]
