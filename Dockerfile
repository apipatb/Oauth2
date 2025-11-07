# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o oauth2-server .

# Run stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/oauth2-server .
COPY --from=builder /app/static ./static

# Expose port
EXPOSE 8080

# Set environment variables with defaults
ENV DATABASE_TYPE=sqlite \
    DATABASE_URL=./oauth2.db \
    SERVER_PORT=8080 \
    JWT_SECRET=change-this-secret-in-production

# Run the application
CMD ["./oauth2-server"]
