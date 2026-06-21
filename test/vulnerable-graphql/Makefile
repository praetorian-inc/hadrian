.PHONY: all build run run-custom clean deps test help

# Default target
all: build

# Build the server binary
build:
	@echo "Building vulnerable GraphQL server..."
	go build -o vulnerable-graphql .

# Run the server (default port 5013, matching legacy DVGA Docker port)
run: build
	@echo "Starting vulnerable GraphQL server on port 5013..."
	./vulnerable-graphql

# Run on a custom port
run-custom: build
	@echo "Starting vulnerable GraphQL server on port $(PORT)..."
	PORT=$(PORT) ./vulnerable-graphql

# Remove the built binary
clean:
	@echo "Cleaning..."
	rm -f vulnerable-graphql
	go clean

# Download / tidy dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Run tests (with the race detector — the in-memory store is mutex-guarded and
# exercised concurrently by TestConcurrentGraphQLAccess). These boot HTTP
# handlers and exercise real shell/file-write behavior, so they are gated behind
# the `integration` build tag and do NOT run on a bare `go test ./...`.
test:
	@echo "Running tests..."
	go test -tags=integration -race -v ./...

# Help
help:
	@echo "Vulnerable GraphQL Server — Makefile Commands"
	@echo ""
	@echo "Usage:"
	@echo "  make build              Build the server binary"
	@echo "  make run                Run server on default port (5013)"
	@echo "  make run-custom PORT=X  Run server on custom port"
	@echo "  make clean              Remove built binary"
	@echo "  make deps               Download Go dependencies"
	@echo "  make test               Run unit tests"
	@echo "  make help               Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build"
	@echo "  make run                # Start server on port 5013"
	@echo "  make run-custom PORT=8080"
	@echo ""
	@echo "Environment Variables:"
	@echo "  PORT  Server port (default: 5013)"
