.PHONY: all proto build run clean test help

# Default target
all: proto build

# Generate Go code from proto files
proto:
	@echo "Generating protobuf code..."
	@mkdir -p pb
	protoc --go_out=pb --go_opt=paths=source_relative \
		--go-grpc_out=pb --go-grpc_opt=paths=source_relative \
		service.proto

# Build the server
build: proto
	@echo "Building vulnerable gRPC server..."
	go build -o grpc-server main.go

# Run the server (default port 50051)
run: build
	@echo "Starting vulnerable gRPC server on port 50051..."
	./grpc-server

# Run on custom port
run-custom:
	@echo "Starting vulnerable gRPC server on port $(PORT)..."
	GRPC_PORT=$(PORT) ./grpc-server

# Clean generated files
clean:
	@echo "Cleaning generated files..."
	rm -rf pb/
	rm -f grpc-server
	go clean

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Run tests (if any)
test:
	@echo "Running tests..."
	go test -v ./...

# Install protoc-gen-go and protoc-gen-go-grpc
install-protoc-gen:
	@echo "Installing protoc Go plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Help
help:
	@echo "Vulnerable gRPC Server - Makefile Commands"
	@echo ""
	@echo "Usage:"
	@echo "  make proto              Generate protobuf code"
	@echo "  make build              Build the server binary"
	@echo "  make run                Run server on default port (50051)"
	@echo "  make run-custom PORT=X  Run server on custom port"
	@echo "  make clean              Remove generated files"
	@echo "  make deps               Download Go dependencies"
	@echo "  make test               Run tests"
	@echo "  make install-protoc-gen Install protoc Go plugins"
	@echo "  make help               Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Generate proto + build"
	@echo "  make run                # Start server on port 50051"
	@echo "  make run-custom PORT=8080"
	@echo ""
	@echo "Environment Variables:"
	@echo "  GRPC_PORT  Server port (default: 50051)"
