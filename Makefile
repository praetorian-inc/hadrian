BINARY := hadrian
MODULE := github.com/praetorian-inc/hadrian
BUILD_DIR := bin
GOLANGCI_LINT_VERSION ?= v2.12.2

.PHONY: build test lint fmt vet check clean

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/hadrian

test:
	go test -race ./...

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	elif go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) 2>/dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not available, running go vet..."; \
		go vet ./...; \
	fi

fmt:
	gofmt -w .

vet:
	go vet ./...

check: fmt vet lint test

clean:
	rm -rf $(BUILD_DIR) dist
