BINARY := hadrian
MODULE := github.com/praetorian-inc/hadrian
BUILD_DIR := bin

.PHONY: build test lint fmt vet check clean

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/hadrian

test:
	go test -race ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

vet:
	go vet ./...

check: fmt vet lint test

clean:
	rm -rf $(BUILD_DIR) dist
