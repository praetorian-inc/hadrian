BINARY := hadrian
MODULE := github.com/praetorian-inc/hadrian
BUILD_DIR := bin

.PHONY: build test lint fmt vet check clean cli-docs

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

cli-docs:
	@GOWORK=off go test ./pkg/runner -list 'TestCLISurface' | grep -qE '^TestCLISurface$$' \
	  || { echo "cli-docs: 'go test -list' did not report TestCLISurface in ./pkg/runner. Either the -update writer was renamed, or the package failed to build -- run 'go build ./pkg/runner' to tell which. 'go test -run' exits 0 when its pattern matches nothing, so without this check the target would report success having regenerated nothing at all."; exit 1; }
	GOWORK=off go test ./pkg/runner -run 'TestCLISurface' -count=1 -update

clean:
	rm -rf $(BUILD_DIR) dist
