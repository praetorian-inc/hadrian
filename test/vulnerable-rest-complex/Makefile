.PHONY: help build run test clean tidy

PORT ?= 8888

help: ## Show this help message
	@echo "Vulnerable REST Complex - Multi-Resource BOLA/BFLA/BOPLA Test Target"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the vulnerable-rest-complex binary
	GOWORK=off go build -o vulnerable-rest-complex main.go

run: build ## Run the server on PORT (default 8888)
	PORT=$(PORT) ./vulnerable-rest-complex

test: ## Run unit tests
	GOWORK=off go test -v ./...

clean: ## Remove build artifacts
	rm -f vulnerable-rest-complex

tidy: ## Tidy Go dependencies
	GOWORK=off go mod tidy

.DEFAULT_GOAL := help
