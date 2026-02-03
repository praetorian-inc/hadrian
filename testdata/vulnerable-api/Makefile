.PHONY: help build run run-apikey run-basic test test-all test-bearer test-apikey test-basic clean reset

help: ## Show this help message
	@echo "Vulnerable API - BOLA Testing"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the vulnerable API
	GOWORK=off go build -o vulnerable-api main.go

run: build ## Run with Bearer JWT auth (default)
	./vulnerable-api

run-apikey: build ## Run with API key authentication
	AUTH_METHOD=api_key ./vulnerable-api

run-basic: build ## Run with Basic authentication
	AUTH_METHOD=basic ./vulnerable-api

test: build ## Run BOLA vulnerability tests
	./test-bola.sh

clean: ## Remove build artifacts
	rm -f vulnerable-api

install-deps: ## Download Go dependencies
	go mod download

tidy: ## Tidy Go dependencies
	go mod tidy

reset: ## Reset API data to initial state (requires running API)
	curl -s -X POST http://localhost:8080/api/reset | jq .

test-all: build ## Run Hadrian tests with all auth methods
	./run-all-auth-tests.sh --verbose

test-bearer: build ## Run Hadrian tests with Bearer JWT auth only
	./run-all-auth-tests.sh --bearer-only --verbose

test-apikey: build ## Run Hadrian tests with API Key auth only
	./run-all-auth-tests.sh --apikey-only --verbose

test-basic: build ## Run Hadrian tests with Basic auth only
	./run-all-auth-tests.sh --basic-only --verbose

.DEFAULT_GOAL := help
