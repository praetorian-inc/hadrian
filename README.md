# Hadrian

[![CI](https://github.com/praetorian-inc/hadrian/actions/workflows/ci.yml/badge.svg)](https://github.com/praetorian-inc/hadrian/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/praetorian-inc/hadrian)](https://goreportcard.com/report/github.com/praetorian-inc/hadrian)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Hadrian is a security testing framework for REST, GraphQL, and gRPC APIs that tests for OWASP API vulnerabilities and custom security issues using role-based authorization testing.

## Features

- **OWASP API Top 10 Coverage**: Test for BOLA, broken authentication, and more
- **Role-Based Testing**: Define roles with permissions and test cross-role access
- **Mutation Testing**: Three-phase setup/attack/verify testing pattern for proving write/delete vulnerabilities (BFLA and BOPLA)
- **Template-Driven**: YAML templates for customizable security tests
- **Multiple Output Formats**: Terminal, JSON, and Markdown reports
- **Adaptive Rate Limiting**: Proactive request throttling with reactive backoff on 429/503 responses
- **Proxy Support**: Route traffic through Burp Suite or other proxies
- **LLM Triage**: Optional AI-powered finding analysis (Ollama)

## OWASP API Security Top 10 Coverage

| Category | Name | REST | GraphQL | gRPC |
|----------|------|------|---------|------|
| API1:2023 | Broken Object Level Authorization | ✅ | ✅ | ✅ |
| API2:2023 | Broken Authentication | ✅ | ✅ | ✅ |
| API3:2023 | Broken Object Property Level Authorization | ✅ | ✅ | ✅ |
| API4:2023 | Unrestricted Resource Consumption | ❌ | ✅ | ❌ |
| API5:2023 | Broken Function Level Authorization | ✅ | ✅ | ✅ |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | ❌ | ❌ | ❌ |
| API7:2023 | Server Side Request Forgery | ❌ | ❌ | ❌ |
| API8:2023 | Security Misconfiguration | ✅ | ✅ | ✅ |
| API9:2023 | Improper Inventory Management | ✅ | ❌ | ❌ |
| API10:2023 | Unsafe Consumption of APIs | ❌ | ❌ | ❌ |

**REST templates:** 8 in `templates/rest/` | **GraphQL templates:** 13 in `templates/graphql/` | **gRPC templates:** 9 in `templates/grpc/`

## Installation

### From source

```bash
go install github.com/praetorian-inc/hadrian/cmd/hadrian@latest
```

### From releases

Download the latest binary from the [Releases](https://github.com/praetorian-inc/hadrian/releases) page.

## Quick Start

### REST API Testing

```bash
hadrian test rest --api api.yaml --roles roles.yaml --auth auth.yaml
```

### GraphQL API Testing

```bash
hadrian test graphql --target https://api.example.com --auth auth.yaml --roles roles.yaml
```

### gRPC API Testing

```bash
hadrian test grpc --target localhost:50051 --proto service.proto --auth auth.yaml --roles roles.yaml
```

### Common Options

```bash
# Dry run (show what would be tested)
hadrian test rest --api api.yaml --roles roles.yaml --dry-run

# Output to JSON file
hadrian test rest --api api.yaml --roles roles.yaml --output json --output-file report.json

# With LLM-powered triage
hadrian test rest --api api.yaml --roles roles.yaml \
  --llm-host http://localhost:11434 --llm-model llama3.2:latest

# Route through Burp Suite proxy
hadrian test rest --api api.yaml --roles roles.yaml --proxy http://localhost:8080 --insecure
```

## Documentation

| Document | Description |
|----------|-------------|
| [REST Testing](docs/rest.md) | REST API testing guide, templates, and crAPI tutorial |
| [GraphQL Testing](docs/graphql.md) | GraphQL security checks, schema discovery, and DVGA tutorial |
| [gRPC Testing](docs/grpc.md) | gRPC test patterns, mutation testing, and status codes |
| [Configuration](docs/configuration.md) | Auth, roles, rate limiting, proxy, LLM triage, output formats |
| [Architecture](docs/architecture.md) | Internal architecture, data flow, and component overview |

## Tutorials

- **REST**: [crAPI Tutorial](test/crapi/README.md) - Test OWASP crAPI (intentionally vulnerable REST API)
- **GraphQL**: [DVGA Tutorial](test/dvga/README.md) - Test DVGA (Damn Vulnerable GraphQL Application)
- **gRPC**: [gRPC Server Tutorial](test/grpc-server/README.md) - Test a vulnerable gRPC server

## Development

### Prerequisites

- [Go 1.24+](https://go.dev/dl/)
- [golangci-lint](https://golangci-lint.run/welcome/install/)

### Getting started

```bash
git clone https://github.com/praetorian-inc/hadrian.git
cd hadrian
make build
```

### Common commands

```bash
make build       # Build the binary
make test        # Run tests
make lint        # Run linters
make fmt         # Format code
make check       # Run all checks (fmt, vet, lint, test)
```

### Testing

```bash
go test ./...                        # Run unit tests
go test -tags=integration ./...      # Run integration tests
go test -race ./...                  # Run with race detection
go test ./pkg/runner/...             # Run specific package
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please ensure all CI checks pass before requesting review.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## About Praetorian

[Praetorian](https://www.praetorian.com/) is a cybersecurity company that helps organizations secure their most critical assets through offensive security services and the [Praetorian Guard](https://www.praetorian.com/guard) attack surface management platform.
