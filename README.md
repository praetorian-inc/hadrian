<img width="1200" height="628" alt="Hadrian - Open source API security testing framework for REST, GraphQL, and gRPC. Test for OWASP API Top 10 authorization vulnerabilities using YAML-driven templates." src="https://github.com/user-attachments/assets/5703e1d4-7a1d-4c8f-a8e0-9ab45e9ed248" />

# Hadrian: Open-Source API Security Testing Framework

[![CI](https://github.com/praetorian-inc/hadrian/actions/workflows/ci.yml/badge.svg)](https://github.com/praetorian-inc/hadrian/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/praetorian-inc/hadrian)](https://goreportcard.com/report/github.com/praetorian-inc/hadrian)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Hadrian is an open-source API security testing framework that detects OWASP API Top 10 vulnerabilities in REST, GraphQL, and gRPC APIs.** It uses role-based authorization testing and YAML-driven templates to automatically find broken object-level authorization (BOLA), broken function-level authorization (BFLA), broken authentication, and other critical API security flaws — without writing custom test code.

## Why Hadrian?

Most API security scanners test for injection and configuration issues but miss **authorization logic bugs** — the #1 and #5 most critical API vulnerabilities according to OWASP. Hadrian is purpose-built for authorization testing:

- **Define your roles once** (admin, user, guest) with permissions and credentials
- **Hadrian cross-tests every role combination** against every endpoint automatically
- **Three-phase mutation testing** proves write/delete vulnerabilities actually occurred — not just that a 200 OK was returned

> Hadrian found 3 critical BOLA vulnerabilities in [OWASP crAPI](https://github.com/OWASP/crAPI) in under 60 seconds. [Try the tutorial →](https://github.com/praetorian-inc/hadrian/wiki/Tutorials)

## Key Features

| Feature | Description |
|---------|-------------|
| **OWASP API Top 10 Coverage** | 30 built-in templates covering BOLA, broken auth, BFLA, data exposure, and misconfigurations |
| **Role-Based Authorization Testing** | Define roles with permission levels and test cross-role access automatically |
| **Mutation Testing** | Three-phase setup → attack → verify pattern proves write/delete vulnerabilities actually occurred |
| **REST + GraphQL + gRPC** | Test any API protocol with protocol-specific security checks |
| **Template-Driven** | YAML templates for customizable security tests — no code required |
| **Multiple Output Formats** | Terminal, JSON, and Markdown reports for CI/CD integration |
| **Adaptive Rate Limiting** | Proactive request throttling with reactive backoff on 429/503 responses |
| **Proxy Support** | Route traffic through Burp Suite or other intercepting proxies |
| **LLM-Powered Triage** | Optional AI analysis of findings via Ollama to reduce false positives |
| **LLM-Assisted Attack Planning** | AI-driven prioritization of which endpoints and vulnerability patterns to test first |
| **Claude Code Integration** | Auto-generate auth and role configs from OpenAPI, GraphQL SDL, or proto files |

## OWASP API Security Top 10 Coverage

Hadrian includes 30 templates (8 REST, 13 GraphQL, 9 gRPC) covering the most critical API security risks:

| Category | Vulnerability | REST | GraphQL | gRPC |
|----------|--------------|------|---------|------|
| API1:2023 | Broken Object Level Authorization (BOLA) | ✅ | ✅ | ✅ |
| API2:2023 | Broken Authentication | ✅ | ✅ | ✅ |
| API3:2023 | Broken Object Property Level Authorization (BOPLA) | ✅ | ✅ | ✅ |
| API4:2023 | Unrestricted Resource Consumption | — | ✅ | — |
| API5:2023 | Broken Function Level Authorization (BFLA) | ✅ | ✅ | ✅ |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | — | — | — |
| API7:2023 | Server Side Request Forgery | — | — | — |
| API8:2023 | Security Misconfiguration | ✅ | ✅ | ✅ |
| API9:2023 | Improper Inventory Management | ✅ | — | — |
| API10:2023 | Unsafe Consumption of APIs | — | — | — |

## How to Install Hadrian

### Install from Source (Go)

```bash
go install github.com/praetorian-inc/hadrian/cmd/hadrian@latest
```

### Download Pre-Built Binary

Download the latest binary for your platform from the [Releases](https://github.com/praetorian-inc/hadrian/releases) page.

### Build from Source

```bash
git clone https://github.com/praetorian-inc/hadrian.git
cd hadrian
make build
```

## How to Test Your API with Hadrian

### REST API Security Testing

```bash
hadrian test rest --api api.yaml --roles roles.yaml --auth auth.yaml
```

### GraphQL API Security Testing

```bash
hadrian test graphql --target https://api.example.com --auth auth.yaml --roles roles.yaml
```

### gRPC API Security Testing

```bash
hadrian test grpc --target localhost:50051 --proto service.proto --auth auth.yaml --roles roles.yaml
```

### Common Options

```bash
# Preview what would be tested (dry run)
hadrian test rest --api api.yaml --roles roles.yaml --dry-run

# Export findings as JSON
hadrian test rest --api api.yaml --roles roles.yaml --output json --output-file report.json

# AI-powered triage to reduce false positives
hadrian test rest --api api.yaml --roles roles.yaml \
  --llm-host http://localhost:11434 --llm-model llama3.2:latest

# AI-assisted attack planning (prioritizes high-risk endpoints)
hadrian test rest --api api.yaml --roles roles.yaml --auth auth.yaml --planner

# Run only LLM-planned steps (faster, targeted testing)
hadrian test rest --api api.yaml --roles roles.yaml --auth auth.yaml --planner --planner-only

# Route through a proxy for manual inspection
hadrian test rest --api api.yaml --roles roles.yaml --proxy http://localhost:8080 --insecure
```

## How Does Hadrian's Mutation Testing Work?

Unlike scanners that only check HTTP status codes, Hadrian's **three-phase mutation testing** proves that unauthorized actions actually succeeded:

```
Phase 1: SETUP     → Victim creates a resource (stores resource ID)
Phase 2: ATTACK    → Attacker attempts to delete victim's resource
Phase 3: VERIFY    → Confirm the resource was actually deleted
```

This eliminates false positives from APIs that return 200 OK but silently ignore unauthorized requests. [Learn more about mutation testing →](https://github.com/praetorian-inc/hadrian/wiki/Architecture)

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](https://github.com/praetorian-inc/hadrian/wiki/Getting-Started) | Installation, first scan, and configuration walkthrough |
| [REST API Testing](https://github.com/praetorian-inc/hadrian/wiki/REST-API-Testing) | REST testing guide, 8 templates, and OpenAPI integration |
| [GraphQL Security Testing](https://github.com/praetorian-inc/hadrian/wiki/GraphQL-Security-Testing) | 13 GraphQL checks including introspection, DoS, and auth bypass |
| [gRPC Security Testing](https://github.com/praetorian-inc/hadrian/wiki/gRPC-Security-Testing) | gRPC patterns, proto file integration, and mutation testing |
| [Configuration](https://github.com/praetorian-inc/hadrian/wiki/Configuration) | Auth methods, roles, rate limiting, proxy, LLM triage, output formats |
| [Template System](https://github.com/praetorian-inc/hadrian/wiki/Template-System) | How to write custom YAML security test templates |
| [Architecture](https://github.com/praetorian-inc/hadrian/wiki/Architecture) | Internal design, data flow, and component overview |
| [FAQ](https://github.com/praetorian-inc/hadrian/wiki/FAQ) | Frequently asked questions about Hadrian |

### Tutorials

- **REST**: [crAPI Tutorial](https://github.com/praetorian-inc/hadrian/wiki/Tutorials#rest-crapi-tutorial) — Test OWASP crAPI (intentionally vulnerable REST API)
- **GraphQL**: [DVGA Tutorial](https://github.com/praetorian-inc/hadrian/wiki/Tutorials#graphql-dvga-tutorial) — Test Damn Vulnerable GraphQL Application
- **gRPC**: [gRPC Server Tutorial](https://github.com/praetorian-inc/hadrian/wiki/Tutorials#grpc-vulnerable-server-tutorial) — Test an intentionally vulnerable gRPC server

### Claude Code Integration

Hadrian includes a [Claude Code](https://claude.ai/code) skill that **auto-generates `auth.yaml` and `roles.yaml`** from your API specification — no manual config writing needed.

```bash
# Launch Claude Code with Hadrian as a plugin
claude --plugin-dir /path/to/hadrian

# Then ask it to generate your config:
# "Generate Hadrian auth.yaml and roles.yaml from my openapi.yaml"
# "Create Hadrian authorization templates from schema.graphql"
# "Build Hadrian config from service.proto"
```

Supports OpenAPI/Swagger, GraphQL SDL, and gRPC proto files. See the [skill documentation](skills/hadrian-openapi-authz/SKILL.md) for details.

## Frequently Asked Questions

### What types of APIs can Hadrian test?

Hadrian tests **REST APIs** (via OpenAPI/Swagger specs), **GraphQL APIs** (via introspection or SDL schemas), and **gRPC APIs** (via proto files). It supports bearer tokens, basic auth, API keys, and cookie-based authentication across all three protocols.

### How is Hadrian different from OWASP ZAP or Burp Suite?

ZAP and Burp are general-purpose web security scanners focused on injection, XSS, and configuration issues. Hadrian is **purpose-built for API authorization testing** — it understands roles, permissions, and cross-user access patterns. It tests whether User A can access User B's resources, which generic scanners cannot do without extensive manual configuration.

### Does Hadrian modify or delete data during testing?

Mutation tests create temporary resources during the setup phase and may attempt to modify or delete them. Always **test against staging environments first** and use `--dry-run` to preview what will be tested before executing.

### Can I write custom security test templates?

Yes. Hadrian uses YAML templates that define endpoint selectors, role selectors, and detection logic. You can create custom templates for application-specific authorization rules beyond the OWASP Top 10. See the [Template System guide](https://github.com/praetorian-inc/hadrian/wiki/Template-System).

### Does Hadrian integrate with CI/CD pipelines?

Yes. Use `--output json --output-file report.json` to generate machine-readable reports. Hadrian returns a non-zero exit code when vulnerabilities are found, making it suitable for CI/CD gates.

## Development

### Prerequisites

- [Go 1.24+](https://go.dev/dl/)
- [golangci-lint](https://golangci-lint.run/welcome/install/)

### Build and Test

```bash
git clone https://github.com/praetorian-inc/hadrian.git
cd hadrian
make build       # Build the binary
make test        # Run tests
make lint        # Run linters
make check       # Run all checks (fmt, vet, lint, test)
```

```bash
go test ./...                        # Unit tests
go test -tags=integration ./...      # Integration tests
go test -race ./...                  # Race detection
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please ensure all CI checks pass before requesting review.

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.

## About Praetorian

[Praetorian](https://www.praetorian.com/) is a cybersecurity company that helps organizations secure their most critical assets through offensive security services and the [Praetorian Guard](https://www.praetorian.com/guard) attack surface management platform.
