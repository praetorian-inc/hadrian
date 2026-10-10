<!-- Generated from the live cobra command tree by 'make cli-docs'. Do not edit by hand. -->

# hadrian CLI reference

Every command, alias and flag below is derived from the cobra command tree, not from prose.
Schema version 1, surface hash `sha256:bca3ae7706898aae6369cf1a6b9110fa09318903017b177ad26d37db4da425e0`.

Regenerate with `make cli-docs` after adding, removing or renaming a command or a flag.

## Command index

| Command | Aliases | Description |
| --- | --- | --- |
| [`hadrian`](#hadrian) | *(none)* | Hadrian - API Security Testing Framework |
| [`hadrian parse`](#hadrian-parse) | *(none)* | Parse API specification and show operations |
| [`hadrian test`](#hadrian-test) | *(none)* | Run security tests against an API |
| [`hadrian test graphql`](#hadrian-test-graphql) | *(none)* | Run security tests against a GraphQL API |
| [`hadrian test grpc`](#hadrian-test-grpc) | *(none)* | Run security tests against a gRPC API |
| [`hadrian test rest`](#hadrian-test-rest) | *(none)* | Run security tests against a REST API |
| [`hadrian version`](#hadrian-version) | *(none)* | Show Hadrian version |

## `hadrian`

Hadrian - API Security Testing Framework

- Usage: `hadrian`
- Aliases: *(none)*
- Requires a subcommand

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-banner` |  | bool | `false` | Suppress the startup banner |

## `hadrian parse`

Parse API specification and show operations

- Usage: `hadrian parse <api-spec-file>`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-banner` |  | bool | `false` | Suppress the startup banner |

## `hadrian test`

Run security tests against an API

- Usage: `hadrian test`
- Aliases: *(none)*
- Requires a subcommand

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-banner` |  | bool | `false` | Suppress the startup banner |

## `hadrian test graphql`

Run security tests against a GraphQL API

- Usage: `hadrian test graphql`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--auth` |  | string |  | Authentication configuration YAML file |
| `--batch-size` |  | int | `100` | Number of queries in batch attack tests |
| `--ca-cert` |  | string |  | CA certificate for proxy |
| `--complexity-limit` |  | int | `1000` | Maximum complexity score for DoS testing |
| `--depth-limit` |  | int | `10` | Maximum query depth for DoS testing |
| `--dry-run` |  | bool | `false` | Dry run (don't execute tests) |
| `--endpoint` |  | string | `/graphql` | GraphQL endpoint path |
| `--header` | `-H` | stringArray | `[]` | Custom HTTP header (format: 'Key: Value', can specify multiple) |
| `--insecure` |  | bool | `false` | Skip TLS verification |
| `--llm-context` |  | string |  | Additional context for LLM triage |
| `--llm-host` |  | string |  | LLM service host for finding triage |
| `--llm-model` |  | string |  | LLM model name for triage |
| `--llm-provider` |  | string | `ollama` | LLM provider for triage: ollama, openai, anthropic |
| `--llm-timeout` |  | int | `180` | LLM request timeout (seconds) |
| `--output` |  | string | `terminal` | Output format: terminal, json, markdown, sarif |
| `--output-file` |  | string |  | Output file path |
| `--proxy` |  | string |  | HTTP/HTTPS proxy URL |
| `--rate-limit` |  | float64 | `5` | Rate limit (req/s) |
| `--rate-limit-backoff` |  | string | `exponential` | Rate limit backoff strategy: exponential, fixed |
| `--rate-limit-max-retries` |  | int | `5` | Maximum retry attempts on rate limit |
| `--rate-limit-max-wait` |  | duration | `1m0s` | Maximum backoff wait time |
| `--rate-limit-status-codes` |  | intSlice | `[429,503]` | HTTP status codes that trigger rate limiting |
| `--request-ids-limit` |  | int | `1` | Limit request IDs in output (0 = show all) |
| `--roles` |  | string |  | Roles and permissions YAML file |
| `--schema` |  | string |  | GraphQL SDL schema file (uses introspection if not provided) |
| `--skip-builtin-checks` |  | bool | `false` | Skip built-in security checks (introspection, depth limit, batching) |
| `--target` |  | string |  | Target base URL (e.g., https://api.example.com) |
| `--template` |  | stringSlice | `[]` | Filter templates by ID (can specify multiple) |
| `--template-dir` |  | string |  | GraphQL templates directory (default: $HADRIAN_TEMPLATES or ./templates/graphql) |
| `--timeout` |  | int | `30` | Request timeout in seconds |
| `--verbose` |  | bool | `false` | Verbose output |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-banner` |  | bool | `false` | Suppress the startup banner |

## `hadrian test grpc`

Run security tests against a gRPC API

- Usage: `hadrian test grpc`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--auth` |  | string |  | Authentication configuration YAML file |
| `--dry-run` |  | bool | `false` | Dry run (don't execute tests) |
| `--header` | `-H` | stringArray | `[]` | Custom HTTP header (format: 'Key: Value', can specify multiple) |
| `--insecure` |  | bool | `false` | Skip TLS verification |
| `--output` |  | string | `terminal` | Output format: terminal, json, markdown, sarif |
| `--output-file` |  | string |  | Output file path |
| `--plaintext` |  | bool | `false` | Use plaintext connection (no TLS) |
| `--proto` |  | string |  | Proto file path (uses reflection if not provided) |
| `--proxy` |  | string |  | HTTP/HTTPS proxy URL |
| `--rate-limit` |  | float64 | `5` | Rate limit (req/s) |
| `--reflection` |  | bool | `false` | Use server reflection to discover service definition |
| `--roles` |  | string |  | Roles and permissions YAML file |
| `--target` |  | string |  | Target gRPC server address (e.g., localhost:50051) |
| `--template` |  | stringSlice | `[]` | Filter templates by ID or name (can specify multiple) |
| `--template-dir` |  | string |  | gRPC templates directory (default: $HADRIAN_TEMPLATES or ./templates/grpc) |
| `--timeout` |  | int | `30` | Request timeout in seconds |
| `--tls-ca-cert` |  | string |  | Custom CA certificate for TLS |
| `--verbose` |  | bool | `false` | Verbose output |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-banner` |  | bool | `false` | Suppress the startup banner |

## `hadrian test rest`

Run security tests against a REST API

- Usage: `hadrian test rest`
- Aliases: *(none)*

### Flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--api` |  | string |  | API specification (OpenAPI, Swagger, Postman) |
| `--audit-log` |  | string | `.hadrian/audit.log` | Audit log file |
| `--auth` |  | string |  | Authentication configuration YAML file |
| `--ca-cert` |  | string |  | CA certificate for proxy (Burp Suite) |
| `--category` |  | stringSlice | `[owasp]` | Filter by template metadata — exact match against info.category and info.tags (case-insensitive, default: owasp) |
| `--dry-run` |  | bool | `false` | Show what would be tested without making requests |
| `--header` | `-H` | stringArray | `[]` | Custom HTTP header (format: 'Key: Value', can specify multiple) |
| `--insecure` |  | bool | `false` | Skip TLS verification (use with proxies) |
| `--llm-context` |  | string |  | Additional context for LLM analysis (e.g., 'This API handles financial data') |
| `--llm-host` |  | string |  | LLM provider host URL (e.g., http://localhost:11434 for Ollama) |
| `--llm-model` |  | string |  | LLM model name (e.g., llama3.2:latest) |
| `--llm-provider` |  | string | `ollama` | LLM provider for triage: ollama, openai, anthropic |
| `--llm-timeout` |  | int | `180` | LLM request timeout in seconds |
| `--output` |  | string | `terminal` | Output format: terminal, json, markdown, sarif |
| `--output-file` |  | string |  | Write findings to file |
| `--planner` |  | bool | `false` | Enable LLM-assisted attack planning (experimental) |
| `--planner-context` |  | string |  | Additional context for the planner (e.g., 'Focus on payment endpoints, this is a fintech API') |
| `--planner-model` |  | string |  | LLM model for planner (default: gpt-4o for openai, claude-sonnet-4-20250514 for anthropic) |
| `--planner-only` |  | bool | `false` | Run ONLY the LLM-planned steps, skip brute-force (requires --planner) |
| `--planner-provider` |  | string | `openai` | LLM provider for planner: openai, anthropic, ollama |
| `--planner-timeout` |  | int | `120` | Planner LLM request timeout in seconds |
| `--proxy` |  | string |  | HTTP/HTTPS proxy URL (e.g., http://localhost:8080) |
| `--rate-limit` |  | float64 | `5` | Global rate limit (req/s) |
| `--rate-limit-backoff` |  | string | `exponential` | Backoff type for rate limit retries: exponential, fixed |
| `--rate-limit-max-retries` |  | int | `5` | Maximum retry attempts on rate limit response |
| `--rate-limit-max-wait` |  | duration | `1m0s` | Maximum backoff wait time on rate limit |
| `--rate-limit-status-codes` |  | intSlice | `[429,503]` | Status codes that trigger rate limit retry |
| `--request-ids` |  | int | `1` | Number of request IDs to display per finding (0 = all) |
| `--roles` |  | string |  | Roles and permissions YAML file |
| `--template` |  | stringSlice | `[]` | Filter templates by ID or name (can specify multiple) |
| `--template-dir` |  | string |  | Directory containing test templates (default: $HADRIAN_TEMPLATES or ./templates/rest) |
| `--timeout` |  | int | `30` | Request timeout (seconds) |
| `--verbose` | `-v` | bool | `false` | Enable verbose logging output |

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-banner` |  | bool | `false` | Suppress the startup banner |

## `hadrian version`

Show Hadrian version

- Usage: `hadrian version`
- Aliases: *(none)*

### Inherited flags

| Flag | Short | Type | Default | Description |
| --- | --- | --- | --- | --- |
| `--no-banner` |  | bool | `false` | Suppress the startup banner |
