# SSTI Testing CLI Tool

A standalone command-line tool for testing Server-Side Template Injection (SSTI) vulnerabilities in individual web pages.

## Purpose

This tool allows security engineers to:
- Test individual web pages for SSTI vulnerabilities without needing a full OpenAPI spec
- Useful for PortSwigger labs and manual pentesting
- Inject payloads into specific parameters and detect template engine responses

## Installation

```bash
# From the hadrian-api-tester directory
go build -o ssti-test ./cmd/ssti-test/

# Or run directly
go run ./cmd/ssti-test/ [flags]
```

## Usage

```bash
# Test PortSwigger SSTI lab
./ssti-test -target "https://xxx.web-security-academy.net/" -param message

# With Burp proxy
./ssti-test -target "https://xxx.web-security-academy.net/" -param message -proxy http://127.0.0.1:8080 -insecure

# POST request with verbose output
./ssti-test -target "https://example.com/submit" -param user_input -method POST -verbose

# GET request with custom parameter
./ssti-test -target "https://example.com/search" -param q -method GET
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | *required* | Target URL to test |
| `-param` | `message` | Parameter name to inject payloads into |
| `-method` | `GET` | HTTP method (GET or POST) |
| `-proxy` | - | Proxy URL for Burp Suite (e.g., http://127.0.0.1:8080) |
| `-verbose` | `false` | Show all payloads tested |
| `-insecure` | `false` | Skip TLS verification |

## Output Example

```
[*] Target: https://xxx.web-security-academy.net/
[*] Parameter: message
[*] Testing 8 SSTI payloads...

[+] VULNERABLE! Payload: {{7*7}}
    Engine: jinja2
    Evidence: 49
    Match Type: exact

[*] Scan complete. Found 1 SSTI indicator(s).
```

## How It Works

The tool uses the existing `pkg/injection/ssti` module and:

1. Creates HTTP requests with SSTI payloads injected into the specified parameter
2. For GET requests: Injects payload in query string
3. For POST requests: Injects payload in form body (application/x-www-form-urlencoded)
4. Analyzes responses for:
   - Exact matches (e.g., `{{7*7}}` → `49`)
   - Template errors (TemplateSyntaxError, TemplateException, etc.)
5. Reports detected vulnerabilities with engine type and evidence

## Tested Payloads

The tool tests multiple template engines:
- **Universal**: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- **Jinja2**: `{{config}}`, `{{''.__class__}}`
- **FreeMarker**: `<#assign x=7*7>${x}`

See `pkg/injection/ssti/module.go` for the complete payload list.

## Testing

```bash
# Run tests
go test ./cmd/ssti-test/ -v

# Run with coverage
go test ./cmd/ssti-test/ -cover
```

## Integration with Burp Suite

Use the `-proxy` and `-insecure` flags to route traffic through Burp:

```bash
./ssti-test \
  -target "https://target.com/vulnerable" \
  -param input \
  -proxy http://127.0.0.1:8080 \
  -insecure
```

This allows you to:
- Inspect raw requests/responses in Burp
- Modify payloads manually
- Chain with other Burp tools (Scanner, Intruder, etc.)

## License

Part of the Hadrian API security testing framework.
