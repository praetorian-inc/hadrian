# SSTI Payload Files

This directory contains YAML payload files for Server-Side Template Injection (SSTI) testing.

## Structure

Each YAML file represents a collection of payloads for a specific template engine or category:

```yaml
engine: <engine-name>
payloads:
  - value: "<payload>"
    expected: "<expected-output-or-error>"
    description: "<description>"
```

## Files

- **universal.yaml**: Payloads that work across multiple template engines
  - Jinja2, Twig, Nunjucks ({{...}})
  - FreeMarker, Velocity, Pebble (${...})
  - ERB, EJS (<%= ... %>)
  - Ruby, Slim (#{...})

- **jinja2.yaml**: Jinja2-specific payloads
  - Config object access
  - Class introspection
  - Method resolution order
  - Flask globals access

- **freemarker.yaml**: FreeMarker-specific payloads
  - Variable assignment
  - Command execution attempts

- **twig.yaml**: Twig-specific payloads
  - String multiplication (Twig-specific behavior)
  - Runtime loader access

## Usage

### With ssti-test CLI:

```bash
# Use embedded default payloads
./ssti-test -target "https://example.com/" -param q

# Use custom payloads from directory
./ssti-test -target "https://example.com/" -param q -payloads ./payloads/ssti/
```

### Programmatically:

```go
// Use embedded defaults
module := ssti.NewSSTIModule()

// Load from custom directory
module, err := ssti.NewSSTIModuleWithPayloads("./payloads/ssti/")
if err != nil {
    log.Fatal(err)
}
```

## Adding New Payloads

1. Create a new YAML file or edit an existing one
2. Follow the structure shown above
3. Set appropriate engine name
4. Provide:
   - **value**: The actual payload to inject
   - **expected**: Either an exact string match or "error" for error-based detection
   - **description**: Human-readable description of what the payload does

## Detection Types

- **Exact Match**: The response contains the expected value (e.g., "49" for arithmetic tests)
- **Error-based**: The payload triggers a template error (expected: "error")

## Schema Validation

Each payload is validated to ensure it has:
- Non-empty `value`
- Non-empty `expected`
- Non-empty `engine`
- Non-empty `description`

Invalid payloads will cause loading to fail with a descriptive error message.
