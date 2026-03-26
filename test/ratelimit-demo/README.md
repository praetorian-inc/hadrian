# Rate Limit Demo Server

A Go web application demonstrating various rate limiting patterns for testing Hadrian's rate limit detection capabilities.

## Quick Start

```bash
# Build the server
cd /workspaces/praetorian-dev/modules/hadrian/test/ratelimit-demo
go build -o ratelimit-demo .

# Start the server
./ratelimit-demo

# In another terminal, test an endpoint
curl http://localhost:8080/api/v1/status-429/resource

# Run 6 times to see rate limiting
for i in {1..6}; do curl http://localhost:8080/api/v1/status-429/resource; echo; done
```

## Server Options

```bash
./ratelimit-demo [flags]

Flags:
  -port int              Server port (default 8080)
  -default-limit int     Default rate limit (default 5)
  -default-window duration Default time window (default 60s)
```

## Endpoints

### Baseline (No Rate Limit)

| Endpoint | Description | Rate Limit |
|----------|-------------|------------|
| `GET /api/v1/basic/resource` | Baseline endpoint | **None** (always 200) |

**Example:**
```bash
# Make 100 requests - all succeed
for i in {1..100}; do curl -s http://localhost:8080/api/v1/basic/resource | jq -r .status; done
```

### Status Code Patterns

| Endpoint | Description | Response When Limited |
|----------|-------------|----------------------|
| `GET /api/v1/status-429/resource` | Returns 429 after limit | `429 Too Many Requests` |
| `GET /api/v1/status-503/resource` | Returns 503 after limit | `503 Service Unavailable` |

**Example:**
```bash
# Exhaust limit (5 requests), then get 429
for i in {1..6}; do
  curl -s -w "\nHTTP Status: %{http_code}\n" http://localhost:8080/api/v1/status-429/resource
done
```

### Retry-After Patterns

| Endpoint | Description | Retry-After Format |
|----------|-------------|-------------------|
| `GET /api/v1/retry-seconds/resource` | Returns Retry-After in seconds | `Retry-After: 5` |
| `GET /api/v1/retry-date/resource` | Returns Retry-After as HTTP-date | `Retry-After: Fri, 31 Jan 2026 12:00:05 GMT` |

**Example:**
```bash
# Exhaust limit, see Retry-After header
for i in {1..6}; do
  curl -i http://localhost:8080/api/v1/retry-seconds/resource 2>&1 | grep -E "(HTTP/|Retry-After:)"
done
```

### X-RateLimit Headers

| Endpoint | Description | Headers Included |
|----------|-------------|-----------------|
| `GET /api/v1/ratelimit-headers/resource` | Returns standard rate limit headers | `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset` |

**Example:**
```bash
# See rate limit headers on each request
for i in {1..6}; do
  echo "Request $i:"
  curl -i http://localhost:8080/api/v1/ratelimit-headers/resource 2>&1 | \
    grep -E "(X-RateLimit-|HTTP/)"
done
```

### Response Body Patterns

| Endpoint | Description | Content-Type | Body Format |
|----------|-------------|--------------|-------------|
| `GET /api/v1/body-plain/resource` | Plain text error | `text/plain` | `Too Many Requests` |
| `GET /api/v1/body-json/resource` | JSON error | `application/json` | `{"error": "rate_limit_exceeded"}` |
| `GET /api/v1/body-json-retry/resource` | JSON with retry info | `application/json` | `{"error": "...", "retry_after": 5, "message": "..."}` |

**Example:**
```bash
# See JSON error response
for i in {1..6}; do
  curl -s http://localhost:8080/api/v1/body-json-retry/resource | jq .
done
```

### Scoping Patterns

| Endpoint | Description | Counter Scope |
|----------|-------------|--------------|
| `GET /api/v1/global/resource` | Shared counter | All `/global/*` endpoints share one counter |
| `GET /api/v1/global/other` | Shared counter | Same counter as `/global/resource` |
| `GET /api/v1/per-endpoint/one` | Independent counter | Each endpoint has its own counter |
| `GET /api/v1/per-endpoint/two` | Independent counter | Separate from `/per-endpoint/one` |
| `GET /api/v1/per-ip/resource` | Per-IP counter | Each client IP has independent counter |

**Example (Global Shared Counter):**
```bash
# Make 3 requests to /global/resource and 3 to /global/other
# The 6th request (to either) will be rate limited
for i in {1..3}; do curl -s http://localhost:8080/api/v1/global/resource?limit=5 | jq -r .status; done
for i in {1..3}; do curl -s http://localhost:8080/api/v1/global/other?limit=5 | jq -r .status; done
```

**Example (Per-Endpoint Independent):**
```bash
# Exhaust /per-endpoint/one (5 requests)
for i in {1..5}; do curl -s http://localhost:8080/api/v1/per-endpoint/one | jq -r .status; done

# /per-endpoint/two still works (independent counter)
curl -s http://localhost:8080/api/v1/per-endpoint/two | jq -r .status  # Returns "ok"
```

## Query Parameters

All rate-limited endpoints support:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 5 | Number of requests allowed before rate limiting |
| `window` | int | 60 | Time window in seconds before counter resets |

**Example:**
```bash
# Custom limit of 3 requests with 10-second window
curl "http://localhost:8080/api/v1/status-429/resource?limit=3&window=10"

# After 3 requests, wait 10 seconds for reset
for i in {1..4}; do
  curl -s "http://localhost:8080/api/v1/status-429/resource?limit=3&window=10"
  echo
done
sleep 10
curl -s "http://localhost:8080/api/v1/status-429/resource?limit=3&window=10"  # Works again
```

## Testing with Hadrian

### Run Hadrian Against Demo Server

```bash
# Start the demo server
cd /workspaces/praetorian-dev/modules/hadrian/test/ratelimit-demo
./ratelimit-demo &

# Run Hadrian with rate limit templates
cd /workspaces/praetorian-dev/modules/hadrian
HADRIAN_TEMPLATES=test/ratelimit-demo/templates ./hadrian test \
  --api test/ratelimit-demo/openapi.yaml \
  --roles test/ratelimit-demo/roles.yaml \
  --verbose

# Stop the server
kill %1
```

### Expected Hadrian Findings

| Template | Endpoint Pattern | Expected Result |
|----------|-----------------|----------------|
| `01-detect-429.yaml` | `/status-429/*` | ✅ Detects 429 rate limiting |
| `02-detect-503.yaml` | `/status-503/*` | ✅ Detects 503 rate limiting |
| `03-detect-no-limit.yaml` | `/basic/*` | ⚠️ **Vulnerability**: No rate limit detected |
| `04-detect-retry-after.yaml` | `/retry-*/*` | ℹ️ Info: Retry-After header present |

### Hadrian --rate-limit Flag Interaction

Hadrian's `--rate-limit` flag controls **client-side request pacing** to avoid overwhelming the target:

```bash
# Hadrian sends requests at 10 req/s (prevents client from being rate limited)
./hadrian test --api openapi.yaml --rate-limit 10

# Server-side rate limiting (what we're testing) is independent
# The demo server still enforces its own limits (default: 5 req/60s per endpoint)
```

**Key difference:**
- **Hadrian `--rate-limit`**: Client-side throttling (how fast Hadrian sends requests)
- **Demo server limits**: Server-side enforcement (what the server allows)

## Implementation Details

### Rate Limiter Algorithm

The server uses a **fixed window counter** algorithm:

```go
type Counter struct {
    count     int           // Current request count
    windowEnd time.Time     // When counter resets
    limit     int           // Maximum requests allowed
    window    time.Duration // Window duration
}
```

**Behavior:**
1. First request creates a counter with `windowEnd = now + window`
2. Subsequent requests increment the counter
3. When `count >= limit`, requests are denied (429/503)
4. When `now > windowEnd`, counter resets

### Thread Safety

All rate limiter operations are protected by `sync.RWMutex` for concurrent access.

### Key Generation

Rate limit keys determine counter scope:

```go
// Endpoint-specific
key := "status-429:" + r.URL.Path  // Independent per endpoint

// Global shared
key := "global-shared"  // All /global/* share one counter

// Per-IP
key := "per-ip:" + clientIP  // Independent per client
```

## Testing the Implementation

```bash
# Run unit tests
cd /workspaces/praetorian-dev/modules/hadrian/test/ratelimit-demo
GOWORK=off go test -v

# Run specific test
GOWORK=off go test -v -run TestStatus429Handler

# Run with race detection
GOWORK=off go test -race -v
```

## Files

```
ratelimit-demo/
├── main.go                          # Server entry point, CLI flags
├── handlers.go                      # HTTP handlers for all endpoints
├── limiter.go                       # In-memory rate limiter
├── limiter_test.go                  # Rate limiter unit tests
├── handlers_test.go                 # HTTP handler tests
├── openapi.yaml                     # OpenAPI 3.0 spec
├── roles.yaml                       # Minimal roles config
├── templates/ratelimit/             # Hadrian test templates
│   ├── 01-detect-429.yaml              # Detect 429 rate limiting
│   ├── 02-detect-503.yaml              # Detect 503 rate limiting
│   ├── 03-detect-no-limit.yaml         # Detect missing rate limits
│   └── 04-detect-retry-after.yaml      # Detect Retry-After headers
└── README.md                        # This file
```

## Common Scenarios

### Scenario 1: Testing Rate Limit Detection

**Goal:** Verify Hadrian detects rate limits correctly

```bash
# Start server
./ratelimit-demo &

# Test with Hadrian
HADRIAN_TEMPLATES=templates ./hadrian test \
  --api openapi.yaml \
  --roles roles.yaml

# Should find:
# - LOW severity: Rate limits detected on /status-429/* and /status-503/*
# - MEDIUM severity: No rate limit on /basic/* (vulnerability)
```

### Scenario 2: Testing Custom Limits

**Goal:** Test with different rate limit thresholds

```bash
# Start server with custom defaults
./ratelimit-demo --default-limit 10 --default-window 30s &

# Manual testing with custom limits
curl "http://localhost:8080/api/v1/status-429/resource?limit=2&window=5"
```

### Scenario 3: Testing Per-IP Limits

**Goal:** Verify IP-based rate limiting

```bash
# Simulate different IPs using X-Forwarded-For header
for i in {1..6}; do
  curl -H "X-Forwarded-For: 192.168.1.1" \
    http://localhost:8080/api/v1/per-ip/resource
done  # IP 192.168.1.1 gets rate limited

curl -H "X-Forwarded-For: 192.168.1.2" \
  http://localhost:8080/api/v1/per-ip/resource  # IP 192.168.1.2 works
```

## Troubleshooting

### Server Won't Start

```bash
# Check if port is already in use
lsof -i :8080

# Use different port
./ratelimit-demo --port 9090
```

### Rate Limits Not Working

```bash
# Check server logs - they show each request
./ratelimit-demo
# Output: [15:04:05] GET /api/v1/status-429/resource -> 200 (1.23ms)

# Verify query parameters are being passed
curl -v "http://localhost:8080/api/v1/status-429/resource?limit=3"
```

### Hadrian Not Detecting Limits

```bash
# Check template directory is correct
ls templates/ratelimit/  # Should show *.yaml files
```

## Architecture Notes

### Why Fixed Window?

Fixed window counters are simple and performant but have edge cases:

**Burst at window boundary:**
```
Window 1: [55s] 5 requests → Reset at 60s
Window 2: [1s]  5 requests → 10 requests in 6 seconds
```

For production, consider:
- **Sliding window**: More accurate but more complex
- **Token bucket**: Allows bursts with gradual refill
- **Leaky bucket**: Smooth rate limiting

This demo uses fixed window for **simplicity and clarity** in testing.

### Rate Limit Key Design

The key structure determines counter scope:

```go
// Pattern: <type>:<identifier>
"status-429:/api/v1/status-429/resource"  // Per-endpoint
"global-shared"                            // Global shared
"per-ip:192.168.1.1"                       // Per-IP
```

This allows flexible rate limiting strategies in a single implementation.

## Future Enhancements

- [ ] Add sliding window algorithm
- [ ] Add token bucket algorithm
- [ ] Persist counters to Redis
- [ ] Add distributed rate limiting
- [ ] Add rate limit analytics endpoint
- [ ] Add WebSocket support
- [ ] Add GraphQL endpoint examples
