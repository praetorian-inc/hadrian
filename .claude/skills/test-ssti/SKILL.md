---
name: test-ssti
description: Test the SSTI injection tool against vulnerable Docker environments
allowed-tools: "Read, Write, Bash, Grep, Glob"
---

# Test SSTI Injection Tool

Run and test the SSTI injection detection tool against vulnerable Docker environments.

## Working Directory

All commands should be run from: `hadrian-api-tester/`

```bash
cd /Users/gianluigidaltoso/Projects/hadrian/hadrian-api-tester
```

## Available Vulnerable Environments

| Directory | Engine | Port | Target URL | Parameter |
|-----------|--------|------|------------|-----------|
| `vulnerable-environments/ssti/python-jinja2/` | Jinja2 | 5000 | `http://localhost:5000/greet` | `name` |
| `vulnerable-environments/ssti/nodejs-pug/` | Pug | 3000 | `http://localhost:3000/greet` | `name` |

Each environment also exposes a POST `/render` endpoint with `template` parameter.

## Setup Steps

### 1. Check Docker availability

```bash
docker --version
```

### 2. Build vulnerable environments

```bash
docker build -t ssti-jinja2 vulnerable-environments/ssti/python-jinja2/
docker build -t ssti-pug vulnerable-environments/ssti/nodejs-pug/
```

### 3. Start containers

Start in background with port mapping. Use unique container names to manage them:

```bash
# Start Jinja2 environment
docker run -d --name ssti-jinja2-test -p 5000:5000 ssti-jinja2

# Start Pug environment
docker run -d --name ssti-pug-test -p 3000:3000 ssti-pug
```

### 4. Wait for containers to be ready

```bash
# Wait for Jinja2
for i in {1..10}; do curl -s http://localhost:5000/ > /dev/null && break || sleep 1; done

# Wait for Pug
for i in {1..10}; do curl -s http://localhost:3000/ > /dev/null && break || sleep 1; done
```

## Run SSTI Tests

### Basic Tests (Multi-pass verification mode)

```bash
# Test Jinja2 with default payloads
go run cmd/ssti-test/main.go -target "http://localhost:5000/greet" -param "name" -method GET

# Test Pug with specific payloads
go run cmd/ssti-test/main.go -target "http://localhost:3000/greet" -param "name" -method GET -payloads payloads/ssti/pug.yaml
```

### Fingerprinting Mode Tests

```bash
# Test Jinja2 with fingerprinting
go run cmd/ssti-test/main.go -target "http://localhost:5000/greet" -param "name" -method GET -fingerprint

# Test Pug with fingerprinting
go run cmd/ssti-test/main.go -target "http://localhost:3000/greet" -param "name" -method GET -fingerprint
```

### POST Endpoint Tests

```bash
# Test Jinja2 POST endpoint
go run cmd/ssti-test/main.go -target "http://localhost:5000/render" -param "template" -method POST

# Test Pug POST endpoint
go run cmd/ssti-test/main.go -target "http://localhost:3000/render" -param "template" -method POST -payloads payloads/ssti/pug.yaml
```

### Verbose Mode

Add `-verbose` flag to see all payloads being tested:

```bash
go run cmd/ssti-test/main.go -target "http://localhost:5000/greet" -param "name" -method GET -verbose
```

## Expected Results

### For Jinja2 (Python Flask)

The tool should:
- Detect Jinja2 engine as **CONFIRMED**
- Pass all 3 verification passes (1337, 481, 1513)
- In fingerprint mode: identify as `python-like` family first

### For Pug (Node.js Express)

The tool should:
- Detect Pug engine as **CONFIRMED** when using pug.yaml payloads
- Pass all 3 verification passes (1337, 481, 1513)
- In fingerprint mode: identify as `javascript-like` family first

## Edge Cases to Test

### 1. Wrong payload file for engine

Test what happens when using wrong payloads:

```bash
# Using Jinja2 payloads against Pug (should NOT detect)
go run cmd/ssti-test/main.go -target "http://localhost:3000/greet" -param "name" -method GET -payloads payloads/ssti/jinja2.yaml

# Using Pug payloads against Jinja2 (should NOT detect)
go run cmd/ssti-test/main.go -target "http://localhost:5000/greet" -param "name" -method GET -payloads payloads/ssti/pug.yaml
```

**Expected**: Should show "NOT VULNERABLE" or "NOT FOUND" since syntax differs.

### 2. Non-vulnerable endpoint

```bash
# Test against root endpoint (not vulnerable to parameter injection)
go run cmd/ssti-test/main.go -target "http://localhost:5000/" -param "name" -method GET
```

**Expected**: Should show "No vulnerabilities detected".

### 3. Invalid parameter name

```bash
# Test with non-existent parameter
go run cmd/ssti-test/main.go -target "http://localhost:5000/greet" -param "invalid_param" -method GET
```

**Expected**: Should show "NOT VULNERABLE" for all engines.

### 4. Connection refused (no server)

```bash
# Test against non-running server
go run cmd/ssti-test/main.go -target "http://localhost:9999/greet" -param "name" -method GET
```

**Expected**: Should handle error gracefully without crashing.

### 5. Multiple payload files

```bash
# Test with multiple payload files
go run cmd/ssti-test/main.go -target "http://localhost:5000/greet" -param "name" -method GET -payloads "payloads/ssti/jinja2.yaml,payloads/ssti/mako.yaml"
```

### 6. Invalid URL format

```bash
# Missing protocol
go run cmd/ssti-test/main.go -target "localhost:5000/greet" -param "name" -method GET
```

**Expected**: Should provide clear error message.

### 7. Missing required flags

```bash
# Missing target
go run cmd/ssti-test/main.go -param "name" -method GET
```

**Expected**: Should display error "-target is required".

## Cleanup

After testing, stop and remove the containers:

```bash
docker stop ssti-jinja2-test ssti-pug-test 2>/dev/null
docker rm ssti-jinja2-test ssti-pug-test 2>/dev/null
```

## Output Analysis

When analyzing test output, verify:

1. **Correct engine detection**: The tool identifies the correct template engine
2. **Pass count accuracy**: All verification passes should succeed for vulnerable endpoints
3. **False positives**: Wrong payload files should NOT produce false confirmations
4. **Error handling**: Invalid inputs should produce helpful error messages
5. **Request efficiency**: Fingerprint mode should use fewer requests than full scan

### Sample Expected Output (Jinja2 Confirmed)

```
[*] SSTI Scanner - Multi-pass Verification
[*] Target: http://localhost:5000/greet
[*] Parameter: name

[ENGINE: jinja2]
  Pass 1/3: {{7*191}} → "1337"... ✓ FOUND
  Pass 2/3: {{13*37}} → "481"... ✓ FOUND
  Pass 3/3: {{17*89}} → "1513"... ✓ FOUND
  Result: ✓ CONFIRMED (3/3)

[SUMMARY]
  CONFIRMED: jinja2
```

## Arguments

If the user provides additional arguments, append them to the tool command:
- `-verbose`: Show all payloads tested
- `-proxy http://127.0.0.1:8080`: Route through proxy (e.g., Burp Suite)
- `-insecure`: Skip TLS verification
- `-fingerprint`: Use fingerprinting mode

## Reporting

After running tests, report:
- Which environments were tested
- Detection results for each engine
- Any unexpected behaviors or potential bugs found
- Edge case test results
- Suggestions for improvements if issues were detected
