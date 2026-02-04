# Vulnerable SSTI Test Environments

Docker containers with intentionally vulnerable applications for testing the SSTI detection tool.

**WARNING: These containers are deliberately vulnerable. Never expose them to untrusted networks or use in production.**

## Available Environments

| Directory | Language | Template Engine | Port |
|-----------|----------|-----------------|------|
| `python-jinja2/` | Python | Jinja2 (Flask) | 5000 |
| `nodejs-pug/` | Node.js | Pug (Express) | 3000 |

## Quick Start

### Build All

```bash
cd vulnerable-environments
docker build -t ssti-jinja2 python-jinja2/
docker build -t ssti-pug nodejs-pug/
```

### Run

```bash
# Run Jinja2 environment
docker run --rm -p 5000:5000 ssti-jinja2

# Run Pug environment (in another terminal)
docker run --rm -p 3000:3000 ssti-pug
```

### Test with ssti-test

```bash
# Test Jinja2 (Python)
./ssti-test -target "http://localhost:5000/greet" -param "name" -method GET

# Test Pug (Node.js)
./ssti-test -target "http://localhost:3000/greet" -param "name" -method GET -payloads payloads/ssti/pug.yaml
```

## Adding New Environments

To add a new vulnerable environment:

1. Create a directory named `{language}-{engine}/` (e.g., `php-smarty/`)
2. Create a single `Dockerfile` that builds and runs the vulnerable app
3. Create a `README.md` with build/run instructions
4. Expose a predictable port
5. Implement at minimum:
   - `GET /greet?name=PAYLOAD` - Query parameter injection
   - `POST /render` with `template` body param - Body injection

## Security Notice

These environments are for authorized security testing only. By using these containers, you agree to:

- Only run them on isolated networks
- Never expose them to the internet
- Use them solely for testing SSTI detection tools
- Delete them when testing is complete
