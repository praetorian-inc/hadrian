# Python/Jinja2 Vulnerable SSTI Environment

A deliberately vulnerable Flask application using Jinja2 templates for testing SSTI detection tools.

## Build

```bash
docker build -t ssti-jinja2 .
```

## Run

```bash
docker run --rm -p 5000:5000 ssti-jinja2
```

The application will be available at `http://localhost:5000`

## Test Endpoints

### GET /greet

Vulnerable to SSTI via query parameter `name`:

```bash
# Basic test
curl "http://localhost:5000/greet?name={{7*7}}"
# Expected: Hello, 49!

# Verification test (1337)
curl "http://localhost:5000/greet?name={{7*191}}"
# Expected: Hello, 1337!
```

### POST /render

Vulnerable to SSTI via form body parameter `template`:

```bash
curl -X POST -d "template={{7*7}}" http://localhost:5000/render
# Expected: 49
```

## Testing with ssti-test

```bash
# From hadrian-api-tester directory
./ssti-test -target "http://localhost:5000/greet" -param "name" -method GET

# Or test POST endpoint
./ssti-test -target "http://localhost:5000/render" -param "template" -method POST
```

## Stop

Press `Ctrl+C` to stop the container. The `--rm` flag ensures the container is automatically removed.
