# Node.js/Pug Vulnerable SSTI Environment

A deliberately vulnerable Express application using Pug templates for testing SSTI detection tools.

## Build

```bash
docker build -t ssti-pug .
```

## Run

```bash
docker run --rm -p 3000:3000 ssti-pug
```

The application will be available at `http://localhost:3000`

## Test Endpoints

### GET /greet

Vulnerable to SSTI via query parameter `name`:

```bash
# Basic test
curl "http://localhost:3000/greet?name=%23%7B7*7%7D"
# Note: #{7*7} URL-encoded as %23%7B7*7%7D
# Expected: <p>Hello, 49!</p>

# Verification test (1337)
curl "http://localhost:3000/greet?name=%23%7B7*191%7D"
# Expected: <p>Hello, 1337!</p>
```

### POST /render

Vulnerable to SSTI via form body parameter `template`:

```bash
curl -X POST -d "template=p Result: #{7*7}" http://localhost:3000/render
# Expected: <p>Result: 49</p>
```

## Testing with ssti-test

```bash
# From hadrian-api-tester directory
./ssti-test -target "http://localhost:3000/greet" -param "name" -method GET -payloads payloads/ssti/pug.yaml

# Or test POST endpoint
./ssti-test -target "http://localhost:3000/render" -param "template" -method POST -payloads payloads/ssti/pug.yaml
```

## Stop

Press `Ctrl+C` to stop the container. The `--rm` flag ensures the container is automatically removed.
