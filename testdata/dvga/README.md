# DVGA Test Setup

DVGA (Damn Vulnerable GraphQL Application) is an intentionally vulnerable GraphQL API for testing security tools.

## Quick Start

### 1. Start DVGA

```bash
cd testdata/dvga
docker-compose up -d
```

DVGA will be available at `http://localhost:5013/graphql`

### 2. Create Test Users and Obtain Tokens

Access the DVGA UI at `http://localhost:5013` to create users or use the GraphQL API:

**Create Admin User (if needed):**
```graphql
mutation {
  createUser(username: "admin", password: "password") {
    username
  }
}
```

**Login to Get Token:**
```graphql
mutation {
  login(username: "admin", password: "password") {
    accessToken
  }
}
```

**Set Environment Variables:**
```bash
export DVGA_ADMIN_TOKEN="<access_token_from_login>"
export DVGA_OPERATOR_TOKEN="<operator_access_token>"
export DVGA_USER_TOKEN="<user_access_token>"
```

### 3. Run Hadrian Tests

```bash
# Set the endpoint
export DVGA_ENDPOINT="http://localhost:5013/graphql"

# Run integration tests (requires DVGA running)
GOWORK=off go test -tags=integration ./pkg/plugins/graphql/...
```

## Available GraphQL Operations

### Queries

- `users` - List all users (requires authentication)
- `user(id: Int!)` - Get specific user
- `pastes` - List all pastes
- `paste(id: Int!)` - Get specific paste
- `systemHealth` - System health status

### Mutations

- `createPaste(title: String!, content: String!)` - Create a paste
- `editPaste(id: Int!, title: String, content: String)` - Edit a paste
- `deletePaste(id: Int!)` - Delete a paste
- `createUser(username: String!, password: String!)` - Create user
- `login(username: String!, password: String!)` - Login and get token

### Example Introspection Query

```graphql
query IntrospectionQuery {
  __schema {
    queryType {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    mutationType {
      name
      fields {
        name
      }
    }
  }
}
```

## Known Vulnerabilities (For Testing)

DVGA contains intentional vulnerabilities that Hadrian should detect:

1. **Introspection Enabled** - Schema disclosure
2. **No Query Depth Limiting** - Allows deeply nested queries
3. **No Rate Limiting** - Allows query flooding
4. **Injection Vulnerabilities** - SQL injection in some resolvers
5. **Broken Authentication** - Weak session management
6. **Broken Authorization** - IDOR vulnerabilities
7. **Information Disclosure** - Verbose error messages

## Test Configuration Files

- `dvga-roles.yaml` - Role definitions and permissions for BOLA testing
- `dvga-auth.yaml` - Authentication configuration for Hadrian
- `docker-compose.yaml` - Docker setup for DVGA

## Troubleshooting

### Port Already in Use

```bash
# Stop DVGA
docker-compose down

# Check what's using port 5013
lsof -i :5013

# Kill the process or change the port in docker-compose.yaml
```

### DVGA Not Responding

```bash
# Check container logs
docker-compose logs dvga

# Restart container
docker-compose restart dvga
```

### Token Expired

Tokens expire after a period. Re-login to get a new token:

```graphql
mutation {
  login(username: "admin", password: "password") {
    accessToken
  }
}
```

## References

- DVGA GitHub: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
- GraphQL Introspection: https://graphql.org/learn/introspection/
- Hadrian GraphQL Plugin: `../../pkg/plugins/graphql/`
