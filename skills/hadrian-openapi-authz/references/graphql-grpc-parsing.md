# GraphQL SDL and gRPC Proto Parsing Reference

## GraphQL SDL Schema Parsing

Hadrian loads GraphQL schemas via `LoadSchemaFromFile()` which parses SDL (Schema Definition Language) files.

### Extracting Operations

From the SDL schema, extract:

**Queries** (read operations):
```graphql
type Query {
  getUser(id: ID!): User           # → object: users, BOLA target (id arg)
  listOrders: [Order]              # → object: orders, collection
  searchProducts(term: String): [Product]  # → object: products
}
```

**Mutations** (write operations):
```graphql
type Mutation {
  createUser(input: CreateUserInput!): User    # → object: users, write
  updateOrder(id: ID!, input: OrderInput): Order  # → object: orders, BOLA target
  deleteProduct(id: ID!): Boolean              # → object: products, BOLA target
}
```

### Mapping to Hadrian Objects

| GraphQL Element | Hadrian Mapping |
|----------------|-----------------|
| Query field return type | `object` name (lowercase, pluralized) |
| Mutation field return type | `object` name |
| `ID!` argument | `owner_field` candidate for BOLA |
| Field with no ID arg | Collection endpoint (no owner_field) |

### GraphQL to Permission Mapping

| GraphQL Operation | Hadrian Permission |
|------------------|-------------------|
| Query (read) | `read:<object>:<scope>` |
| Mutation (create) | `write:<object>:<scope>` |
| Mutation (update) | `write:<object>:<scope>` |
| Mutation (delete) | `delete:<object>:<scope>` |

### Endpoint Mapping for GraphQL

For GraphQL, endpoints represent individual operations rather than URL paths:

```yaml
endpoints:
  - path: "query.getUser"
    object: users
    owner_field: id          # From the ID! argument
  - path: "query.listOrders"
    object: orders
  - path: "mutation.createUser"
    object: users
  - path: "mutation.updateOrder"
    object: orders
    owner_field: id
  - path: "mutation.deleteProduct"
    object: products
    owner_field: id
```

### Role Inference from GraphQL

GraphQL schemas may include custom directives that indicate access control:

```graphql
type Query {
  adminDashboard: Dashboard @auth(requires: ADMIN)
  myProfile: User @auth(requires: USER)
  publicInfo: Info  # No @auth → possibly public
}
```

Look for:
- `@auth`, `@authorized`, `@hasRole` directives → explicit role requirements
- `admin` prefix in operation names → admin-level operations
- Operations returning sensitive types (e.g., `AllUsers`, `SystemConfig`) → likely admin
- Operations with no auth directives alongside others that have them → possibly public

---

## gRPC Proto File Parsing

Hadrian parses proto files to discover gRPC services and methods.

### Extracting Services and Methods

From the proto file:

```protobuf
syntax = "proto3";
package myapi;

service UserService {
  rpc GetUser (GetUserRequest) returns (User);           // Read, BOLA target
  rpc ListUsers (ListUsersRequest) returns (UserList);   // Read, collection
  rpc CreateUser (CreateUserRequest) returns (User);     // Write
  rpc DeleteUser (DeleteUserRequest) returns (Empty);    // Delete, BOLA target
}

service AdminService {
  rpc GetAllUsers (Empty) returns (UserList);            // Admin read
  rpc UpdateConfig (ConfigRequest) returns (Config);     // Admin write
}

message GetUserRequest {
  string user_id = 1;    // BOLA target field
}
```

### Mapping to Hadrian Objects

| Proto Element | Hadrian Mapping |
|--------------|-----------------|
| Service name | Object group (e.g., `UserService` → `users`) |
| RPC method name | Operation within object |
| Request message ID fields | `owner_field` candidate |
| `AdminService` prefix | Admin-level operations |

### gRPC to Permission Mapping

| RPC Method Pattern | Hadrian Permission |
|-------------------|-------------------|
| `Get*`, `List*`, `Search*` | `read:<object>:<scope>` |
| `Create*`, `Add*`, `Update*`, `Set*` | `write:<object>:<scope>` |
| `Delete*`, `Remove*` | `delete:<object>:<scope>` |
| `Execute*`, `Run*`, `Trigger*` | `execute:<object>:<scope>` |

### Endpoint Mapping for gRPC

For gRPC, endpoints use the fully qualified method path:

```yaml
endpoints:
  - path: "/myapi.UserService/GetUser"
    object: users
    owner_field: user_id       # From GetUserRequest.user_id
  - path: "/myapi.UserService/ListUsers"
    object: users
  - path: "/myapi.UserService/CreateUser"
    object: users
  - path: "/myapi.UserService/DeleteUser"
    object: users
    owner_field: user_id
  - path: "/myapi.AdminService/GetAllUsers"
    object: users
  - path: "/myapi.AdminService/UpdateConfig"
    object: config
```

### Role Inference from gRPC

Proto files rarely include auth metadata, but infer roles from:
- **Service naming**: `AdminService`, `InternalService` → admin roles
- **Method naming**: `adminGetUsers`, `internalSync` → admin-level
- **Service separation**: Separate admin vs user services → different access levels
- **Comments/documentation**: `// Admin only`, `// Requires authentication`

---

## Auth Configuration (Shared)

Both GraphQL and gRPC use the same `auth.yaml` format as REST. The auth method is typically:

| API Type | Common Auth | Hadrian Method |
|----------|-------------|----------------|
| GraphQL | Bearer token in Authorization header | `bearer` |
| GraphQL | API key in custom header | `api_key` |
| GraphQL | Cookie-based session | `cookie` |
| gRPC | Bearer token in metadata | `bearer` |
| gRPC | API key in metadata | `api_key` |
| gRPC | mTLS (certificate-based) | Not directly supported — use `no_auth` |
