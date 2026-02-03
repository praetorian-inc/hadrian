# Phase 2: Triage Results

## Work Type Classification

**Work Type:** LARGE (New feature/capability)

**Classification Method:** Signal parsing from Linear ticket ENG-1172

### Signals Detected
- "Extend the API security testing framework" → New module
- "comprehensive GraphQL API security testing" → New capability
- Multiple new components: schema discovery, query construction, vulnerability testing
- CLI extensions with new flags
- New permissions matrix format
- GraphQL-specific findings format

### Scope Analysis
- **Estimated Files:** 20+ new files
- **New Packages:** pkg/graphql/, pkg/plugins/graphql/
- **Modified Packages:** pkg/runner/, cmd/hadrian/
- **New Test Files:** Multiple test files for new packages

## Phases to Execute

All 16 phases (LARGE work type):

| Phase | Name | Status |
|-------|------|--------|
| 1 | Setup | ✅ Complete |
| 2 | Triage | ✅ Complete |
| 3 | Codebase Discovery | Pending |
| 4 | Skill Discovery | Pending |
| 5 | Complexity | Pending |
| 6 | Brainstorming | Pending |
| 7 | Architecture Plan | Pending |
| 8 | Implementation | Pending |
| 9 | Design Verification | Pending |
| 10 | Domain Compliance | Pending |
| 11 | Code Quality | Pending |
| 12 | Test Planning | Pending |
| 13 | Testing | Pending |
| 14 | Coverage Verification | Pending |
| 15 | Test Quality | Pending |
| 16 | Completion | Pending |

## Checkpoints (Human Approval Required)

| Phase | Type | Description |
|-------|------|-------------|
| 6 | Human approval | Design review (brainstorming output) |
| 7 | Human approval | Architecture plan review |
| 8 | Human approval | Implementation review |
| 16 | Human approval | Completion review |

## Key Requirements from Ticket

### Must Implement
1. **GraphQL-Specific Vulnerability Testing**
   - Introspection disclosure detection
   - Query depth attacks (DoS)
   - Query complexity attacks
   - Batching attacks via aliasing
   - Field suggestion exploitation
   - Directive injection
   - Fragment-based attacks

2. **Authorization Testing Adaptations**
   - Field-level authorization
   - Type-level access control
   - Resolver permission boundaries
   - Nested query authorization
   - Mutation/subscription authorization

3. **Query Construction Engine**
   - Schema-based query generation
   - Mutation payload construction
   - Variable manipulation
   - Fragment construction
   - Alias generation for batching

4. **CLI Extensions**
   - `--graphql` flag for GraphQL mode
   - `--schema` for SDL file when introspection disabled
   - `--graphql-endpoint` (default /graphql)
   - `--target-operations` for specific operations
   - `--depth-limit` and `--complexity-limit` for DoS testing

5. **GraphQL Permissions Matrix**
   - Type-level access definitions
   - Field-level access within types
   - Mutation/query/subscription access
   - Nested access rules

### Explicitly Out of Scope
- None specified (schema discovery IS in scope)
