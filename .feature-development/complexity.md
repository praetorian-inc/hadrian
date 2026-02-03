# Complexity Assessment

**Feature:** GraphQL API Security Testing Module
**Assessed:** 2026-02-02

## Complexity Score

| Factor | Value | Scoring | Score |
|--------|-------|---------|-------|
| Files to modify | 4 | Medium (4-10) | 2 × 2 = **4** |
| Files to create | ~20 | High (6+) | 3 × 1 = **3** |
| Dependencies | 2 (gqlparser, testify) | Low (0-2) | 1 × 1.5 = **1.5** |
| Constraints | 2 | Medium (1-2) | 2 × 2 = **4** |
| Cross-cutting | Yes (new plugin, templates, CLI) | High | 3 × 3 = **9** |
| **Total** | | | **21.5** |

## Complexity Tier: COMPLEX

Score 21.5 falls in COMPLEX range (16-25).

## Constraints Identified

1. **Dual Schema Support:** Must support both SDL files and introspection JSON
2. **Backward Compatibility:** Existing REST workflow must remain unchanged
3. **Plugin Interface:** Must conform to existing Plugin interface exactly
4. **Test Infrastructure:** Need vulnerable GraphQL app for dynamic testing

## Cross-Cutting Concerns

1. **Plugin System:** New GraphQL plugin in pkg/plugins/graphql/
2. **Template Extensions:** GraphQL-specific template fields
3. **CLI Additions:** New flags for GraphQL mode
4. **Model Extensions:** GraphQL operation types
5. **Role Permissions:** Field-level permission format

## Execution Strategy

```yaml
execution_strategy:
  batch_size: 2-3  # Smaller batches for control
  parallelization: aggressive
  checkpoints: after_each_batch
  skills_to_invoke:
    - developing-with-subagents
```

## Batch Plan

### Batch 1: Core Plugin Infrastructure
- `pkg/plugins/graphql/plugin.go` - Plugin registration
- `pkg/plugins/graphql/plugin_test.go` - Plugin tests
- **Reason:** Foundation for all other batches

### Batch 2: Schema Parsing
- `pkg/graphql/schema.go` - Schema type definitions
- `pkg/graphql/introspection.go` - Introspection result handling
- `pkg/plugins/graphql/schema_parser.go` - SDL and introspection parsing
- **Depends on:** Batch 1
- **Reason:** Schema handling before operation conversion

### Batch 3: Operation Conversion
- `pkg/plugins/graphql/operation_converter.go` - GraphQL → model.Operation
- `pkg/graphql/permissions.go` - Field-level permission testing
- **Depends on:** Batch 2
- **Reason:** Converts schema to testable operations

### Batch 4: Query Construction & Execution
- `pkg/graphql/query_builder.go` - Dynamic query construction
- `pkg/graphql/executor.go` - GraphQL query execution
- **Depends on:** Batch 3
- **Reason:** Test execution engine

### Batch 5: Attack Patterns
- `pkg/graphql/attacks.go` - GraphQL-specific attack patterns
- `pkg/graphql/depth_analyzer.go` - Query depth/complexity analysis
- **Depends on:** Batch 4
- **Can parallel with:** Batch 6

### Batch 6: CLI & Templates
- `cmd/hadrian/graphql.go` - CLI flag additions
- `templates/graphql/*.yaml` - Security test templates
- **Depends on:** Batch 4
- **Can parallel with:** Batch 5

### Batch 7: Test Infrastructure
- `testdata/graphql/` - Test schemas
- `testdata/dvga/` - DVGA setup (vulnerable app)
- **Independent:** Can start early

## Triage Revision: None Required

Work type LARGE matches COMPLEX complexity tier.

## Risk Factors

| Risk | Mitigation |
|------|-----------|
| GraphQL parser complexity | Use established library (gqlparser) |
| Introspection variations | Test against multiple GraphQL servers |
| Field permission mapping | Design flexible permission format |
| Test coverage | DVGA provides comprehensive test cases |

## Estimated Effort

- **New code:** ~2,500-3,500 LOC
- **Test code:** ~1,500-2,000 LOC
- **Templates:** ~500-800 LOC (YAML)
- **Total:** ~4,500-6,300 LOC
