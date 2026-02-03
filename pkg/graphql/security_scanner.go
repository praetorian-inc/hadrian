package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SecurityScanner performs security checks on GraphQL endpoints
type SecurityScanner struct {
	schema   *Schema
	executor *Executor
	gen      *AttackGenerator
	config   ScanConfig
}

// ScanConfig contains configuration for security scanning
type ScanConfig struct {
	DepthLimit      int
	ComplexityLimit int
	BatchSize       int
	Verbose         bool
}

// NewSecurityScanner creates a new security scanner
func NewSecurityScanner(schema *Schema, executor *Executor, config ScanConfig) *SecurityScanner {
	var gen *AttackGenerator
	if schema != nil {
		gen = NewAttackGenerator(schema)
	}

	return &SecurityScanner{
		schema:   schema,
		executor: executor,
		gen:      gen,
		config:   config,
	}
}

// CheckIntrospection checks if introspection is enabled
// If schema was successfully fetched, introspection is enabled (disclosure)
func (s *SecurityScanner) CheckIntrospection(ctx context.Context) *Finding {
	if s.schema == nil {
		return nil
	}

	// If we have a schema, introspection was successful
	finding := NewFinding(
		FindingTypeIntrospectionDisclosure,
		SeverityMedium,
		"GraphQL introspection is enabled, allowing attackers to discover the full schema",
	)

	finding.WithRemediation("Disable introspection in production environments")

	return finding
}

// CheckDepthLimit checks if the server has query depth limiting
// If a deep query succeeds (200 response), there's no depth limit
func (s *SecurityScanner) CheckDepthLimit(ctx context.Context) *Finding {
	if s.schema == nil || s.gen == nil {
		return nil
	}

	depth := s.config.DepthLimit
	if depth == 0 {
		depth = 10 // Default depth
	}

	// Get the first available query field from schema
	startField := ""
	if len(s.schema.Queries) > 0 {
		startField = s.schema.Queries[0].Name
	}
	if startField == "" {
		return nil // No queries available
	}

	// Generate a deep query using schema relationships
	deepQuery, err := s.gen.DepthAttackQueryWithSchema(startField, depth)
	if err != nil {
		// If schema-aware fails, the schema may not have recursive relationships
		return nil
	}

	// Execute the deep query
	result, err := s.executor.Execute(ctx, deepQuery, nil, "", nil)
	if err != nil {
		// Network error - can't determine
		return nil
	}

	// If query succeeded (200 and no GraphQL errors), no depth limit exists
	if result.IsSuccess() {
		finding := NewFinding(
			FindingTypeNoDepthLimit,
			SeverityHigh,
			fmt.Sprintf("Server allows deeply nested queries (depth %d) without restriction", depth),
		)

		finding.WithRemediation("Implement query depth limiting to prevent resource exhaustion attacks")
		finding.WithDetails(map[string]interface{}{
			"tested_depth": depth,
			"query":        deepQuery,
		})

		return finding
	}

	return nil
}

// CheckBatchingLimit checks if the server has batching limits
// If a batched query with many operations succeeds, there's no batching limit
func (s *SecurityScanner) CheckBatchingLimit(ctx context.Context) *Finding {
	if s.schema == nil || s.gen == nil {
		return nil
	}

	batchSize := s.config.BatchSize
	if batchSize == 0 {
		batchSize = 10 // Default batch size
	}

	// Get the first available query field from schema
	baseField := ""
	if len(s.schema.Queries) > 0 {
		baseField = s.schema.Queries[0].Name
	} else {
		baseField = "__typename"
	}

	// Generate a batched query using schema info for proper field selection
	batchedQuery, err := s.gen.BatchingAttackQueryWithSchema(baseField, batchSize)
	if err != nil {
		// Fallback to __typename if schema query fails
		batchedQuery, err = s.gen.BatchingAttackQueryWithSchema("__typename", batchSize)
		if err != nil || batchedQuery == "" {
			return nil
		}
	}

	// Execute the batched query
	result, err := s.executor.Execute(ctx, batchedQuery, nil, "", nil)
	if err != nil {
		// Network error - can't determine
		return nil
	}

	// If query succeeded (200 and no GraphQL errors), no batching limit exists
	if result.IsSuccess() {
		finding := NewFinding(
			FindingTypeNoBatchingLimit,
			SeverityMedium,
			fmt.Sprintf("Server allows batched queries with %d operations without restriction", batchSize),
		)

		finding.WithRemediation("Implement batching limits to prevent resource exhaustion attacks")
		finding.WithDetails(map[string]interface{}{
			"tested_batch_size": batchSize,
			"query":             batchedQuery,
		})

		return finding
	}

	return nil
}

// CheckBOLA checks for Broken Object Level Authorization vulnerabilities
// It tests if queries with user-specific fields can be accessed with different user contexts
func (s *SecurityScanner) CheckBOLA(ctx context.Context, authConfigs map[string]*AuthInfo) *Finding {
	if s.schema == nil || len(authConfigs) < 2 {
		return nil
	}

	// Find queries that take ID parameters
	var targetQuery *FieldDef
	for _, q := range s.schema.Queries {
		if len(q.Args) > 0 {
			// Look for queries with "id" parameter
			for _, arg := range q.Args {
				if arg.Name == "id" {
					targetQuery = q
					break
				}
			}
		}
		if targetQuery != nil {
			break
		}
	}

	if targetQuery == nil {
		return nil
	}

	// Get victim and attacker auth configs
	var victimAuth, attackerAuth *AuthInfo
	for role, auth := range authConfigs {
		if role == "victim" {
			victimAuth = auth
		} else if role == "attacker" {
			attackerAuth = auth
		}
	}

	if victimAuth == nil || attackerAuth == nil {
		return nil
	}

	// Step 1: Query as victim to get a real ID
	victimQuery := fmt.Sprintf(`query { %s { id } }`, targetQuery.Name)
	victimResult, err := s.executor.Execute(ctx, victimQuery, nil, "", victimAuth)
	if err != nil || !victimResult.IsSuccess() {
		// Can't get victim's ID, skip test
		return nil
	}

	// Extract victim's ID from response body
	var victimID string
	var gqlResp struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(victimResult.Body), &gqlResp); err == nil {
		if queryData, ok := gqlResp.Data[targetQuery.Name].(map[string]interface{}); ok {
			if id, ok := queryData["id"].(string); ok {
				victimID = id
			}
		}
	}

	if victimID == "" {
		// No ID found in victim's data
		return nil
	}

	// Step 2: Try to access victim's ID as attacker
	query := fmt.Sprintf(`query { %s(id: "%s") { id } }`, targetQuery.Name, victimID)

	// Execute as attacker
	result, err := s.executor.Execute(ctx, query, nil, "", attackerAuth)
	if err != nil {
		return nil
	}

	// If successful (200 + data returned), BOLA vulnerability exists
	if result.IsSuccess() {
		finding := NewFinding(
			FindingTypeBOLA,
			SeverityCritical,
			fmt.Sprintf("BOLA detected: attacker can access victim data via %s query using ID %s - unauthorized access to user-specific resources", targetQuery.Name, victimID),
		)

		finding.WithRemediation("Implement proper object-level authorization checks to verify the authenticated user has permission to access the requested resource")
		finding.WithDetails(map[string]interface{}{
			"query":     query,
			"test_id":   victimID,
			"operation": targetQuery.Name,
		})

		return finding
	}

	return nil
}

// CheckBFLA checks for Broken Function Level Authorization vulnerabilities
// It tests if mutations requiring higher privileges can be executed by lower-privileged users
func (s *SecurityScanner) CheckBFLA(ctx context.Context, authConfigs map[string]*AuthInfo) *Finding {
	if s.schema == nil || len(authConfigs) < 2 || len(s.schema.Mutations) == 0 {
		return nil
	}

	// Find mutations that modify sensitive data (delete, update, admin operations)
	var targetMutation *FieldDef
	sensitiveOperations := []string{
		"delete", "remove", "update", "admin", "create",
		"modify", "edit", "change",
		"grant", "revoke", "assign",
		"promote", "demote",
		"approve", "reject",
		"publish", "unpublish",
		"activate", "deactivate", "enable", "disable",
		"ban", "unban", "suspend",
	}
	for _, m := range s.schema.Mutations {
		mutationLower := strings.ToLower(m.Name)
		for _, op := range sensitiveOperations {
			if strings.Contains(mutationLower, op) {
				targetMutation = m
				break
			}
		}
		if targetMutation != nil {
			break
		}
	}

	if targetMutation == nil {
		return nil
	}

	// Get admin and user auth configs
	var adminAuth, userAuth *AuthInfo
	for role, auth := range authConfigs {
		if role == "admin" {
			adminAuth = auth
		} else if role == "user" {
			userAuth = auth
		}
	}

	if adminAuth == nil || userAuth == nil {
		return nil
	}

	// Generate mutation query
	var queryArgs string
	if len(targetMutation.Args) > 0 {
		// Build arguments based on schema
		args := []string{}
		for _, arg := range targetMutation.Args {
			if arg.Name == "id" {
				args = append(args, `id: "test-123"`)
			}
		}
		if len(args) > 0 {
			queryArgs = "(" + strings.Join(args, ", ") + ")"
		}
	}

	query := fmt.Sprintf(`mutation { %s%s { __typename } }`, targetMutation.Name, queryArgs)

	// Execute as lower-privileged user
	result, err := s.executor.Execute(ctx, query, nil, "", userAuth)
	if err != nil {
		return nil
	}

	// If successful (200 + mutation succeeded), BFLA vulnerability exists
	if result.IsSuccess() {
		finding := NewFinding(
			FindingTypeBFLA,
			SeverityCritical,
			fmt.Sprintf("BFLA detected: low-privileged user can execute %s mutation - privilege escalation vulnerability", targetMutation.Name),
		)

		finding.WithRemediation("Implement proper function-level authorization checks to restrict sensitive mutations to authorized users only")
		finding.WithDetails(map[string]interface{}{
			"mutation":  targetMutation.Name,
			"query":     query,
			"user_role": "user",
		})

		return finding
	}

	return nil
}

// RunAllChecks runs all security checks and returns findings
// authConfigs is optional - when provided, enables BOLA/BFLA testing
func (s *SecurityScanner) RunAllChecks(ctx context.Context, authConfigs map[string]*AuthInfo) []*Finding {
	findings := make([]*Finding, 0)

	// Check introspection
	if finding := s.CheckIntrospection(ctx); finding != nil {
		findings = append(findings, finding)
	}

	// Check depth limit
	if finding := s.CheckDepthLimit(ctx); finding != nil {
		findings = append(findings, finding)
	}

	// Check batching limit
	if finding := s.CheckBatchingLimit(ctx); finding != nil {
		findings = append(findings, finding)
	}

	// Check BOLA (if auth configs provided)
	if authConfigs != nil && len(authConfigs) >= 2 {
		if finding := s.CheckBOLA(ctx, authConfigs); finding != nil {
			findings = append(findings, finding)
		}

		// Check BFLA (if auth configs provided)
		if finding := s.CheckBFLA(ctx, authConfigs); finding != nil {
			findings = append(findings, finding)
		}
	}

	return findings
}
