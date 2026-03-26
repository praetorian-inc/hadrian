package graphql

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/log"
	"github.com/praetorian-inc/hadrian/pkg/model"
)

const (
	// DefaultDepthLimit is the default maximum query depth for DoS testing
	DefaultDepthLimit = 10
	// DefaultBatchSize is the default number of queries in batch attack tests
	DefaultBatchSize = 10
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
	Endpoint        string // GraphQL endpoint URL for findings
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
func (s *SecurityScanner) CheckIntrospection(ctx context.Context) *model.Finding {
	if s.schema == nil {
		return nil
	}

	// Clear request IDs before test
	s.executor.ClearRequestIDs()

	// Make a simple introspection query to capture request ID
	introspectionQuery := `{ __schema { queryType { name } } }`
	result, err := s.executor.Execute(ctx, introspectionQuery, nil, "", nil)
	if err != nil {
		return nil
	}

	// If introspection succeeds, it's a finding
	if result.IsSuccess() {
		finding := s.newFinding(
			CategoryAPI8,
			FindingTypeIntrospectionDisclosure.String(),
			"GraphQL introspection is enabled, allowing attackers to discover the full schema\nRemediation: Disable introspection in production environments",
			model.SeverityMedium,
		)
		return finding
	}

	return nil
}

// generateID generates a unique hexadecimal ID for findings
func generateID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// crypto/rand.Read only fails if system randomness source fails
		// This is catastrophic and should panic since ID uniqueness is critical
		panic(fmt.Sprintf("failed to generate random ID: %v", err))
	}
	return hex.EncodeToString(b)
}

// newFinding creates a new security finding with common fields pre-populated.
func (s *SecurityScanner) newFinding(category, name, description string, severity model.Severity) *model.Finding {
	return &model.Finding{
		ID:              generateID(),
		Category:        category,
		Name:            name,
		Description:     description,
		Severity:        severity,
		Confidence:      1.0,
		IsVulnerability: true,
		Endpoint:        s.config.Endpoint,
		Method:          "POST",
		RequestIDs:      s.executor.GetRequestIDs(),
		Timestamp:       time.Now(),
	}
}

// CheckDepthLimit checks if the server has query depth limiting
// If a deep query succeeds (200 response), there's no depth limit
func (s *SecurityScanner) CheckDepthLimit(ctx context.Context) *model.Finding {
	if s.schema == nil || s.gen == nil {
		return nil
	}

	depth := s.config.DepthLimit
	if depth == 0 {
		depth = DefaultDepthLimit
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

	// Clear request IDs before test
	s.executor.ClearRequestIDs()

	// Execute the deep query
	result, err := s.executor.Execute(ctx, deepQuery, nil, "", nil)
	if err != nil {
		// Network error - can't determine
		return nil
	}

	// If query succeeded (200 and no GraphQL errors), no depth limit exists
	if result.IsSuccess() {
		finding := s.newFinding(
			CategoryAPI4,
			FindingTypeNoDepthLimit.String(),
			fmt.Sprintf("Server allows deeply nested queries (depth %d) without restriction\nRemediation: Implement query depth limiting to prevent resource exhaustion attacks", depth),
			model.SeverityHigh,
		)

		return finding
	}

	return nil
}

// CheckBatchingLimit checks if the server has batching limits
// If a batched query with many operations succeeds, there's no batching limit
func (s *SecurityScanner) CheckBatchingLimit(ctx context.Context) *model.Finding {
	if s.schema == nil || s.gen == nil {
		return nil
	}

	batchSize := s.config.BatchSize
	if batchSize == 0 {
		batchSize = DefaultBatchSize
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

	// Clear request IDs before test
	s.executor.ClearRequestIDs()

	// Execute the batched query
	result, err := s.executor.Execute(ctx, batchedQuery, nil, "", nil)
	if err != nil {
		// Network error - can't determine
		return nil
	}

	// If query succeeded (200 and no GraphQL errors), no batching limit exists
	if result.IsSuccess() {
		finding := s.newFinding(
			CategoryAPI4,
			FindingTypeNoBatchingLimit.String(),
			fmt.Sprintf("Server allows batched queries with %d operations without restriction\nRemediation: Implement batching limits to prevent resource exhaustion attacks", batchSize),
			model.SeverityMedium,
		)

		return finding
	}

	return nil
}

// CheckBOLA checks for Broken Object Level Authorization vulnerabilities
// It tests if queries with user-specific fields can be accessed with different user contexts
func (s *SecurityScanner) CheckBOLA(ctx context.Context, authConfigs map[string]*AuthInfo) *model.Finding {
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
	var victimRole, attackerRole string
	for role, auth := range authConfigs {
		if role == "victim" {
			victimAuth = auth
			victimRole = role
		} else if role == "attacker" {
			attackerAuth = auth
			attackerRole = role
		}
	}

	if victimAuth == nil || attackerAuth == nil {
		log.Debug("CheckBOLA skipped: auth config requires 'victim' and 'attacker' roles")
		return nil
	}

	// Clear request IDs before starting test
	s.executor.ClearRequestIDs()

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
	// Use GraphQL variables to prevent injection
	query := fmt.Sprintf(`query($id: ID!) { %s(id: $id) { id } }`, targetQuery.Name)
	variables := map[string]interface{}{"id": victimID}

	// Execute as attacker
	result, err := s.executor.Execute(ctx, query, variables, "", attackerAuth)
	if err != nil {
		return nil
	}

	// If successful (200 + data returned), BOLA vulnerability exists
	if result.IsSuccess() {
		finding := s.newFinding(
			CategoryAPI1,
			FindingTypeBOLA.String(),
			fmt.Sprintf("BOLA detected: attacker can access victim data via %s query using ID %s - unauthorized access to user-specific resources\nRemediation: Implement proper object-level authorization checks to verify the authenticated user has permission to access the requested resource", targetQuery.Name, victimID),
			model.SeverityCritical,
		)
		finding.AttackerRole = attackerRole
		finding.VictimRole = victimRole

		return finding
	}

	return nil
}

// CheckBFLA checks for Broken Function Level Authorization vulnerabilities
// It tests if mutations requiring higher privileges can be executed by lower-privileged users
func (s *SecurityScanner) CheckBFLA(ctx context.Context, authConfigs map[string]*AuthInfo) *model.Finding {
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
	var adminRole, userRole string
	for role, auth := range authConfigs {
		if role == "admin" {
			adminAuth = auth
			adminRole = role
		} else if role == "user" {
			userAuth = auth
			userRole = role
		}
	}

	if adminAuth == nil || userAuth == nil {
		log.Debug("CheckBFLA skipped: auth config requires 'admin' and 'user' roles")
		return nil
	}

	// Clear request IDs before starting test
	s.executor.ClearRequestIDs()

	// Generate mutation query using GraphQL variables (defense-in-depth against injection)
	// This follows the same pattern as CheckBOLA
	var query string
	var variables map[string]interface{}

	if len(targetMutation.Args) > 0 {
		// Build variable definitions and arguments
		varDefs := []string{}
		argsList := []string{}
		variables = make(map[string]interface{})

		for _, arg := range targetMutation.Args {
			if arg.Name == "id" {
				varDefs = append(varDefs, "$id: ID!")
				argsList = append(argsList, "id: $id")
				variables["id"] = "test-123"
			}
		}

		if len(varDefs) > 0 {
			varDefsStr := strings.Join(varDefs, ", ")
			argsStr := strings.Join(argsList, ", ")
			query = fmt.Sprintf(`mutation(%s) { %s(%s) { __typename } }`, varDefsStr, targetMutation.Name, argsStr)
		} else {
			query = fmt.Sprintf(`mutation { %s { __typename } }`, targetMutation.Name)
		}
	} else {
		query = fmt.Sprintf(`mutation { %s { __typename } }`, targetMutation.Name)
	}

	// Execute as lower-privileged user
	result, err := s.executor.Execute(ctx, query, variables, "", userAuth)
	if err != nil {
		return nil
	}

	// If successful (200 + mutation succeeded), BFLA vulnerability exists
	if result.IsSuccess() {
		finding := s.newFinding(
			CategoryAPI5,
			FindingTypeBFLA.String(),
			fmt.Sprintf("BFLA detected: low-privileged user can execute %s mutation - privilege escalation vulnerability\nRemediation: Implement proper function-level authorization checks to restrict sensitive mutations to authorized users only", targetMutation.Name),
			model.SeverityCritical,
		)
		finding.AttackerRole = userRole
		finding.VictimRole = adminRole

		return finding
	}

	return nil
}

// FindingCallback is called when a finding is discovered (for real-time reporting)
type FindingCallback func(*model.Finding)

// RunAllChecks runs all security checks and returns findings
// onFinding callback is called for each finding (can be nil)
func (s *SecurityScanner) RunAllChecks(ctx context.Context, authConfigs map[string]*AuthInfo, onFinding FindingCallback) []*model.Finding {
	findings := make([]*model.Finding, 0)

	// Check introspection
	log.Debug("Checking introspection...")
	if finding := s.CheckIntrospection(ctx); finding != nil {
		if onFinding != nil {
			onFinding(finding)
		}
		findings = append(findings, finding)
	}

	// Check depth limit
	log.Debug("Checking depth limit...")
	if finding := s.CheckDepthLimit(ctx); finding != nil {
		if onFinding != nil {
			onFinding(finding)
		}
		findings = append(findings, finding)
	}

	// Check batching limit
	log.Debug("Checking batching limit...")
	if finding := s.CheckBatchingLimit(ctx); finding != nil {
		if onFinding != nil {
			onFinding(finding)
		}
		findings = append(findings, finding)
	}

	// Check BOLA (if auth configs provided)
	if len(authConfigs) >= 2 {
		log.Debug("Checking BOLA...")
		if finding := s.CheckBOLA(ctx, authConfigs); finding != nil {
			if onFinding != nil {
				onFinding(finding)
			}
			findings = append(findings, finding)
		}

		// Check BFLA (if auth configs provided)
		log.Debug("Checking BFLA...")
		if finding := s.CheckBFLA(ctx, authConfigs); finding != nil {
			if onFinding != nil {
				onFinding(finding)
			}
			findings = append(findings, finding)
		}
	}

	return findings
}
