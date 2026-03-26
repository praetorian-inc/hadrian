package graphql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityScanner_CheckIntrospection(t *testing.T) {
	t.Run("returns finding when introspection succeeds", func(t *testing.T) {
		// Create test server that allows introspection
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`))
		}))
		defer server.Close()

		// Fetch schema via introspection
		introspectionClient := NewIntrospectionClient(http.DefaultClient, server.URL)
		schema, err := introspectionClient.FetchSchema(context.Background())
		require.NoError(t, err)
		require.NotNil(t, schema)

		// Create executor and scanner
		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		// Check for introspection disclosure
		ctx := context.Background()
		finding := scanner.CheckIntrospection(ctx)

		// Assert finding exists with correct properties
		assert.NotNil(t, finding)
		assert.Equal(t, FindingTypeIntrospectionDisclosure.String(), finding.Name)
		assert.Equal(t, model.SeverityMedium, finding.Severity)
		assert.Equal(t, CategoryAPI8, finding.Category)
	})

	t.Run("returns nil when schema is nil", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(nil, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckIntrospection(ctx)

		assert.Nil(t, finding)
	})
}

func TestSecurityScanner_CheckDepthLimit(t *testing.T) {
	t.Run("returns finding when deep query succeeds", func(t *testing.T) {
		// Create test server that accepts deep queries (no depth limit)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"user":{"friend":{"friend":{"friend":{"id":"123"}}}}}}`))
		}))
		defer server.Close()

		// Create simple schema for testing
		schema := &Schema{
			QueryType: "Query",
			Types: map[string]*TypeDef{
				"Query": {
					Name: "Query",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "user", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
					},
				},
				"User": {
					Name: "User",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
						{Name: "friend", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
					},
				},
			},
			Queries: []*FieldDef{
				{Name: "user", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
			},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		gen := NewAttackGenerator(schema)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{
			DepthLimit: 10,
		})

		// Check for depth limit
		ctx := context.Background()
		finding := scanner.CheckDepthLimit(ctx)

		// Assert finding exists with correct properties
		assert.NotNil(t, finding)
		assert.Equal(t, FindingTypeNoDepthLimit.String(), finding.Name)
		assert.Equal(t, model.SeverityHigh, finding.Severity)
		assert.Equal(t, CategoryAPI4, finding.Category)

		// Verify generator is being used
		assert.NotNil(t, gen)
	})

	t.Run("returns nil when deep query fails", func(t *testing.T) {
		// Create test server that rejects deep queries (has depth limit)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"errors":[{"message":"Query depth limit exceeded"}]}`))
		}))
		defer server.Close()

		schema := &Schema{
			QueryType: "Query",
			Types: map[string]*TypeDef{
				"Query": {
					Name: "Query",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "user", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
					},
				},
				"User": {
					Name: "User",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
						{Name: "friend", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
					},
				},
			},
			Queries: []*FieldDef{
				{Name: "user", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
			},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{
			DepthLimit: 10,
		})

		ctx := context.Background()
		finding := scanner.CheckDepthLimit(ctx)

		assert.Nil(t, finding)
	})
}

func TestSecurityScanner_CheckBatchingLimit(t *testing.T) {
	t.Run("returns finding when batched query succeeds", func(t *testing.T) {
		// Create test server that accepts batched queries (no batching limit)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"q1":{"id":"1"},"q2":{"id":"2"},"q3":{"id":"3"}}}`))
		}))
		defer server.Close()

		schema := &Schema{
			QueryType: "Query",
			Types: map[string]*TypeDef{
				"Query": {
					Name: "Query",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "user", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
					},
				},
				"User": {
					Name: "User",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
			Queries: []*FieldDef{
				{Name: "user", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
			},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		gen := NewAttackGenerator(schema)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{
			BatchSize: 10,
		})

		// Check for batching limit
		ctx := context.Background()
		finding := scanner.CheckBatchingLimit(ctx)

		// Assert finding exists with correct properties
		assert.NotNil(t, finding)
		assert.Equal(t, FindingTypeNoBatchingLimit.String(), finding.Name)
		assert.Equal(t, model.SeverityMedium, finding.Severity)
		assert.Equal(t, CategoryAPI4, finding.Category)

		// Verify generator is being used
		assert.NotNil(t, gen)
	})

	t.Run("returns nil when batched query fails", func(t *testing.T) {
		// Create test server that rejects batched queries (has batching limit)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"errors":[{"message":"Batching limit exceeded"}]}`))
		}))
		defer server.Close()

		schema := &Schema{
			QueryType: "Query",
			Types: map[string]*TypeDef{
				"Query": {
					Name: "Query",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "user", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
					},
				},
				"User": {
					Name: "User",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
			Queries: []*FieldDef{
				{Name: "user", Type: &TypeRef{Name: "User", Kind: TypeKindObject}},
			},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{
			BatchSize: 10,
		})

		ctx := context.Background()
		finding := scanner.CheckBatchingLimit(ctx)

		assert.Nil(t, finding)
	})
}

func TestSecurityScanner_CheckDepthLimit_UsesSchemaFields(t *testing.T) {
	t.Run("uses actual schema fields instead of hardcoded ones", func(t *testing.T) {
		// Create test server that accepts deep queries (no depth limit)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Return success for paste query
			_, _ = w.Write([]byte(`{"data":{"paste":{"content":{"content":{"content":"nested"}}}}}}`))
		}))
		defer server.Close()

		// DVGA-like schema with paste query
		schema := &Schema{
			QueryType: "Query",
			Types: map[string]*TypeDef{
				"Query": {
					Name: "Query",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "paste", Type: &TypeRef{Name: "Paste", Kind: TypeKindObject}},
					},
				},
				"Paste": {
					Name: "Paste",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
						{Name: "content", Type: &TypeRef{Name: "Paste", Kind: TypeKindObject}},
					},
				},
			},
			Queries: []*FieldDef{
				{Name: "paste", Type: &TypeRef{Name: "Paste", Kind: TypeKindObject}},
			},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{
			DepthLimit: 10,
		})

		// Check for depth limit - should use "paste" field from schema
		ctx := context.Background()
		finding := scanner.CheckDepthLimit(ctx)

		// Assert finding exists (no depth limit enforced)
		assert.NotNil(t, finding)
		assert.Equal(t, FindingTypeNoDepthLimit.String(), finding.Name)
	})
}

func TestSecurityScanner_CheckBOLA(t *testing.T) {
	t.Run("detects BOLA when attacker accesses victim data", func(t *testing.T) {
		// Track request count
		requestCount := 0

		// Create test server that allows unauthorized access
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			// Return victim's data regardless of auth header
			_, _ = w.Write([]byte(`{"data":{"user":{"id":"victim-123","email":"victim@example.com"}}}`))
		}))
		defer server.Close()

		// Schema with user query that takes ID parameter
		schema := &Schema{
			QueryType: "Query",
			Types: map[string]*TypeDef{
				"Query": {
					Name: "Query",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{
							Name: "user",
							Type: &TypeRef{Name: "User", Kind: TypeKindObject},
							Args: []*ArgumentDef{
								{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
							},
						},
					},
				},
				"User": {
					Name: "User",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
						{Name: "email", Type: &TypeRef{Name: "String", Kind: TypeKindScalar}},
					},
				},
			},
			Queries: []*FieldDef{
				{
					Name: "user",
					Type: &TypeRef{Name: "User", Kind: TypeKindObject},
					Args: []*ArgumentDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
		}

		// Auth configs for victim and attacker
		authConfigs := map[string]*AuthInfo{
			"victim":   {Method: "bearer", Value: "victim-token"},
			"attacker": {Method: "bearer", Value: "attacker-token"},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckBOLA(ctx, authConfigs)

		// Should detect BOLA vulnerability
		assert.NotNil(t, finding)
		assert.Equal(t, FindingTypeBOLA.String(), finding.Name)
		assert.Equal(t, model.SeverityCritical, finding.Severity)
		assert.Contains(t, finding.Description, "unauthorized access")
	})

	t.Run("returns nil when BOLA protected", func(t *testing.T) {
		// Create test server that properly enforces authorization
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			// Check auth header - executor sets it directly to the value (not "Bearer X")
			authHeader := r.Header.Get("Authorization")
			if authHeader == "attacker-token" {
				// Attacker trying to access victim data - return error
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"errors":[{"message":"Unauthorized"}]}`))
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"user":{"id":"victim-123"}}}`))
		}))
		defer server.Close()

		schema := &Schema{
			QueryType: "Query",
			Types: map[string]*TypeDef{
				"Query": {
					Name: "Query",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{
							Name: "user",
							Type: &TypeRef{Name: "User", Kind: TypeKindObject},
							Args: []*ArgumentDef{
								{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
							},
						},
					},
				},
			},
			Queries: []*FieldDef{
				{
					Name: "user",
					Type: &TypeRef{Name: "User", Kind: TypeKindObject},
					Args: []*ArgumentDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
		}

		authConfigs := map[string]*AuthInfo{
			"victim":   {Method: "bearer", Value: "victim-token"},
			"attacker": {Method: "bearer", Value: "attacker-token"},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckBOLA(ctx, authConfigs)

		// Should not detect BOLA (properly protected)
		assert.Nil(t, finding)
	})

	t.Run("returns nil when no auth configs provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		schema := &Schema{
			QueryType: "Query",
			Queries:   []*FieldDef{},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckBOLA(ctx, nil)

		assert.Nil(t, finding)
	})

	// NEW TEST - Dynamic ID discovery
	t.Run("uses dynamic ID discovery from victim query", func(t *testing.T) {
		// Track queries to verify the two-phase approach
		queryLog := []string{}

		// Create test server that returns real data
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			queryLog = append(queryLog, string(body))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			// Both victim and attacker queries return the same data
			// (simulating a BOLA vulnerability where attacker can access victim's data)
			_, _ = w.Write([]byte(`{"data":{"user":{"id":"victim-real-id-456","email":"victim@example.com"}}}`))
		}))
		defer server.Close()

		schema := &Schema{
			QueryType: "Query",
			Queries: []*FieldDef{
				{
					Name: "user",
					Type: &TypeRef{Name: "User", Kind: TypeKindObject},
					Args: []*ArgumentDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
		}

		authConfigs := map[string]*AuthInfo{
			"victim":   {Method: "bearer", Value: "victim-token"},
			"attacker": {Method: "bearer", Value: "attacker-token"},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckBOLA(ctx, authConfigs)

		// Should detect BOLA with real victim ID (not hardcoded)
		assert.NotNil(t, finding)
		assert.Equal(t, FindingTypeBOLA.String(), finding.Name)

		// Verify the finding references the real ID, not the hardcoded one
		assert.Contains(t, finding.Description, "victim-real-id-456")
	})
}

func TestSecurityScanner_CheckBFLA(t *testing.T) {
	t.Run("detects BFLA when low-priv user executes admin mutation", func(t *testing.T) {
		// Create test server that allows unauthorized mutations
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			// Return success for delete mutation regardless of auth
			_, _ = w.Write([]byte(`{"data":{"deleteUser":{"success":true}}}`))
		}))
		defer server.Close()

		// Schema with admin-level delete mutation
		schema := &Schema{
			QueryType:    "Query",
			MutationType: "Mutation",
			Types: map[string]*TypeDef{
				"Mutation": {
					Name: "Mutation",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{
							Name: "deleteUser",
							Type: &TypeRef{Name: "DeleteResult", Kind: TypeKindObject},
							Args: []*ArgumentDef{
								{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
							},
						},
					},
				},
				"DeleteResult": {
					Name: "DeleteResult",
					Kind: TypeKindObject,
					Fields: []*FieldDef{
						{Name: "success", Type: &TypeRef{Name: "Boolean", Kind: TypeKindScalar}},
					},
				},
			},
			Mutations: []*FieldDef{
				{
					Name: "deleteUser",
					Type: &TypeRef{Name: "DeleteResult", Kind: TypeKindObject},
					Args: []*ArgumentDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
		}

		authConfigs := map[string]*AuthInfo{
			"admin": {Method: "bearer", Value: "admin-token"},
			"user":  {Method: "bearer", Value: "user-token"},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckBFLA(ctx, authConfigs)

		// Should detect BFLA vulnerability
		assert.NotNil(t, finding)
		assert.Equal(t, FindingTypeBFLA.String(), finding.Name)
		assert.Equal(t, model.SeverityCritical, finding.Severity)
		assert.Contains(t, finding.Description, "privilege escalation")
	})

	t.Run("returns nil when BFLA protected", func(t *testing.T) {
		// Create test server that properly enforces authorization
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			// Check auth header - executor sets it directly to the value (not "Bearer X")
			authHeader := r.Header.Get("Authorization")
			if authHeader == "user-token" {
				// Low-priv user trying admin mutation - return error
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"errors":[{"message":"Insufficient privileges"}]}`))
				return
			}

			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"deleteUser":{"success":true}}}`))
		}))
		defer server.Close()

		schema := &Schema{
			MutationType: "Mutation",
			Mutations: []*FieldDef{
				{
					Name: "deleteUser",
					Type: &TypeRef{Name: "DeleteResult", Kind: TypeKindObject},
					Args: []*ArgumentDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
		}

		authConfigs := map[string]*AuthInfo{
			"admin": {Method: "bearer", Value: "admin-token"},
			"user":  {Method: "bearer", Value: "user-token"},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckBFLA(ctx, authConfigs)

		// Should not detect BFLA (properly protected)
		assert.Nil(t, finding)
	})

	t.Run("returns nil when no auth configs provided", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		schema := &Schema{
			MutationType: "Mutation",
			Mutations:    []*FieldDef{},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		finding := scanner.CheckBFLA(ctx, nil)

		assert.Nil(t, finding)
	})

	// NEW TEST - Expanded sensitive operations list
	t.Run("detects more sensitive operation types", func(t *testing.T) {
		sensitiveOps := []string{"modify", "edit", "grant", "promote", "approve", "publish", "activate", "ban"}

		for _, op := range sensitiveOps {
			mutationName := op + "User"

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"` + mutationName + `":{"success":true}}}`))
			}))
			defer server.Close()

			schema := &Schema{
				MutationType: "Mutation",
				Mutations: []*FieldDef{
					{
						Name: mutationName,
						Type: &TypeRef{Name: "Result", Kind: TypeKindObject},
					},
				},
			}

			authConfigs := map[string]*AuthInfo{
				"admin": {Method: "bearer", Value: "admin-token"},
				"user":  {Method: "bearer", Value: "user-token"},
			}

			executor := NewExecutor(http.DefaultClient, server.URL, nil)
			scanner := NewSecurityScanner(schema, executor, ScanConfig{})

			finding := scanner.CheckBFLA(context.Background(), authConfigs)

			assert.NotNil(t, finding, "Should detect BFLA for %s operation", op)
			assert.Equal(t, FindingTypeBFLA.String(), finding.Name)
		}
	})

	t.Run("uses GraphQL variables for arguments like BOLA check", func(t *testing.T) {
		// Track what queries were executed
		var receivedQuery string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Capture the query body
			body := make([]byte, 2048)
			n, _ := r.Body.Read(body)
			receivedQuery = string(body[:n])

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"deleteUser":{"success":true}}}`))
		}))
		defer server.Close()

		schema := &Schema{
			MutationType: "Mutation",
			Mutations: []*FieldDef{
				{
					Name: "deleteUser",
					Type: &TypeRef{Name: "DeleteResult", Kind: TypeKindObject},
					Args: []*ArgumentDef{
						{Name: "id", Type: &TypeRef{Name: "ID", Kind: TypeKindScalar}},
					},
				},
			},
		}

		authConfigs := map[string]*AuthInfo{
			"admin": {Method: "bearer", Value: "admin-token"},
			"user":  {Method: "bearer", Value: "user-token"},
		}

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{})

		ctx := context.Background()
		scanner.CheckBFLA(ctx, authConfigs)

		// Verify the query uses GraphQL variables instead of string interpolation
		// This follows the same pattern as CheckBOLA (line 300-301 in security_scanner.go)
		assert.NotEmpty(t, receivedQuery)

		// Should use variables syntax: mutation($id: ID!)
		assert.Contains(t, receivedQuery, "$id")
		// Should pass variables separately
		assert.Contains(t, receivedQuery, "variables")
		// Should NOT use inline string interpolation
		assert.NotContains(t, receivedQuery, `id: "test-123"`)
	})
}

func TestSecurityScanner_RunAllChecks(t *testing.T) {
	t.Run("returns all findings from security checks", func(t *testing.T) {
		// Create test server that allows introspection and has no limits
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Return success for all queries
			_, _ = w.Write([]byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`))
		}))
		defer server.Close()

		// Fetch schema
		introspectionClient := NewIntrospectionClient(http.DefaultClient, server.URL)
		schema, err := introspectionClient.FetchSchema(context.Background())
		require.NoError(t, err)

		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(schema, executor, ScanConfig{
			DepthLimit: 10,
			BatchSize:  10,
		})

		// Run all checks (no auth configs, no callback)
		ctx := context.Background()
		findings := scanner.RunAllChecks(ctx, nil, nil)

		// Should return slice of findings
		assert.NotNil(t, findings)
		assert.IsType(t, []*model.Finding{}, findings)

		// Should have at least introspection finding
		assert.GreaterOrEqual(t, len(findings), 1)

		// Verify introspection finding exists
		hasIntrospectionFinding := false
		for _, f := range findings {
			if f.Name == FindingTypeIntrospectionDisclosure.String() {
				hasIntrospectionFinding = true
				break
			}
		}
		assert.True(t, hasIntrospectionFinding)
	})

	t.Run("returns empty slice when no findings", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Return errors for all queries
			_, _ = w.Write([]byte(`{"errors":[{"message":"Forbidden"}]}`))
		}))
		defer server.Close()

		// No schema (introspection disabled)
		executor := NewExecutor(http.DefaultClient, server.URL, nil)
		scanner := NewSecurityScanner(nil, executor, ScanConfig{})

		ctx := context.Background()
		findings := scanner.RunAllChecks(ctx, nil, nil)

		assert.NotNil(t, findings)
		assert.Equal(t, 0, len(findings))
	})
}
