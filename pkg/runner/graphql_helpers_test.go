// pkg/runner/graphql_helpers_test.go
package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadConfigs_BothEmpty tests when no config files are provided
func TestLoadConfigs_BothEmpty(t *testing.T) {
	authConfig, rolesConfig, err := loadConfigs("", "")
	assert.NoError(t, err)
	assert.Nil(t, authConfig)
	assert.Nil(t, rolesConfig)
}

// TestLoadConfigs_InvalidAuthPath tests with invalid auth config path
func TestLoadConfigs_InvalidAuthPath(t *testing.T) {
	authConfig, rolesConfig, err := loadConfigs("/nonexistent/auth.yaml", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load auth config")
	assert.Nil(t, authConfig)
	assert.Nil(t, rolesConfig)
}

// TestLoadConfigs_InvalidRolesPath tests with invalid roles config path
func TestLoadConfigs_InvalidRolesPath(t *testing.T) {
	authConfig, rolesConfig, err := loadConfigs("", "/nonexistent/roles.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load roles config")
	assert.Nil(t, authConfig)
	assert.Nil(t, rolesConfig)
}

// TestLoadConfigs_ValidPaths tests with valid config files
func TestLoadConfigs_ValidPaths(t *testing.T) {
	// Create temporary config files
	tmpDir := t.TempDir()

	// Create valid auth config
	authPath := filepath.Join(tmpDir, "auth.yaml")
	authContent := `method: bearer
location: header
key_name: Authorization
roles:
  admin:
    token: admin-token-123
  user:
    token: user-token-456
`
	err := os.WriteFile(authPath, []byte(authContent), 0644)
	require.NoError(t, err)

	// Create valid roles config
	rolesPath := filepath.Join(tmpDir, "roles.yaml")
	rolesContent := `roles:
  - name: admin
    level: 100
    permissions:
      - "read:*:*"
      - "write:*:*"
  - name: user
    level: 10
    permissions:
      - "read:*:own"
`
	err = os.WriteFile(rolesPath, []byte(rolesContent), 0644)
	require.NoError(t, err)

	// Test loading both configs
	authConfig, rolesConfig, err := loadConfigs(authPath, rolesPath)
	assert.NoError(t, err)
	assert.NotNil(t, authConfig)
	assert.NotNil(t, rolesConfig)
	assert.Equal(t, "bearer", authConfig.Method)
	assert.Len(t, authConfig.Roles, 2)
	assert.Len(t, rolesConfig.Roles, 2)
}

// TestBuildAuthConfigs_NilInput tests with nil auth config
func TestBuildAuthConfigs_NilInput(t *testing.T) {
	authConfigs, err := buildAuthConfigs(nil)
	assert.NoError(t, err)
	assert.Nil(t, authConfigs)
}

// TestBuildAuthConfigs_EmptyRoles tests with empty roles
func TestBuildAuthConfigs_EmptyRoles(t *testing.T) {
	authConfig := &auth.AuthConfig{
		Method:   "bearer",
		Location: "header",
		KeyName:  "Authorization",
		Roles:    map[string]*auth.RoleAuth{},
	}

	authConfigs, err := buildAuthConfigs(authConfig)
	assert.NoError(t, err)
	assert.Nil(t, authConfigs)
}

// TestBuildAuthConfigs_BearerAuth tests bearer token conversion
func TestBuildAuthConfigs_BearerAuth(t *testing.T) {
	authConfig := &auth.AuthConfig{
		Method:   "bearer",
		Location: "header",
		KeyName:  "Authorization",
		Roles: map[string]*auth.RoleAuth{
			"admin": {Token: "admin-token-123"},
			"user":  {Token: "user-token-456"},
		},
	}

	authConfigs, err := buildAuthConfigs(authConfig)
	assert.NoError(t, err)
	assert.NotNil(t, authConfigs)
	assert.Len(t, authConfigs, 2)

	// Check admin role
	assert.NotNil(t, authConfigs["admin"])
	assert.Equal(t, "bearer", authConfigs["admin"].Method)
	assert.Equal(t, "Bearer admin-token-123", authConfigs["admin"].Value)
	assert.Equal(t, "header", authConfigs["admin"].Location)
	assert.Equal(t, "Authorization", authConfigs["admin"].KeyName)

	// Check user role
	assert.NotNil(t, authConfigs["user"])
	assert.Equal(t, "bearer", authConfigs["user"].Method)
	assert.Equal(t, "Bearer user-token-456", authConfigs["user"].Value)
}

// TestBuildAuthConfigs_APIKeyAuth tests API key conversion
func TestBuildAuthConfigs_APIKeyAuth(t *testing.T) {
	authConfig := &auth.AuthConfig{
		Method:   "api_key",
		Location: "header",
		KeyName:  "X-API-Key",
		Roles: map[string]*auth.RoleAuth{
			"service": {APIKey: "service-key-789"},
		},
	}

	authConfigs, err := buildAuthConfigs(authConfig)
	assert.NoError(t, err)
	assert.NotNil(t, authConfigs)
	assert.Len(t, authConfigs, 1)
	assert.Equal(t, "api_key", authConfigs["service"].Method)
	assert.Equal(t, "service-key-789", authConfigs["service"].Value)
}

// TestBuildAuthConfigs_BasicAuth tests basic auth conversion
func TestBuildAuthConfigs_BasicAuth(t *testing.T) {
	authConfig := &auth.AuthConfig{
		Method:   "basic",
		Location: "header",
		KeyName:  "Authorization",
		Roles: map[string]*auth.RoleAuth{
			"admin": {Username: "admin", Password: "secret123"},
		},
	}

	authConfigs, err := buildAuthConfigs(authConfig)
	assert.NoError(t, err)
	assert.NotNil(t, authConfigs)
	assert.Len(t, authConfigs, 1)
	assert.Equal(t, "basic", authConfigs["admin"].Method)
	// Basic auth should be base64 encoded username:password
	assert.NotEmpty(t, authConfigs["admin"].Value)
}

// TestBuildAuthConfigs_MissingTokenForBearer tests validation
func TestBuildAuthConfigs_MissingTokenForBearer(t *testing.T) {
	authConfig := &auth.AuthConfig{
		Method:   "bearer",
		Location: "header",
		KeyName:  "Authorization",
		Roles: map[string]*auth.RoleAuth{
			"admin": {Token: ""}, // Missing token
		},
	}

	authConfigs, err := buildAuthConfigs(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bearer auth requires 'token' field")
	assert.Nil(t, authConfigs)
}

// TestBuildAuthConfigs_MissingAPIKey tests API key validation
func TestBuildAuthConfigs_MissingAPIKey(t *testing.T) {
	authConfig := &auth.AuthConfig{
		Method:   "api_key",
		Location: "header",
		KeyName:  "X-API-Key",
		Roles: map[string]*auth.RoleAuth{
			"service": {APIKey: ""}, // Missing API key
		},
	}

	authConfigs, err := buildAuthConfigs(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api_key auth requires 'api_key' field")
	assert.Nil(t, authConfigs)
}

// TestBuildAuthConfigs_MissingBasicAuthCredentials tests basic auth validation
func TestBuildAuthConfigs_MissingBasicAuthCredentials(t *testing.T) {
	authConfig := &auth.AuthConfig{
		Method:   "basic",
		Location: "header",
		KeyName:  "Authorization",
		Roles: map[string]*auth.RoleAuth{
			"admin": {Username: "admin", Password: ""}, // Missing password
		},
	}

	authConfigs, err := buildAuthConfigs(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "basic auth requires 'username' and 'password' fields")
	assert.Nil(t, authConfigs)
}

// TestBuildAuthConfigs_UnsupportedMethod tests unsupported auth method
func TestBuildAuthConfigs_UnsupportedMethod(t *testing.T) {
	authConfig := &auth.AuthConfig{
		Method:   "oauth2",
		Location: "header",
		KeyName:  "Authorization",
		Roles: map[string]*auth.RoleAuth{
			"admin": {Token: "token"},
		},
	}

	authConfigs, err := buildAuthConfigs(authConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth method")
	assert.Nil(t, authConfigs)
}

// TestFetchSchema_Introspection tests schema fetching via introspection
func TestFetchSchema_Introspection(t *testing.T) {
	// Create mock GraphQL server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return minimal valid introspection response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		response := `{
			"data": {
				"__schema": {
					"queryType": {"name": "Query"},
					"mutationType": {"name": "Mutation"},
					"types": [
						{"name": "Query", "kind": "OBJECT", "fields": []},
						{"name": "Mutation", "kind": "OBJECT", "fields": []}
					]
				}
			}
		}`
		_, _ = w.Write([]byte(response))
	}))
	defer server.Close()

	config := GraphQLConfig{
		Target:   server.URL,
		Endpoint: "/graphql",
		Schema:   "", // Empty means use introspection
	}

	httpClient := &http.Client{}
	ctx := context.Background()

	schema, err := fetchSchema(ctx, config, httpClient)
	assert.NoError(t, err)
	assert.NotNil(t, schema)
}

// TestFetchSchema_SDLFile tests SDL file loading with nonexistent file
func TestFetchSchema_SDLFile(t *testing.T) {
	config := GraphQLConfig{
		Target:   "https://api.example.com",
		Endpoint: "/graphql",
		Schema:   "/path/to/schema.graphql",
	}

	httpClient := &http.Client{}
	ctx := context.Background()

	schema, err := fetchSchema(ctx, config, httpClient)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load schema from file")
	assert.Nil(t, schema)
}

// TestFetchSchema_IntrospectionFailure tests introspection error handling
func TestFetchSchema_IntrospectionFailure(t *testing.T) {
	// Create server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	config := GraphQLConfig{
		Target:   server.URL,
		Endpoint: "/graphql",
		Schema:   "", // Use introspection
	}

	httpClient := &http.Client{}
	ctx := context.Background()

	schema, err := fetchSchema(ctx, config, httpClient)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "introspection failed")
	assert.Nil(t, schema)
}

// TestReportFindings_Empty tests reporting with no findings
func TestReportFindings_Empty(t *testing.T) {
	// Should not panic with empty findings
	findings := []*model.Finding{}
	reportFindings(findings) // Just verify it doesn't crash
}

// TestReportFindings_WithFindings tests reporting with actual findings
func TestReportFindings_WithFindings(t *testing.T) {
	findings := []*model.Finding{
		{
			ID:          "test-1",
			Category:    "API3",
			Name:        graphql.FindingTypeIntrospectionDisclosure.String(),
			Description: "GraphQL introspection is enabled\nRemediation: Disable introspection in production",
			Severity:    model.SeverityHigh,
		},
		{
			ID:          "test-2",
			Category:    "API4",
			Name:        graphql.FindingTypeNoDepthLimit.String(),
			Description: "Query allows excessive depth",
			Severity:    model.SeverityMedium,
		},
	}

	// Should not panic with valid findings
	reportFindings(findings)
}

// TestRunTemplateTests_ReturnsTemplateCount tests that runTemplateTests returns the count of loaded templates
func TestRunTemplateTests_ReturnsTemplateCount(t *testing.T) {
	// Create a test server that returns a simple GraphQL response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data": {"test": "value"}}`))
	}))
	defer server.Close()

	config := GraphQLConfig{
		TemplateDir: "../../templates/graphql",
		Timeout:   30,
		Verbose:   false,
	}

	// Run template tests
	findings, templateCount := runTemplateTests(
		context.Background(),
		config,
		server.URL,
		server.Client(),
		nil,
		nil, // reporter
	)

	// Verify findings are returned (may be 0 if no templates match)
	assert.NotNil(t, findings)

	// Verify template count is returned and matches loaded templates
	assert.Greater(t, templateCount, 0, "should load at least one template")
}

// TestRunSecurityChecks_NoTemplates tests that runSecurityChecks returns 0 template count when no templates specified
func TestRunSecurityChecks_NoTemplates(t *testing.T) {
	// Create a minimal GraphQL schema
	schema := &graphql.Schema{
		Queries:   []*graphql.FieldDef{},
		Mutations: []*graphql.FieldDef{},
		Types:     map[string]*graphql.TypeDef{},
	}

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data": {}}`))
	}))
	defer server.Close()

	config := GraphQLConfig{
		TemplateDir:       "", // No templates directory specified
		DepthLimit:      10,
		ComplexityLimit: 1000,
		BatchSize:       100,
		Timeout:         30,
		Verbose:         false,
	}

	// Run security checks
	findings, templateCount := runSecurityChecks(
		context.Background(),
		schema,
		server.Client(),
		server.URL,
		config,
		nil,
		nil, // No reporter for this test
	)

	// Verify findings are returned
	assert.NotNil(t, findings)

	// Verify template count is 0 when no templates are specified
	assert.Equal(t, 0, templateCount, "should have 0 templates when none specified")
}

// TestMapTemplateSeverity tests the severity mapping function
func TestMapTemplateSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected model.Severity
	}{
		{"CRITICAL", model.SeverityCritical},
		{"HIGH", model.SeverityHigh},
		{"MEDIUM", model.SeverityMedium},
		{"LOW", model.SeverityLow},
		{"INFO", model.SeverityInfo},
		{"UNKNOWN", model.SeverityMedium}, // Default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := mapTemplateSeverity(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
