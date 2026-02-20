package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/praetorian-inc/hadrian/pkg/plugins/graphql"
	_ "github.com/praetorian-inc/hadrian/pkg/plugins/grpc"
	_ "github.com/praetorian-inc/hadrian/pkg/plugins/rest"
)

// =============================================================================
// executeTemplate tests
// =============================================================================

// newTestServer creates an httptest server that returns the given status code and body.
func newTestServer(statusCode int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(body))
	}))
}

// makeCompiledTemplate creates a minimal CompiledTemplate for testing.
func makeCompiledTemplate(id string, requiresAuth bool, methods []string, attackerLevel, victimLevel string, testPattern string) *templates.CompiledTemplate {
	tmpl := &templates.Template{
		ID: id,
		Info: templates.TemplateInfo{
			Name:        id,
			Category:    "API1",
			Severity:    "HIGH",
			TestPattern: testPattern,
		},
		EndpointSelector: templates.EndpointSelector{
			RequiresAuth: requiresAuth,
			Methods:      methods,
		},
		RoleSelector: templates.RoleSelector{
			AttackerPermissionLevel: attackerLevel,
			VictimPermissionLevel:   victimLevel,
		},
		HTTP: []templates.HTTPTest{
			{
				Method: "{{operation.method}}",
				Path:   "{{operation.path}}",
				Matchers: []templates.Matcher{
					{
						Type:   "status",
						Status: []int{200},
					},
				},
			},
		},
		Detection: templates.Detection{
			SuccessIndicators: []templates.Indicator{
				{Type: "status_code", StatusCode: 200},
			},
			VulnerabilityPattern: "test",
		},
	}

	compiled, err := templates.Compile(tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to compile test template: %v", err))
	}
	return compiled
}

// makeTestRolesConfig creates a role config with specified roles and levels.
func makeTestRolesConfig() *roles.RoleConfig {
	return &roles.RoleConfig{
		Roles: []*roles.Role{
			{Name: "user", Level: 10},
			{Name: "admin", Level: 100},
		},
	}
}

// makeTestAuthConfig creates a bearer auth config with the given roles.
func makeTestAuthConfig(roleTokens map[string]string) *auth.AuthConfig {
	roleAuths := make(map[string]*auth.RoleAuth)
	for name, token := range roleTokens {
		roleAuths[name] = &auth.RoleAuth{Token: token}
	}
	return &auth.AuthConfig{
		Method:   "bearer",
		Location: "header",
		KeyName:  "Authorization",
		Roles:    roleAuths,
	}
}

func TestExecuteTemplate_UnauthenticatedEndpoint(t *testing.T) {
	// Create a server that returns 200 (matching the vulnerability pattern)
	server := newTestServer(200, `{"data": "exposed"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("unauth-test", false, []string{"GET"}, "lower", "", "simple")
	op := &model.Operation{
		Method: "GET",
		Path:   "/api/public",
	}
	rolesCfg := makeTestRolesConfig()
	executor := templates.NewExecutor(server.Client())
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client())

	findings, err := executeTemplate(
		context.Background(),
		executor,
		mutationExecutor,
		tmpl,
		op,
		rolesCfg,
		nil, // no auth needed
		server.URL,
	)

	require.NoError(t, err)
	// For unauthenticated, runs once without roles
	// Whether matched depends on executor output
	assert.NotNil(t, findings)
}

func TestExecuteTemplate_UnauthenticatedEndpoint_WithPathParams(t *testing.T) {
	server := newTestServer(200, `{"data": "test"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("unauth-params", false, []string{"GET"}, "lower", "", "simple")
	op := &model.Operation{
		Method: "GET",
		Path:   "/api/users/{id}",
		PathParams: []model.Parameter{
			{Name: "id", Example: "42"},
		},
	}
	rolesCfg := makeTestRolesConfig()
	executor := templates.NewExecutor(server.Client())
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client())

	findings, err := executeTemplate(
		context.Background(),
		executor,
		mutationExecutor,
		tmpl,
		op,
		rolesCfg,
		nil,
		server.URL,
	)

	require.NoError(t, err)
	assert.NotNil(t, findings)
}

func TestExecuteTemplate_UnauthenticatedEndpoint_PathParamDefaultValue(t *testing.T) {
	server := newTestServer(200, `{"data": "test"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("unauth-default-param", false, []string{"GET"}, "lower", "", "simple")
	op := &model.Operation{
		Method: "GET",
		Path:   "/api/items/{id}",
		PathParams: []model.Parameter{
			{Name: "id"}, // No example - should default to "1"
		},
	}
	rolesCfg := makeTestRolesConfig()
	executor := templates.NewExecutor(server.Client())
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client())

	findings, err := executeTemplate(
		context.Background(),
		executor,
		mutationExecutor,
		tmpl,
		op,
		rolesCfg,
		nil,
		server.URL,
	)

	require.NoError(t, err)
	assert.NotNil(t, findings)
}

func TestExecuteTemplate_AuthenticatedEndpoint_SkipsSameRole(t *testing.T) {
	server := newTestServer(200, `{"data": "vulnerable"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("auth-test", true, []string{"GET"}, "lower", "higher", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/users/{id}",
		RequiresAuth: true,
		PathParams: []model.Parameter{
			{Name: "id", Example: "42"},
		},
	}
	rolesCfg := makeTestRolesConfig()
	authCfg := makeTestAuthConfig(map[string]string{
		"user":  "user-token",
		"admin": "admin-token",
	})

	executor := templates.NewExecutor(server.Client())
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client())

	findings, err := executeTemplate(
		context.Background(),
		executor,
		mutationExecutor,
		tmpl,
		op,
		rolesCfg,
		authCfg,
		server.URL,
	)

	require.NoError(t, err)
	// Results depend on executor matching, but should not panic
	assert.NotNil(t, findings)
}

func TestExecuteTemplate_AuthenticatedEndpoint_NoVictimRole(t *testing.T) {
	server := newTestServer(200, `{"data": "test"}`)
	defer server.Close()

	// Template with no victim role
	tmpl := makeCompiledTemplate("auth-no-victim", true, []string{"GET"}, "lower", "", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/profile",
		RequiresAuth: true,
	}
	rolesCfg := makeTestRolesConfig()
	authCfg := makeTestAuthConfig(map[string]string{
		"user":  "user-token",
		"admin": "admin-token",
	})

	executor := templates.NewExecutor(server.Client())
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client())

	findings, err := executeTemplate(
		context.Background(),
		executor,
		mutationExecutor,
		tmpl,
		op,
		rolesCfg,
		authCfg,
		server.URL,
	)

	require.NoError(t, err)
	assert.NotNil(t, findings)
}

func TestExecuteTemplate_AuthenticatedEndpoint_RoleNotConfigured(t *testing.T) {
	server := newTestServer(200, `{"data": "test"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("auth-missing-role", true, []string{"GET"}, "all", "all", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/data",
		RequiresAuth: true,
	}

	// Roles config has roles, but auth config only has one token
	rolesCfg := makeTestRolesConfig()
	authCfg := makeTestAuthConfig(map[string]string{
		"user": "user-token",
		// admin has no token
	})

	executor := templates.NewExecutor(server.Client())
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client())

	// Should not error - roles without auth are skipped
	findings, err := executeTemplate(
		context.Background(),
		executor,
		mutationExecutor,
		tmpl,
		op,
		rolesCfg,
		authCfg,
		server.URL,
	)

	require.NoError(t, err)
	assert.NotNil(t, findings)
}

func TestExecuteTemplate_NilAuthConfig(t *testing.T) {
	server := newTestServer(200, `{"data": "test"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("auth-nil-config", true, []string{"GET"}, "lower", "higher", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/data",
		RequiresAuth: true,
	}
	rolesCfg := makeTestRolesConfig()

	executor := templates.NewExecutor(server.Client())
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client())

	// With nil auth config, auth info will be nil for all roles
	findings, err := executeTemplate(
		context.Background(),
		executor,
		mutationExecutor,
		tmpl,
		op,
		rolesCfg,
		nil, // nil auth config
		server.URL,
	)

	require.NoError(t, err)
	assert.NotNil(t, findings)
}

// =============================================================================
// templateApplies tests
// =============================================================================

func TestTemplateApplies_MethodFilter_Match(t *testing.T) {
	tmpl := makeCompiledTemplate("test", false, []string{"GET", "POST"}, "lower", "", "simple")
	op := &model.Operation{Method: "GET", Path: "/api/test"}

	assert.True(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_MethodFilter_NoMatch(t *testing.T) {
	tmpl := makeCompiledTemplate("test", false, []string{"POST"}, "lower", "", "simple")
	op := &model.Operation{Method: "GET", Path: "/api/test"}

	assert.False(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_MethodFilter_CaseInsensitive(t *testing.T) {
	tmpl := makeCompiledTemplate("test", false, []string{"get"}, "lower", "", "simple")
	op := &model.Operation{Method: "GET", Path: "/api/test"}

	assert.True(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_MethodFilter_Empty(t *testing.T) {
	// No method filter = all methods match
	tmpl := makeCompiledTemplate("test", false, []string{}, "lower", "", "simple")
	op := &model.Operation{Method: "DELETE", Path: "/api/test"}

	assert.True(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_PathParameterRequired_HasParams(t *testing.T) {
	tmpl := makeCompiledTemplate("test", false, []string{}, "lower", "", "simple")
	tmpl.EndpointSelector.HasPathParameter = true
	op := &model.Operation{
		Method:     "GET",
		Path:       "/api/users/{id}",
		PathParams: []model.Parameter{{Name: "id"}},
	}

	assert.True(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_PathParameterRequired_NoParams(t *testing.T) {
	tmpl := makeCompiledTemplate("test", false, []string{}, "lower", "", "simple")
	tmpl.EndpointSelector.HasPathParameter = true
	op := &model.Operation{
		Method: "GET",
		Path:   "/api/users",
	}

	assert.False(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_AuthRequired_HasAuth(t *testing.T) {
	tmpl := makeCompiledTemplate("test", true, []string{}, "lower", "", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/data",
		RequiresAuth: true,
	}

	assert.True(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_AuthRequired_NoAuth(t *testing.T) {
	tmpl := makeCompiledTemplate("test", true, []string{}, "lower", "", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/public",
		RequiresAuth: false,
	}

	assert.False(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_PathPattern_Match(t *testing.T) {
	tmpl := makeCompiledTemplate("test", false, []string{}, "lower", "", "simple")
	tmpl.EndpointSelector.PathPattern = `/api/users/.*`
	op := &model.Operation{
		Method: "GET",
		Path:   "/api/users/123",
	}

	assert.True(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_PathPattern_NoMatch(t *testing.T) {
	tmpl := makeCompiledTemplate("test", false, []string{}, "lower", "", "simple")
	tmpl.EndpointSelector.PathPattern = `/api/admin/.*`
	op := &model.Operation{
		Method: "GET",
		Path:   "/api/users/123",
	}

	assert.False(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_AllFiltersMatch(t *testing.T) {
	tmpl := makeCompiledTemplate("test", true, []string{"GET"}, "lower", "", "simple")
	tmpl.EndpointSelector.HasPathParameter = true
	tmpl.EndpointSelector.PathPattern = `/api/users/.*`
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/users/{id}",
		RequiresAuth: true,
		PathParams:   []model.Parameter{{Name: "id"}},
	}

	assert.True(t, templateApplies(tmpl, op))
}

// =============================================================================
// runTest integration tests with httptest
// =============================================================================

func TestRunTest_MissingAPIFile(t *testing.T) {
	ctx := context.Background()
	config := Config{
		API:                  "/nonexistent/api.yaml",
		Roles:                "/nonexistent/roles.yaml",
		RateLimit:            5.0,
		RateLimitBackoff:     "exponential",
		RateLimitMaxWait:     60000000000, // 60s in ns
		RateLimitMaxRetries:  5,
		RateLimitStatusCodes: []int{429, 503},
		Output:               "terminal",
		Concurrency:          1,
	}

	err := runTest(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

func TestRunTest_InvalidAPISpec(t *testing.T) {
	// Create valid roles file and invalid API spec
	tmpDir := t.TempDir()

	apiFile := filepath.Join(tmpDir, "api.yaml")
	_ = os.WriteFile(apiFile, []byte("not valid yaml: [[["), 0644)

	rolesFile := filepath.Join(tmpDir, "roles.yaml")
	_ = os.WriteFile(rolesFile, []byte("roles:\n  - name: user\n    level: 10\n    permissions:\n      - \"read:*:*\"\n"), 0644)

	ctx := context.Background()
	config := Config{
		API:                  apiFile,
		Roles:                rolesFile,
		RateLimit:            5.0,
		RateLimitBackoff:     "exponential",
		RateLimitMaxWait:     60000000000,
		RateLimitMaxRetries:  5,
		RateLimitStatusCodes: []int{429, 503},
		Output:               "terminal",
		Concurrency:          1,
	}

	err := runTest(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse API spec")
}

func TestRunTest_ProductionBlocked(t *testing.T) {
	// Create API spec with production URL
	tmpDir := t.TempDir()

	apiFile := filepath.Join(tmpDir, "api.yaml")
	apiContent := `openapi: "3.0.0"
info:
  title: Prod API
  version: "1.0"
servers:
  - url: https://api.example.com
paths:
  /users:
    get:
      summary: List users
      responses:
        "200":
          description: Success
`
	_ = os.WriteFile(apiFile, []byte(apiContent), 0644)

	rolesFile := filepath.Join(tmpDir, "roles.yaml")
	_ = os.WriteFile(rolesFile, []byte("roles:\n  - name: user\n    level: 10\n    permissions:\n      - \"read:*:*\"\n"), 0644)

	ctx := context.Background()
	config := Config{
		API:                  apiFile,
		Roles:                rolesFile,
		RateLimit:            5.0,
		RateLimitBackoff:     "exponential",
		RateLimitMaxWait:     60000000000,
		RateLimitMaxRetries:  5,
		RateLimitStatusCodes: []int{429, 503},
		Output:               "terminal",
		Concurrency:          1,
		AllowProduction:      false, // should block
	}

	err := runTest(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "production testing blocked")
}

func TestRunTest_FullPipeline(t *testing.T) {
	// Create a test server that responds to requests
	server := newTestServer(200, `{"id": 1, "name": "test"}`)
	defer server.Close()

	// Create API spec pointing to test server
	tmpDir := t.TempDir()

	apiFile := filepath.Join(tmpDir, "api.yaml")
	apiContent := fmt.Sprintf(`openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: %s
paths:
  /users:
    get:
      summary: List users
      responses:
        "200":
          description: Success
`, server.URL)
	_ = os.WriteFile(apiFile, []byte(apiContent), 0644)

	rolesFile := filepath.Join(tmpDir, "roles.yaml")
	_ = os.WriteFile(rolesFile, []byte("roles:\n  - name: user\n    level: 10\n    permissions:\n      - \"read:*:*\"\n  - name: admin\n    level: 100\n    permissions:\n      - \"*:*:*\"\n"), 0644)

	// Create a simple template
	tmplDir := filepath.Join(tmpDir, "templates", "rest", "owasp")
	_ = os.MkdirAll(tmplDir, 0755)
	tmplContent := `id: test-bola
info:
  name: "Test BOLA"
  category: "owasp"
  severity: "HIGH"
  test_pattern: "simple"
endpoint_selector:
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`
	_ = os.WriteFile(filepath.Join(tmplDir, "test-bola.yaml"), []byte(tmplContent), 0644)

	// Unset LLM env vars
	_ = os.Unsetenv("OLLAMA_HOST")

	ctx := context.Background()
	config := Config{
		API:                  apiFile,
		Roles:                rolesFile,
		TemplateDir:          filepath.Join(tmpDir, "templates", "rest"),
		RateLimit:            100.0, // high rate limit for test speed
		RateLimitBackoff:     "exponential",
		RateLimitMaxWait:     60000000000,
		RateLimitMaxRetries:  5,
		RateLimitStatusCodes: []int{429, 503},
		Output:               "terminal",
		Concurrency:          1,
		Timeout:              10,
		AllowInternal:        true,
	}

	err := runTest(ctx, config)
	assert.NoError(t, err)
}

func TestRunTest_BadRolesFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid API spec with localhost URL
	apiFile := filepath.Join(tmpDir, "api.yaml")
	apiContent := `openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
servers:
  - url: http://localhost:9999
paths:
  /users:
    get:
      summary: List users
      responses:
        "200":
          description: Success
`
	_ = os.WriteFile(apiFile, []byte(apiContent), 0644)

	// Create invalid roles file
	rolesFile := filepath.Join(tmpDir, "roles.yaml")
	_ = os.WriteFile(rolesFile, []byte("not: valid: roles: [[["), 0644)

	ctx := context.Background()
	config := Config{
		API:                  apiFile,
		Roles:                rolesFile,
		RateLimit:            5.0,
		RateLimitBackoff:     "exponential",
		RateLimitMaxWait:     60000000000,
		RateLimitMaxRetries:  5,
		RateLimitStatusCodes: []int{429, 503},
		Output:               "terminal",
		Concurrency:          1,
		AllowInternal:        true,
	}

	err := runTest(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load roles")
}
