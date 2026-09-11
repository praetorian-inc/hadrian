package runner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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
	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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
	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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
	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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
	tmpl.CompiledPathPattern = regexp.MustCompile(`/api/users/.*`)
	op := &model.Operation{
		Method: "GET",
		Path:   "/api/users/123",
	}

	assert.True(t, templateApplies(tmpl, op))
}

func TestTemplateApplies_PathPattern_NoMatch(t *testing.T) {
	tmpl := makeCompiledTemplate("test", false, []string{}, "lower", "", "simple")
	tmpl.EndpointSelector.PathPattern = `/api/admin/.*`
	tmpl.CompiledPathPattern = regexp.MustCompile(`/api/admin/.*`)
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
	tmpl.CompiledPathPattern = regexp.MustCompile(`/api/users/.*`)
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/users/{id}",
		RequiresAuth: true,
		PathParams:   []model.Parameter{{Name: "id"}},
	}

	assert.True(t, templateApplies(tmpl, op))
}

// TestTemplateApplies_ParameterScoped proves the CLI selector honors the
// parameter-scoped endpoint_selector fields (query_parameter_names, body_field_names).
func TestTemplateApplies_ParameterScoped(t *testing.T) {
	t.Run("QueryParameterNames matches op with the named query param", func(t *testing.T) {
		tmpl := makeCompiledTemplate("param-query", true, []string{"GET"}, "lower", "", "simple")
		tmpl.EndpointSelector.QueryParameterNames = []string{"filter[user-ids]"}
		op := &model.Operation{
			Method:       "GET",
			Path:         "/api/videos",
			RequiresAuth: true,
			QueryParams: []model.Parameter{
				{Name: "filter[user-ids]", In: "query"},
			},
		}

		assert.True(t, templateApplies(tmpl, op))
	})

	t.Run("QueryParameterNames does not match op without the named query param", func(t *testing.T) {
		tmpl := makeCompiledTemplate("param-query", true, []string{"GET"}, "lower", "", "simple")
		tmpl.EndpointSelector.QueryParameterNames = []string{"filter[user-ids]"}
		op := &model.Operation{
			Method:       "GET",
			Path:         "/api/videos",
			RequiresAuth: true,
			QueryParams: []model.Parameter{
				{Name: "page", In: "query"},
			},
		}

		assert.False(t, templateApplies(tmpl, op))
	})

	t.Run("BodyFieldNames matches op whose body schema has the named field", func(t *testing.T) {
		tmpl := makeCompiledTemplate("param-body", true, []string{"POST"}, "lower", "", "simple")
		tmpl.EndpointSelector.BodyFieldNames = []string{"username"}
		op := &model.Operation{
			Method:       "POST",
			Path:         "/api/users",
			RequiresAuth: true,
			BodySchema: &model.Schema{
				Type: "object",
				Properties: map[string]*model.SchemaProperty{
					"username": {Type: "string"},
				},
			},
		}

		assert.True(t, templateApplies(tmpl, op))
	})

	t.Run("BodyFieldNames does not match op whose body schema lacks the named field", func(t *testing.T) {
		tmpl := makeCompiledTemplate("param-body", true, []string{"POST"}, "lower", "", "simple")
		tmpl.EndpointSelector.BodyFieldNames = []string{"username"}
		op := &model.Operation{
			Method:       "POST",
			Path:         "/api/users",
			RequiresAuth: true,
			BodySchema: &model.Schema{
				Type: "object",
				Properties: map[string]*model.SchemaProperty{
					"email": {Type: "string"},
				},
			},
		}

		assert.False(t, templateApplies(tmpl, op))
	})

	t.Run("HasQueryParameter matches op with a query param", func(t *testing.T) {
		tmpl := makeCompiledTemplate("has-query", true, []string{"GET"}, "lower", "", "simple")
		tmpl.EndpointSelector.HasQueryParameter = true
		op := &model.Operation{
			Method: "GET", Path: "/api/videos", RequiresAuth: true,
			QueryParams: []model.Parameter{{Name: "page", In: "query"}},
		}
		assert.True(t, templateApplies(tmpl, op))
	})
	t.Run("HasQueryParameter does not match op without query params", func(t *testing.T) {
		tmpl := makeCompiledTemplate("has-query", true, []string{"GET"}, "lower", "", "simple")
		tmpl.EndpointSelector.HasQueryParameter = true
		op := &model.Operation{Method: "GET", Path: "/api/videos", RequiresAuth: true}
		assert.False(t, templateApplies(tmpl, op))
	})
	t.Run("HasBodyField matches op with non-empty body schema properties", func(t *testing.T) {
		tmpl := makeCompiledTemplate("has-body", true, []string{"POST"}, "lower", "", "simple")
		tmpl.EndpointSelector.HasBodyField = true
		op := &model.Operation{
			Method: "POST", Path: "/api/users", RequiresAuth: true,
			BodySchema: &model.Schema{Type: "object", Properties: map[string]*model.SchemaProperty{"username": {Type: "string"}}},
		}
		assert.True(t, templateApplies(tmpl, op))
	})
	t.Run("HasBodyField does not match op with nil body schema", func(t *testing.T) {
		tmpl := makeCompiledTemplate("has-body", true, []string{"POST"}, "lower", "", "simple")
		tmpl.EndpointSelector.HasBodyField = true
		op := &model.Operation{Method: "POST", Path: "/api/users", RequiresAuth: true}
		assert.False(t, templateApplies(tmpl, op))
	})
	t.Run("HasBodyField does not match op with empty body schema properties", func(t *testing.T) {
		tmpl := makeCompiledTemplate("has-body", true, []string{"POST"}, "lower", "", "simple")
		tmpl.EndpointSelector.HasBodyField = true
		op := &model.Operation{
			Method: "POST", Path: "/api/users", RequiresAuth: true,
			BodySchema: &model.Schema{Type: "object", Properties: map[string]*model.SchemaProperty{}},
		}
		assert.False(t, templateApplies(tmpl, op))
	})
	t.Run("QueryParameterNames matches case-insensitively", func(t *testing.T) {
		tmpl := makeCompiledTemplate("param-query-ci", true, []string{"GET"}, "lower", "", "simple")
		tmpl.EndpointSelector.QueryParameterNames = []string{"Filter[User-IDs]"}
		op := &model.Operation{
			Method: "GET", Path: "/api/videos", RequiresAuth: true,
			QueryParams: []model.Parameter{{Name: "filter[user-ids]", In: "query"}},
		}
		assert.True(t, templateApplies(tmpl, op))
	})
	t.Run("BodyFieldNames matches case-insensitively", func(t *testing.T) {
		tmpl := makeCompiledTemplate("param-body-ci", true, []string{"POST"}, "lower", "", "simple")
		tmpl.EndpointSelector.BodyFieldNames = []string{"Username"}
		op := &model.Operation{
			Method: "POST", Path: "/api/users", RequiresAuth: true,
			BodySchema: &model.Schema{Type: "object", Properties: map[string]*model.SchemaProperty{"username": {Type: "string"}}},
		}
		assert.True(t, templateApplies(tmpl, op))
	})
}

func TestExecuteTemplate_NoneAttacker_AuthEndpoint(t *testing.T) {
	// Server returns 200 — endpoint accepts unauthenticated request (vulnerable)
	server := newTestServer(200, `{"data": "exposed"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("none-attacker-test", true, []string{"GET"}, "none", "higher", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/users",
		RequiresAuth: true,
	}
	rolesCfg := makeTestRolesConfig()
	authCfg := makeTestAuthConfig(map[string]string{
		"user":  "user-token",
		"admin": "admin-token",
	})

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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
	require.NotEmpty(t, findings, "should produce findings when server accepts unauthenticated request")
	for _, f := range findings {
		assert.Equal(t, "anonymous", f.AttackerRole)
	}
}

func TestExecuteTemplate_NoneAttacker_ServerRejects(t *testing.T) {
	// Server returns 401 — endpoint properly rejects unauthenticated request
	server := newTestServer(401, `{"error": "unauthorized"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("none-attacker-reject", true, []string{"GET"}, "none", "higher", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/users",
		RequiresAuth: true,
	}
	rolesCfg := makeTestRolesConfig()
	authCfg := makeTestAuthConfig(map[string]string{
		"user":  "user-token",
		"admin": "admin-token",
	})

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

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
	assert.Empty(t, findings, "should produce zero findings when server properly rejects")
}

func TestExecuteTemplate_NoneAttacker_NoVictim(t *testing.T) {
	// Server returns 200 — no victim role specified
	server := newTestServer(200, `{"data": "exposed"}`)
	defer server.Close()

	tmpl := makeCompiledTemplate("none-attacker-no-victim", true, []string{"GET"}, "none", "", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/config",
		RequiresAuth: true,
	}
	rolesCfg := makeTestRolesConfig()

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

	findings, err := executeTemplate(
		context.Background(),
		executor,
		mutationExecutor,
		tmpl,
		op,
		rolesCfg,
		nil, // no auth config needed
		server.URL,
	)

	require.NoError(t, err)
	require.Len(t, findings, 1, "should produce exactly one finding with no victim role")
	assert.Equal(t, "anonymous", findings[0].AttackerRole)
	assert.Empty(t, findings[0].VictimRole)
	assert.Equal(t, "none-attacker-no-victim", findings[0].TemplateID, "TemplateID must propagate from the 'none' attacker branch — SARIF dedup depends on it")
}

// TestExecuteTemplate_PropagatesTemplateID drives each finding-construction
// branch in executeTemplate (unauthenticated, "none" attacker, authenticated
// cross-role) and asserts Finding.TemplateID is populated. A regression that
// drops `TemplateID: tmpl.ID` would silently collapse every SARIF result to
// rule "hadrian.unknown" and break GitHub Code Scanning deduplication.
func TestExecuteTemplate_PropagatesTemplateID(t *testing.T) {
	t.Run("unauthenticated endpoint", func(t *testing.T) {
		server := newTestServer(200, `{"data": "exposed"}`)
		defer server.Close()

		tmpl := makeCompiledTemplate("tmpl-unauth", false, []string{"GET"}, "lower", "", "simple")
		op := &model.Operation{Method: "GET", Path: "/api/public"}
		executor := templates.NewExecutor(server.Client(), nil)
		mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

		findings, err := executeTemplate(context.Background(), executor, mutationExecutor, tmpl, op, makeTestRolesConfig(), nil, server.URL)
		require.NoError(t, err)
		require.NotEmpty(t, findings, "unauthenticated branch should produce at least one finding")
		for _, f := range findings {
			assert.Equal(t, "tmpl-unauth", f.TemplateID)
		}
	})

	t.Run("authenticated cross-role", func(t *testing.T) {
		server := newTestServer(200, `{"data": "vulnerable"}`)
		defer server.Close()

		tmpl := makeCompiledTemplate("tmpl-auth", true, []string{"GET"}, "lower", "higher", "simple")
		op := &model.Operation{
			Method:       "GET",
			Path:         "/api/users/{id}",
			RequiresAuth: true,
			PathParams:   []model.Parameter{{Name: "id", Example: "42"}},
		}
		executor := templates.NewExecutor(server.Client(), nil)
		mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

		authCfg := &auth.AuthConfig{
			Method: "bearer",
			Roles: map[string]*auth.RoleAuth{
				"user":  {Token: "user-token"},
				"admin": {Token: "admin-token"},
			},
		}

		findings, err := executeTemplate(context.Background(), executor, mutationExecutor, tmpl, op, makeTestRolesConfig(), authCfg, server.URL)
		require.NoError(t, err)
		require.NotEmpty(t, findings, "authenticated branch should produce at least one finding")
		for _, f := range findings {
			assert.Equal(t, "tmpl-auth", f.TemplateID)
		}
	})
}

// =============================================================================
// Three-role execution tests (anonymous role bug fix)
// =============================================================================

// makeThreeRoleConfig creates a role config with administrator, monitoring, and anonymous roles.
func makeThreeRoleConfig() *roles.RoleConfig {
	return &roles.RoleConfig{
		Roles: []*roles.Role{
			{Name: "administrator", Level: 100},
			{Name: "monitoring", Level: 50},
			{Name: "anonymous", Level: 0},
		},
	}
}

// makeTestCookieAuthConfig creates a cookie auth config with the given role cookies.
func makeTestCookieAuthConfig(roleCookies map[string]string) *auth.AuthConfig {
	roleAuths := make(map[string]*auth.RoleAuth)
	for name, cookie := range roleCookies {
		roleAuths[name] = &auth.RoleAuth{Cookie: cookie}
	}
	return &auth.AuthConfig{
		Method:     "cookie",
		CookieName: "JSESSIONID",
		Roles:      roleAuths,
	}
}

func TestExecuteTemplate_ThreeRoles_SkipsLevelZeroAttacker(t *testing.T) {
	var mu sync.Mutex
	receivedCookies := make([]string, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedCookies = append(receivedCookies, r.Header.Get("Cookie"))
		mu.Unlock()
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data": "test"}`))
	}))
	defer server.Close()

	tmpl := makeCompiledTemplate("bola-test", true, []string{"GET"}, "lower", "higher", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/users/{id}",
		RequiresAuth: true,
		PathParams:   []model.Parameter{{Name: "id", Example: "42"}},
	}
	rolesCfg := makeThreeRoleConfig()
	authCfg := makeTestCookieAuthConfig(map[string]string{
		"administrator": "ADMIN_COOKIE",
		"monitoring":    "MONITORING_COOKIE",
		"anonymous":     "d",
	})

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

	findings, err := executeTemplate(
		context.Background(), executor, mutationExecutor,
		tmpl, op, rolesCfg, authCfg, server.URL,
	)

	require.NoError(t, err)

	// Level-0 anonymous is skipped as BOLA attacker (tested via "none" templates).
	// Only monitoring(50)→administrator(100) pairing should execute.
	assert.Len(t, receivedCookies, 1, "should send 1 request (level-0 attackers skipped)")

	monitoringCookieCount := 0
	for _, c := range receivedCookies {
		if c == "JSESSIONID=MONITORING_COOKIE" {
			monitoringCookieCount++
		}
	}
	assert.Equal(t, 1, monitoringCookieCount, "monitoring should send 1 request")

	attackerRoles := make(map[string]int)
	for _, f := range findings {
		attackerRoles[f.AttackerRole]++
	}
	assert.NotContains(t, attackerRoles, "anonymous", "level-0 anonymous should not appear as BOLA attacker")
	assert.Contains(t, attackerRoles, "monitoring")
}

func TestExecuteTemplate_ThreeAuthenticatedRoles_AllPairingsExecute(t *testing.T) {
	var mu sync.Mutex
	receivedCookies := make([]string, 0)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedCookies = append(receivedCookies, r.Header.Get("Cookie"))
		mu.Unlock()
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data": "test"}`))
	}))
	defer server.Close()

	tmpl := makeCompiledTemplate("bola-test", true, []string{"GET"}, "lower", "higher", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/users/{id}",
		RequiresAuth: true,
		PathParams:   []model.Parameter{{Name: "id", Example: "42"}},
	}
	// All roles have non-zero levels — all are authenticated
	rolesCfg := &roles.RoleConfig{
		Roles: []*roles.Role{
			{Name: "admin", Level: 100},
			{Name: "manager", Level: 50},
			{Name: "viewer", Level: 10},
		},
	}
	authCfg := makeTestCookieAuthConfig(map[string]string{
		"admin":   "ADMIN_COOKIE",
		"manager": "MANAGER_COOKIE",
		"viewer":  "VIEWER_COOKIE",
	})

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

	findings, err := executeTemplate(
		context.Background(), executor, mutationExecutor,
		tmpl, op, rolesCfg, authCfg, server.URL,
	)

	require.NoError(t, err)

	// Expect 3 pairings: viewer→manager, viewer→admin, manager→admin
	assert.Len(t, receivedCookies, 3, "should send 3 requests")
	assert.Len(t, findings, 3, "should produce 3 findings")

	attackerRoles := make(map[string]int)
	for _, f := range findings {
		attackerRoles[f.AttackerRole]++
	}
	assert.Equal(t, 2, attackerRoles["viewer"], "viewer attacks manager and admin")
	assert.Equal(t, 1, attackerRoles["manager"], "manager attacks admin")
}

func TestExecuteTemplate_FailedRoleDoesNotAbortRemaining(t *testing.T) {
	// Server closes connection for manager cookie but succeeds for viewer.
	// Before the fix, the manager failure caused `return nil, err` which aborted
	// viewer testing and discarded all findings.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") == "JSESSIONID=MANAGER_COOKIE" {
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
				return
			}
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data": "test"}`))
	}))
	defer server.Close()

	tmpl := makeCompiledTemplate("bola-test", true, []string{"GET"}, "lower", "higher", "simple")
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/users/{id}",
		RequiresAuth: true,
		PathParams:   []model.Parameter{{Name: "id", Example: "42"}},
	}
	rolesCfg := &roles.RoleConfig{
		Roles: []*roles.Role{
			{Name: "admin", Level: 100},
			{Name: "manager", Level: 50},
			{Name: "viewer", Level: 10},
		},
	}
	authCfg := makeTestCookieAuthConfig(map[string]string{
		"admin":   "ADMIN_COOKIE",
		"manager": "MANAGER_COOKIE",
		"viewer":  "VIEWER_COOKIE",
	})

	executor := templates.NewExecutor(server.Client(), nil)
	mutationExecutor := orchestrator.NewMutationExecutor(server.Client(), nil)

	findings, err := executeTemplate(
		context.Background(), executor, mutationExecutor,
		tmpl, op, rolesCfg, authCfg, server.URL,
	)

	// Should not return error — failed role is logged and skipped
	require.NoError(t, err)

	// Viewer findings should still exist despite manager failure
	viewerFindings := 0
	for _, f := range findings {
		if f.AttackerRole == "viewer" {
			viewerFindings++
		}
	}
	assert.Equal(t, 2, viewerFindings, "viewer should produce 2 findings (vs admin and vs manager)")

	// Manager findings should be absent (its request failed)
	for _, f := range findings {
		assert.NotEqual(t, "manager", f.AttackerRole, "manager should have no findings (request failed)")
	}
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
	}

	err := runTest(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse API spec")
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
		Timeout:              10,
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
	}

	err := runTest(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load roles")
}

// =============================================================================
// executeCacheDeceptionTemplate dispatch-level guard tests (round-3 review)
// =============================================================================

// makeCacheDeceptionCompiledTemplate builds a minimal cache-deception
// CompiledTemplate for dispatch-level guard tests. cfg may be nil (prime_role
// unset).
func makeCacheDeceptionCompiledTemplate(id string, cfg *templates.CacheDeception) *templates.CompiledTemplate {
	tmpl := &templates.Template{
		ID: id,
		Info: templates.TemplateInfo{
			Name:        id,
			Category:    "API8:2023",
			Severity:    "HIGH",
			TestPattern: "cache-deception",
		},
		EndpointSelector: templates.EndpointSelector{
			RequiresAuth: true,
			Methods:      []string{"GET"},
		},
		RoleSelector: templates.RoleSelector{
			AttackerPermissionLevel: "none",
			VictimPermissionLevel:   "all",
		},
		CacheDeception: cfg,
	}
	compiled, err := templates.Compile(tmpl)
	if err != nil {
		panic(fmt.Sprintf("failed to compile cache-deception test template: %v", err))
	}
	return compiled
}

// F6: prime_role unset or naming a non-authenticatable role must skip (produce
// zero findings), never panic.

func TestExecuteCacheDeceptionTemplate_PrimeRoleUnset_Skipped(t *testing.T) {
	server := newTestServer(200, `{"data":"x"}`)
	defer server.Close()

	tmpl := makeCacheDeceptionCompiledTemplate("cd-no-role", nil) // CacheDeception nil
	op := &model.Operation{Method: "GET", Path: "/api/account", RequiresAuth: true}
	authCfg := makeTestAuthConfig(map[string]string{"user1": "user1-token"})
	cacheExecutor := &orchestrator.CacheDeceptionExecutor{MutationExecutor: orchestrator.NewMutationExecutor(server.Client(), nil)}

	findings, err := executeCacheDeceptionTemplate(context.Background(), cacheExecutor, tmpl, op, nil, authCfg, server.URL)

	require.NoError(t, err)
	assert.Empty(t, findings, "must skip (produce zero findings) when cache_deception.prime_role is unset")
}

func TestExecuteCacheDeceptionTemplate_PrimeRoleEmptyString_Skipped(t *testing.T) {
	server := newTestServer(200, `{"data":"x"}`)
	defer server.Close()

	tmpl := makeCacheDeceptionCompiledTemplate("cd-empty-role", &templates.CacheDeception{PrimeRole: "   "})
	op := &model.Operation{Method: "GET", Path: "/api/account", RequiresAuth: true}
	authCfg := makeTestAuthConfig(map[string]string{"user1": "user1-token"})
	cacheExecutor := &orchestrator.CacheDeceptionExecutor{MutationExecutor: orchestrator.NewMutationExecutor(server.Client(), nil)}

	findings, err := executeCacheDeceptionTemplate(context.Background(), cacheExecutor, tmpl, op, nil, authCfg, server.URL)

	require.NoError(t, err)
	assert.Empty(t, findings, "must skip (produce zero findings) when prime_role is blank/whitespace-only")
}

func TestExecuteCacheDeceptionTemplate_PrimeRoleNotAuthenticatable_Skipped(t *testing.T) {
	server := newTestServer(200, `{"data":"x"}`)
	defer server.Close()

	tmpl := makeCacheDeceptionCompiledTemplate("cd-bad-role", &templates.CacheDeception{PrimeRole: "ghost"})
	op := &model.Operation{Method: "GET", Path: "/api/account", RequiresAuth: true}
	authCfg := makeTestAuthConfig(map[string]string{"user1": "user1-token"}) // "ghost" absent
	cacheExecutor := &orchestrator.CacheDeceptionExecutor{MutationExecutor: orchestrator.NewMutationExecutor(server.Client(), nil)}

	findings, err := executeCacheDeceptionTemplate(context.Background(), cacheExecutor, tmpl, op, nil, authCfg, server.URL)

	require.NoError(t, err)
	assert.Empty(t, findings, "must skip (produce zero findings) when prime_role is not authenticatable")
}

func TestExecuteCacheDeceptionTemplate_NilAuthConfig_Skipped(t *testing.T) {
	server := newTestServer(200, `{"data":"x"}`)
	defer server.Close()

	tmpl := makeCacheDeceptionCompiledTemplate("cd-nil-auth", &templates.CacheDeception{PrimeRole: "user1"})
	op := &model.Operation{Method: "GET", Path: "/api/account", RequiresAuth: true}
	cacheExecutor := &orchestrator.CacheDeceptionExecutor{MutationExecutor: orchestrator.NewMutationExecutor(server.Client(), nil)}

	findings, err := executeCacheDeceptionTemplate(context.Background(), cacheExecutor, tmpl, op, nil, nil, server.URL)

	require.NoError(t, err)
	assert.Empty(t, findings, "must skip (produce zero findings) when auth config is nil — priming requires auth")
}

// F8: non-GET operations must be skipped — only GET responses are CDN-cacheable.

func TestExecuteCacheDeceptionTemplate_NonGET_Skipped(t *testing.T) {
	server := newTestServer(200, `{"data":"x"}`)
	defer server.Close()

	tmpl := makeCacheDeceptionCompiledTemplate("cd-non-get", &templates.CacheDeception{PrimeRole: "user1"})
	op := &model.Operation{Method: "POST", Path: "/api/account", RequiresAuth: true}
	authCfg := makeTestAuthConfig(map[string]string{"user1": "user1-token"})
	cacheExecutor := &orchestrator.CacheDeceptionExecutor{MutationExecutor: orchestrator.NewMutationExecutor(server.Client(), nil)}

	findings, err := executeCacheDeceptionTemplate(context.Background(), cacheExecutor, tmpl, op, nil, authCfg, server.URL)

	require.NoError(t, err)
	assert.Empty(t, findings, "cache-deception must only run against GET operations; a non-GET must be skipped")
}

// F7: a required query parameter must be included on BOTH the authenticated
// prime request(s) and the anonymous replay, so both phases hit the same
// cache key.

func TestExecuteCacheDeceptionTemplate_RequiredQueryParam_IncludedOnBothPhases(t *testing.T) {
	var mu sync.Mutex
	var capturedURLs []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedURLs = append(capturedURLs, r.URL.String())
		mu.Unlock()
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data":"x"}`))
	}))
	defer server.Close()

	tmpl := makeCacheDeceptionCompiledTemplate("cd-query-param", &templates.CacheDeception{PrimeRole: "user1", PrimeRepeat: 1})
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/account",
		RequiresAuth: true,
		QueryParams: []model.Parameter{
			{Name: "api_key", In: "query", Required: true, Example: "secret123"},
			{Name: "debug", In: "query", Required: false, Example: "true"}, // optional — must NOT be appended
		},
	}
	authCfg := makeTestAuthConfig(map[string]string{"user1": "user1-token"})
	cacheExecutor := &orchestrator.CacheDeceptionExecutor{MutationExecutor: orchestrator.NewMutationExecutor(server.Client(), nil)}

	_, err := executeCacheDeceptionTemplate(context.Background(), cacheExecutor, tmpl, op, nil, authCfg, server.URL)
	require.NoError(t, err)

	mu.Lock()
	urls := append([]string(nil), capturedURLs...)
	mu.Unlock()

	require.Len(t, urls, 2, "expected exactly 1 prime request + 1 anonymous replay")
	for _, u := range urls {
		assert.Contains(t, u, "api_key=secret123",
			"both the prime and the replay must hit the URL WITH the required query parameter: %s", u)
		assert.False(t, strings.Contains(u, "debug="),
			"an OPTIONAL query parameter must not be appended to the probed URL: %s", u)
	}
}

// =============================================================================
// buildCacheDeceptionPath unit tests (Fix 1, round-4 review)
// =============================================================================

// TestBuildCacheDeceptionPath proves buildCacheDeceptionPath excludes the auth
// query parameter from the shared probe path ONLY when the prime role
// authenticates via a QUERY-located api-key — so the anonymous replay URL never
// carries an auth key — while still including every other required query
// parameter. Header-located auth and no auth at all must include every required
// query parameter, auth included, since neither leaks an auth key onto the
// anonymous replay (a header is never copied onto the URL at all).
func TestBuildCacheDeceptionPath(t *testing.T) {
	op := &model.Operation{
		Path: "/api/account/{id}",
		PathParams: []model.Parameter{
			{Name: "id", Example: "42"},
		},
		QueryParams: []model.Parameter{
			{Name: "api_key", In: "query", Required: true, Example: "secret123"},
			{Name: "format", In: "query", Required: true, Example: "json"},
			{Name: "debug", In: "query", Required: false, Example: "true"},
		},
	}

	t.Run("query-located auth key is omitted; other required params kept", func(t *testing.T) {
		primeAuth := &auth.AuthInfo{Method: "api_key", Location: "query", KeyName: "api_key"}
		path := buildCacheDeceptionPath(op, primeAuth)

		assert.Contains(t, path, "/api/account/42", "path params must still be resolved")
		assert.False(t, strings.Contains(path, "api_key="),
			"the QUERY-located auth key must be excluded from the shared probe path: %s", path)
		assert.Contains(t, path, "format=json",
			"a required query param that is NOT the auth key must still be included: %s", path)
		assert.False(t, strings.Contains(path, "debug="),
			"an optional query param must never be included regardless of auth location: %s", path)
	})

	t.Run("header-located auth includes all required params (including api_key)", func(t *testing.T) {
		primeAuth := &auth.AuthInfo{Method: "bearer", Location: "header", KeyName: "Authorization"}
		path := buildCacheDeceptionPath(op, primeAuth)

		assert.Contains(t, path, "api_key=secret123",
			"header-located auth never rides in the query string, so the required api_key param must be included as-is: %s", path)
		assert.Contains(t, path, "format=json")
		assert.False(t, strings.Contains(path, "debug="))
	})

	t.Run("nil auth includes all required params (including api_key)", func(t *testing.T) {
		path := buildCacheDeceptionPath(op, nil)

		assert.Contains(t, path, "api_key=secret123",
			"with no auth info at all there is no auth query key to exclude: %s", path)
		assert.Contains(t, path, "format=json")
		assert.False(t, strings.Contains(path, "debug="))
	})
}

// TestExecuteCacheDeceptionTemplate_QueryAPIKeyAuth_ExcludedFromReplayURL is the
// end-to-end counterpart to TestBuildCacheDeceptionPath: with a QUERY-located
// api-key victim, it records every request's URL and asserts the PRIME request
// carries the real auth key (added back by applyHeaders, same as any other
// authenticated request) while the ANONYMOUS replay carries no auth key at all —
// and that both phases still carry the other, non-auth required query param, so
// they hit the same cache key modulo the auth key itself.
func TestExecuteCacheDeceptionTemplate_QueryAPIKeyAuth_ExcludedFromReplayURL(t *testing.T) {
	var mu sync.Mutex
	var capturedURLs []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedURLs = append(capturedURLs, r.URL.String())
		mu.Unlock()
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"data":"x"}`))
	}))
	defer server.Close()

	tmpl := makeCacheDeceptionCompiledTemplate("cd-query-api-key", &templates.CacheDeception{PrimeRole: "user1", PrimeRepeat: 1})
	op := &model.Operation{
		Method:       "GET",
		Path:         "/api/account",
		RequiresAuth: true,
		QueryParams: []model.Parameter{
			{Name: "api_key", In: "query", Required: true, Example: "secret123"},
			{Name: "format", In: "query", Required: true, Example: "json"},
		},
	}
	authCfg := &auth.AuthConfig{
		Method:   "api_key",
		Location: "query",
		KeyName:  "api_key",
		Roles: map[string]*auth.RoleAuth{
			"user1": {APIKey: "secret123"},
		},
	}
	cacheExecutor := &orchestrator.CacheDeceptionExecutor{MutationExecutor: orchestrator.NewMutationExecutor(server.Client(), nil)}

	_, err := executeCacheDeceptionTemplate(context.Background(), cacheExecutor, tmpl, op, nil, authCfg, server.URL)
	require.NoError(t, err)

	mu.Lock()
	urls := append([]string(nil), capturedURLs...)
	mu.Unlock()

	require.Len(t, urls, 2, "expected exactly 1 authenticated prime request + 1 anonymous replay")
	primeURL, replayURL := urls[0], urls[1]

	assert.Contains(t, primeURL, "api_key=secret123",
		"the prime request must carry the real auth query key (added back by applyHeaders): %s", primeURL)
	assert.Contains(t, primeURL, "format=json",
		"the prime request must still carry the other required, non-auth query param: %s", primeURL)

	assert.False(t, strings.Contains(replayURL, "api_key"),
		"the anonymous replay must NOT carry the auth query key (name or value) at all: %s", replayURL)
	assert.Contains(t, replayURL, "format=json",
		"the anonymous replay must still carry the non-auth required query param: %s", replayURL)
}
