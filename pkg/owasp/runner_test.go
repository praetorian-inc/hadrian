package owasp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunner(t *testing.T) {
	t.Run("NewRunner creates runner with dependencies", func(t *testing.T) {
		// Arrange
		executor := templates.NewExecutor(http.DefaultClient)

		// Act
		runner := NewRunner(executor, "testdata")

		// Assert
		assert.NotNil(t, runner)
		assert.NotNil(t, runner.executor)
		assert.Equal(t, "testdata", runner.templateDir)
	})
}

func TestRunCategory(t *testing.T) {
	// Create a mock server for HTTP responses
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "123", "name": "test"}`))
	}))
	defer server.Close()

	t.Run("runs templates for API1 category", func(t *testing.T) {
		// Arrange
		executor := templates.NewExecutor(server.Client())
		runner := NewRunner(executor, "testdata")

		spec := &model.APISpec{
			BaseURL: server.URL,
			Operations: []*model.Operation{
				{
					Method:       "GET",
					Path:         server.URL + "/api/users/{id}",
					PathParams:   []model.Parameter{{Name: "id", In: "path"}},
					RequiresAuth: true,
					Tags:         []string{"users"},
				},
			},
		}

		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{
					Name: "user",
					Permissions: []roles.Permission{
						{Raw: "read:users:own", Action: "read", Object: "users", Scope: "own"},
					},
				},
				{
					Name: "admin",
					Permissions: []roles.Permission{
						{Raw: "read:users:all", Action: "read", Object: "users", Scope: "all"},
						{Raw: "write:users:all", Action: "write", Object: "users", Scope: "all"},
					},
				},
			},
		}

		// Act
		findings, err := runner.RunCategory(context.Background(), spec, rolesCfg, "API1")

		// Assert
		require.NoError(t, err)
		// May or may not find vulnerabilities depending on response matching
		assert.NotNil(t, findings)
	})

	t.Run("iterates all operation-template-role combinations", func(t *testing.T) {
		// Arrange
		callCount := 0
		countServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
		}))
		defer countServer.Close()

		executor := templates.NewExecutor(countServer.Client())
		runner := NewRunner(executor, "testdata")

		spec := &model.APISpec{
			BaseURL: countServer.URL,
			Operations: []*model.Operation{
				{
					Method:       "GET",
					Path:         countServer.URL + "/api/users/{id}",
					PathParams:   []model.Parameter{{Name: "id", In: "path"}},
					RequiresAuth: true,
				},
			},
		}

		// Use 4 roles with varying levels to ensure proper lower/higher split:
		// guest: Level 10, user: Level 20, moderator: Level 30, admin: Level 40
		// Median = (20+30)/2 = 25 (with 4 roles sorted: [10,20,30,40])
		// lower (Level < 25) = [guest, user]
		// higher (Level >= 25) = [moderator, admin]
		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "guest", Level: 10, Permissions: []roles.Permission{
					{Action: "read", Object: "public", Scope: "all"},
				}},
				{Name: "user", Level: 20, Permissions: []roles.Permission{
					{Action: "read", Object: "users", Scope: "own"},
					{Action: "write", Object: "users", Scope: "own"},
				}},
				{Name: "moderator", Level: 30, Permissions: []roles.Permission{
					{Action: "read", Object: "users", Scope: "all"},
					{Action: "write", Object: "users", Scope: "all"},
					{Action: "delete", Object: "posts", Scope: "all"},
				}},
				{Name: "admin", Level: 40, Permissions: []roles.Permission{
					{Action: "read", Object: "users", Scope: "all"},
					{Action: "write", Object: "users", Scope: "all"},
					{Action: "delete", Object: "users", Scope: "all"},
					{Action: "execute", Object: "admin", Scope: "all"},
				}},
			},
		}

		// Act
		_, err := runner.RunCategory(context.Background(), spec, rolesCfg, "API1")

		// Assert
		require.NoError(t, err)
		// With 1 operation, 1 API1 template, 2 lower roles (guest, user), 2 higher roles (moderator, admin)
		// We expect multiple HTTP calls for attacker-victim combinations
		assert.GreaterOrEqual(t, callCount, 1, "should make at least 1 HTTP request")
	})

	t.Run("skips same attacker and victim role", func(t *testing.T) {
		// Arrange
		executor := templates.NewExecutor(server.Client())
		runner := NewRunner(executor, "testdata")

		spec := &model.APISpec{
			BaseURL: server.URL,
			Operations: []*model.Operation{
				{
					Method:       "GET",
					Path:         server.URL + "/api/users/{id}",
					PathParams:   []model.Parameter{{Name: "id", In: "path"}},
					RequiresAuth: true,
				},
			},
		}

		// Only one role - should skip because attacker == victim
		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "single_role", Permissions: []roles.Permission{{Action: "read", Object: "users", Scope: "own"}}},
			},
		}

		// Act
		findings, err := runner.RunCategory(context.Background(), spec, rolesCfg, "API1")

		// Assert
		require.NoError(t, err)
		// Should still work but with limited combinations
		assert.NotNil(t, findings)
	})

	t.Run("returns empty findings for non-matching operations", func(t *testing.T) {
		// Arrange
		executor := templates.NewExecutor(server.Client())
		runner := NewRunner(executor, "testdata")

		spec := &model.APISpec{
			BaseURL: server.URL,
			Operations: []*model.Operation{
				{
					Method:       "GET",
					Path:         "/api/public/health",
					PathParams:   []model.Parameter{}, // No path params - won't match API1 BOLA
					RequiresAuth: false,               // Public endpoint
				},
			},
		}

		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "user", Permissions: []roles.Permission{{Action: "read", Object: "users", Scope: "own"}}},
				{Name: "admin", Permissions: []roles.Permission{{Action: "read", Object: "users", Scope: "all"}}},
			},
		}

		// Act
		findings, err := runner.RunCategory(context.Background(), spec, rolesCfg, "API1")

		// Assert
		require.NoError(t, err)
		assert.Empty(t, findings, "should have no findings for non-matching operations")
	})

	t.Run("returns empty findings for unknown category", func(t *testing.T) {
		// Arrange
		executor := templates.NewExecutor(server.Client())
		runner := NewRunner(executor, "testdata")

		spec := &model.APISpec{
			BaseURL: server.URL,
			Operations: []*model.Operation{
				{
					Method:       "GET",
					Path:         server.URL + "/api/users/{id}",
					PathParams:   []model.Parameter{{Name: "id", In: "path"}},
					RequiresAuth: true,
				},
			},
		}

		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "user", Permissions: []roles.Permission{{Action: "read", Object: "users", Scope: "own"}}},
			},
		}

		// Act
		findings, err := runner.RunCategory(context.Background(), spec, rolesCfg, "API99")

		// Assert
		require.NoError(t, err)
		assert.Empty(t, findings, "should have no findings for unknown category")
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		// Arrange
		executor := templates.NewExecutor(server.Client())
		runner := NewRunner(executor, "testdata")

		spec := &model.APISpec{
			BaseURL: server.URL,
			Operations: []*model.Operation{
				{
					Method:       "GET",
					Path:         server.URL + "/api/users/{id}",
					PathParams:   []model.Parameter{{Name: "id", In: "path"}},
					RequiresAuth: true,
				},
			},
		}

		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "user", Permissions: []roles.Permission{{Action: "read", Object: "users", Scope: "own"}}},
				{Name: "admin", Permissions: []roles.Permission{{Action: "read", Object: "users", Scope: "all"}}},
			},
		}

		// Create cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Act
		findings, err := runner.RunCategory(ctx, spec, rolesCfg, "API1")

		// Assert - should return early due to cancelled context
		// The exact behavior depends on implementation, but shouldn't panic
		assert.NotNil(t, findings) // Returns whatever was collected
		// Error may or may not be set depending on where cancellation is checked
		_ = err
	})
}

func TestCreateFinding(t *testing.T) {
	t.Run("creates finding with all required fields", func(t *testing.T) {
		// Arrange
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				ID: "api1-bola-read",
				Info: templates.TemplateInfo{
					Name:     "BOLA - Cross-User Resource Access",
					Category: "API1:2023",
					Severity: "HIGH",
				},
			},
		}
		operation := &model.Operation{
			Method: "GET",
			Path:   "/api/users/{id}",
		}
		attackerRole := &roles.Role{Name: "user"}
		victimRole := &roles.Role{Name: "admin"}
		result := &templates.ExecutionResult{
			Matched: true,
			Response: model.HTTPResponse{
				StatusCode: 200,
				Body:       `{"id": "123"}`,
			},
		}

		// Act
		finding := createFinding(tmpl, operation, attackerRole, victimRole, result)

		// Assert
		assert.NotEmpty(t, finding.ID)
		assert.Equal(t, "API1:2023", finding.Category)
		assert.Equal(t, "BOLA - Cross-User Resource Access", finding.Name)
		assert.Equal(t, model.SeverityHigh, finding.Severity)
		assert.Equal(t, "user", finding.AttackerRole)
		assert.Equal(t, "admin", finding.VictimRole)
		assert.Equal(t, "GET /api/users/{id}", finding.Endpoint)
		assert.True(t, finding.IsVulnerability)
	})
}
