package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
	"github.com/praetorian-inc/hadrian/pkg/planner"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TEST-005: normalizeOpKey tests
func TestNormalizeOpKey(t *testing.T) {
	tests := []struct {
		method, path, want string
	}{
		{"GET", "/a", "GET /a"},
		{"get", "/a", "GET /a"},
		{"GET", "/a/", "GET /a"},
		{" GET ", " /a ", "GET /a"},
		{"POST", "/", "POST /"}, // root path preserved
		{"DELETE", "/a/b/", "DELETE /a/b"},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeOpKey(tc.method, tc.path))
		})
	}
}

// TEST-006: newPlannerLLMClient dispatch tests
func TestNewPlannerLLMClient_OpenAI(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Setenv("ANTHROPIC_API_KEY", "")
	client, err := newPlannerLLMClient("openai", "", 60*time.Second)
	require.NoError(t, err)
	assert.IsType(t, &planner.OpenAIClient{}, client)
}

func TestNewPlannerLLMClient_EmptyDefaultsToOpenAI(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	t.Setenv("ANTHROPIC_API_KEY", "")
	client, err := newPlannerLLMClient("", "", 60*time.Second)
	require.NoError(t, err)
	assert.IsType(t, &planner.OpenAIClient{}, client)
}

func TestNewPlannerLLMClient_Anthropic(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("OPENAI_API_KEY", "")
	client, err := newPlannerLLMClient("anthropic", "", 60*time.Second)
	require.NoError(t, err)
	assert.IsType(t, &planner.AnthropicClient{}, client)
}

func TestNewPlannerLLMClient_Ollama(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	client, err := newPlannerLLMClient("ollama", "", 60*time.Second)
	require.NoError(t, err)
	assert.IsType(t, &planner.OllamaClient{}, client)
}

func TestNewPlannerLLMClient_Unknown(t *testing.T) {
	_, err := newPlannerLLMClient("bogus", "", 60*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown planner provider")
	assert.Contains(t, err.Error(), "bogus")
}

// === buildAttackPlan tests (TEST-008) ===

type mockPlannerClient struct {
	response string
	err      error
	called   bool
}

func (m *mockPlannerClient) Generate(_ context.Context, _ string) (string, error) {
	m.called = true
	return m.response, m.err
}

func TestBuildAttackPlan_Disabled(t *testing.T) {
	config := Config{PlannerEnabled: false}
	plan, err := buildAttackPlan(context.Background(), config, nil, nil, nil)
	assert.Nil(t, plan)
	assert.NoError(t, err)
}

func TestBuildAttackPlan_InjectedClient(t *testing.T) {
	mock := &mockPlannerClient{response: `{"steps":[],"reasoning":"test"}`}
	config := Config{
		PlannerEnabled:   true,
		PlannerLLMClient: mock,
	}
	spec := &model.APISpec{}
	rolesCfg := &roles.RoleConfig{}

	plan, err := buildAttackPlan(context.Background(), config, spec, rolesCfg, nil)
	require.NoError(t, err)
	assert.True(t, mock.called)
	assert.NotNil(t, plan)
	assert.Equal(t, "test", plan.Reasoning)
}

func TestBuildAttackPlan_InjectedClientError_PlannerOnly(t *testing.T) {
	// Use APIError with non-retryable status to avoid retry backoffs in tests
	mock := &mockPlannerClient{err: &planner.APIError{StatusCode: 401, Message: "bad key"}}
	config := Config{
		PlannerEnabled:   true,
		PlannerOnly:      true,
		PlannerLLMClient: mock,
	}

	_, err := buildAttackPlan(context.Background(), config, &model.APISpec{}, &roles.RoleConfig{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad key")
}

func TestBuildAttackPlan_InjectedClientError_Fallback(t *testing.T) {
	mock := &mockPlannerClient{err: &planner.APIError{StatusCode: 401, Message: "bad key"}}
	config := Config{
		PlannerEnabled:   true,
		PlannerOnly:      false,
		PlannerLLMClient: mock,
	}

	plan, err := buildAttackPlan(context.Background(), config, &model.APISpec{}, &roles.RoleConfig{}, nil)
	assert.Nil(t, plan)
	assert.Error(t, err) // returns error, RunTest handles fallback
}

// === executePlannedSteps tests (TEST-009) ===

func TestExecutePlannedSteps_NilPlan(t *testing.T) {
	result, executed := executePlannedSteps(context.Background(), nil, nil, nil, nil, nil, nil, nil)
	assert.Empty(t, result.findings)
	assert.Empty(t, result.set)
	assert.Equal(t, 0, executed)
}

func TestExecutePlannedSteps_EmptyPlan(t *testing.T) {
	plan := &planner.AttackPlan{Steps: []planner.AttackStep{}}
	result, executed := executePlannedSteps(context.Background(), plan, nil, nil, nil, nil, nil, nil)
	assert.Empty(t, result.findings)
	assert.Equal(t, 0, executed)
}

func TestExecutePlannedSteps_UnknownTemplate(t *testing.T) {
	plan := &planner.AttackPlan{
		Steps: []planner.AttackStep{
			{ID: "s1", TemplateID: "nonexistent", Method: "GET", Path: "/test"},
		},
	}
	tmpls := []*templates.CompiledTemplate{}
	spec := &model.APISpec{Operations: []*model.Operation{{Method: "GET", Path: "/test"}}}

	result, executed := executePlannedSteps(context.Background(), plan, tmpls, spec, nil, nil, nil, nil)
	assert.Empty(t, result.set)
	assert.Equal(t, 0, executed)
}

func TestExecutePlannedSteps_UnknownOperation(t *testing.T) {
	plan := &planner.AttackPlan{
		Steps: []planner.AttackStep{
			{ID: "s1", TemplateID: "t1", Method: "GET", Path: "/nonexistent"},
		},
	}
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "t1"}},
	}
	spec := &model.APISpec{Operations: []*model.Operation{{Method: "GET", Path: "/other"}}}

	result, executed := executePlannedSteps(context.Background(), plan, tmpls, spec, nil, nil, nil, nil)
	assert.Empty(t, result.set)
	assert.Equal(t, 0, executed)
}

// === Happy-path + dedup tests with real httptest executor (TEST-009, TEST-010) ===

func testServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
}

func testTemplateForServer() *templates.CompiledTemplate {
	compiled, _ := templates.Compile(&templates.Template{
		ID: "test-tmpl",
		Info: templates.TemplateInfo{
			Name: "Test", Category: "API1:2023", Severity: "HIGH",
			TestPattern: "simple",
		},
		EndpointSelector: templates.EndpointSelector{
			Methods: []string{"GET"},
		},
		RoleSelector: templates.RoleSelector{
			AttackerPermissionLevel: "none",
		},
		HTTP: []templates.HTTPTest{
			{
				Method: "{{operation.method}}",
				Path:   "{{operation.path}}",
				Matchers: []templates.Matcher{
					{Type: "status", Status: []int{200}},
				},
			},
		},
		Detection: templates.Detection{
			SuccessIndicators: []templates.Indicator{
				{Type: "status_code", StatusCode: 200},
			},
		},
	})
	return compiled
}

func TestExecutePlannedSteps_HappyPath(t *testing.T) {
	server := testServer()
	defer server.Close()

	tmpl := testTemplateForServer()
	spec := &model.APISpec{
		BaseURL:    server.URL,
		Operations: []*model.Operation{{Method: "GET", Path: "/test"}},
	}
	plan := &planner.AttackPlan{
		Steps: []planner.AttackStep{
			{ID: "s1", TemplateID: "test-tmpl", Method: "GET", Path: "/test"},
		},
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	rateLimiter := NewRateLimiter(100, 100)
	rlClient := NewRateLimitingClient(httpClient, rateLimiter, &RateLimitConfig{Rate: 100, Enabled: true, BackoffType: "exponential", BackoffInitial: time.Second, BackoffMax: time.Second, MaxRetries: 1, StatusCodes: []int{429}})
	executor := templates.NewExecutor(rlClient, nil)
	mutExecutor := orchestrator.NewMutationExecutor(rlClient, nil)
	rolesCfg := &roles.RoleConfig{Roles: []*roles.Role{{Name: "anon", Level: 0}}}

	result, executed := executePlannedSteps(context.Background(), plan, []*templates.CompiledTemplate{tmpl}, spec, executor, mutExecutor, rolesCfg, nil)
	assert.Equal(t, 1, executed)
	assert.Contains(t, result.set, "test-tmpl|GET /test")
}

func TestExecutePlannedSteps_DuplicateDedup(t *testing.T) {
	server := testServer()
	defer server.Close()

	tmpl := testTemplateForServer()
	spec := &model.APISpec{
		BaseURL:    server.URL,
		Operations: []*model.Operation{{Method: "GET", Path: "/test"}},
	}
	plan := &planner.AttackPlan{
		Steps: []planner.AttackStep{
			{ID: "s1", TemplateID: "test-tmpl", Method: "GET", Path: "/test"},
			{ID: "s2", TemplateID: "test-tmpl", Method: "GET", Path: "/test"}, // duplicate
		},
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	rateLimiter := NewRateLimiter(100, 100)
	rlClient := NewRateLimitingClient(httpClient, rateLimiter, &RateLimitConfig{Rate: 100, Enabled: true, BackoffType: "exponential", BackoffInitial: time.Second, BackoffMax: time.Second, MaxRetries: 1, StatusCodes: []int{429}})
	executor := templates.NewExecutor(rlClient, nil)
	mutExecutor := orchestrator.NewMutationExecutor(rlClient, nil)
	rolesCfg := &roles.RoleConfig{Roles: []*roles.Role{{Name: "anon", Level: 0}}}

	result, executed := executePlannedSteps(context.Background(), plan, []*templates.CompiledTemplate{tmpl}, spec, executor, mutExecutor, rolesCfg, nil)
	assert.Equal(t, 1, executed) // dedup prevents second execution
	assert.Len(t, result.set, 1)
}
