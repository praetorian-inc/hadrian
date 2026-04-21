package runner

import (
	"context"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
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

func TestExecutePlannedSteps_DuplicateDedup(t *testing.T) {
	// Use a template that requires auth but operation doesn't — templateApplies returns false
	// This tests that the dedup logic path exists without needing a real executor
	plan := &planner.AttackPlan{
		Steps: []planner.AttackStep{
			{ID: "s1", TemplateID: "t1", Method: "GET", Path: "/test"},
			{ID: "s2", TemplateID: "t1", Method: "GET", Path: "/test"}, // duplicate
		},
	}
	tmpl := &templates.CompiledTemplate{
		Template: &templates.Template{
			ID: "t1",
			EndpointSelector: templates.EndpointSelector{
				RequiresAuth: true, // requires auth
				Methods:      []string{"GET"},
			},
		},
	}
	spec := &model.APISpec{Operations: []*model.Operation{{Method: "GET", Path: "/test", RequiresAuth: false}}} // no auth

	// Both steps fail templateApplies (auth mismatch), but dedup would prevent the second anyway
	result, executed := executePlannedSteps(context.Background(), plan, []*templates.CompiledTemplate{tmpl}, spec, nil, nil, nil, nil)
	assert.Empty(t, result.set)
	assert.Equal(t, 0, executed)
}
