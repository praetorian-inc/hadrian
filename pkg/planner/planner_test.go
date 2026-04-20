package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockLLMClient returns canned responses for testing.
type mockLLMClient struct {
	response string
	err      error
}

func (m *mockLLMClient) Generate(_ context.Context, _ string) (string, error) {
	return m.response, m.err
}

func testInput() *PlannerInput {
	return &PlannerInput{
		Spec: &model.APISpec{
			BaseURL: "http://localhost:8888",
			Operations: []*model.Operation{
				{
					Method:       "GET",
					Path:         "/api/users/{id}",
					RequiresAuth: true,
					PathParams:   []model.Parameter{{Name: "id", In: "path"}},
				},
				{
					Method:       "DELETE",
					Path:         "/api/admin/videos/{video_id}",
					RequiresAuth: true,
					PathParams:   []model.Parameter{{Name: "video_id", In: "path"}},
				},
			},
		},
		Roles: &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "admin", Level: 100, Permissions: []roles.Permission{{Raw: "*:*:*"}}},
				{Name: "user", Level: 10, Permissions: []roles.Permission{{Raw: "read:users:own"}}},
			},
		},
		Templates: []*templates.CompiledTemplate{
			{Template: &templates.Template{
				ID:   "api1-bola-read",
				Info: templates.TemplateInfo{Name: "BOLA Read", Category: "API1:2023", Severity: "HIGH"},
				EndpointSelector: templates.EndpointSelector{
					HasPathParameter: true,
					RequiresAuth:     true,
					Methods:          []string{"GET"},
				},
			}},
			{Template: &templates.Template{
				ID:   "api5-bfla-admin",
				Info: templates.TemplateInfo{Name: "BFLA Admin", Category: "API5:2023", Severity: "CRITICAL"},
				EndpointSelector: templates.EndpointSelector{
					RequiresAuth: true,
					Methods:      []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
				},
			}},
		},
	}
}

func TestBuildPrompt_ContainsEndpoints(t *testing.T) {
	prompt := buildPrompt(testInput())

	assert.Contains(t, prompt, "GET /api/users/{id}")
	assert.Contains(t, prompt, "DELETE /api/admin/videos/{video_id}")
	assert.Contains(t, prompt, "requires-auth")
}

func TestBuildPrompt_ContainsTemplates(t *testing.T) {
	prompt := buildPrompt(testInput())

	assert.Contains(t, prompt, "api1-bola-read")
	assert.Contains(t, prompt, "api5-bfla-admin")
	assert.Contains(t, prompt, "API1:2023")
}

func TestBuildPrompt_ContainsRoles(t *testing.T) {
	prompt := buildPrompt(testInput())

	assert.Contains(t, prompt, `name="admin"`)
	assert.Contains(t, prompt, `name="user"`)
	assert.Contains(t, prompt, "level=100")
}

func TestPlannerWithMockLLM(t *testing.T) {
	cannedResponse := `{
		"reasoning": "Testing BOLA on user endpoint",
		"steps": [
			{
				"id": "step-1",
				"method": "GET",
				"path": "/api/users/{id}",
				"template_id": "api1-bola-read",
				"attacker_role": "user",
				"victim_role": "admin",
				"rationale": "Path param + auth = BOLA candidate"
			}
		]
	}`

	client := &mockLLMClient{response: cannedResponse}
	p := NewPlanner(client)

	plan, err := p.Plan(context.Background(), testInput())
	require.NoError(t, err)
	require.Len(t, plan.Steps, 1)

	assert.Equal(t, "step-1", plan.Steps[0].ID)
	assert.Equal(t, "api1-bola-read", plan.Steps[0].TemplateID)
	assert.Equal(t, "user", plan.Steps[0].AttackerRole)
	assert.Equal(t, "admin", plan.Steps[0].VictimRole)
	assert.Equal(t, "Testing BOLA on user endpoint", plan.Reasoning)
}

func TestParsePlan_BareArray(t *testing.T) {
	raw := `[{"id":"s1","method":"GET","path":"/x","template_id":"t1","attacker_role":"user"}]`

	plan, err := parsePlan(raw)
	require.NoError(t, err)
	require.Len(t, plan.Steps, 1)
	assert.Equal(t, "s1", plan.Steps[0].ID)
}

func TestValidatePlan_DropsUnknownTemplate(t *testing.T) {
	plan := &AttackPlan{
		Steps: []AttackStep{
			{ID: "s1", TemplateID: "api1-bola-read", AttackerRole: "user", Method: "GET", Path: "/api/users/{id}"},
			{ID: "s2", TemplateID: "nonexistent", AttackerRole: "user", Method: "GET", Path: "/api/users/{id}"},
		},
	}

	result := validatePlan(plan, testInput())
	require.Len(t, result.Steps, 1)
	assert.Equal(t, "s1", result.Steps[0].ID)
}

func TestValidatePlan_DropsUnknownRole(t *testing.T) {
	plan := &AttackPlan{
		Steps: []AttackStep{
			{ID: "s1", TemplateID: "api1-bola-read", AttackerRole: "hacker", Method: "GET", Path: "/api/users/{id}"},
		},
	}

	result := validatePlan(plan, testInput())
	assert.Empty(t, result.Steps)
}

func TestValidatePlan_DropsUnknownOperation(t *testing.T) {
	plan := &AttackPlan{
		Steps: []AttackStep{
			{ID: "s1", TemplateID: "api1-bola-read", AttackerRole: "user", Method: "GET", Path: "/api/nonexistent"},
		},
	}

	result := validatePlan(plan, testInput())
	assert.Empty(t, result.Steps)
}

// TEST-002: Plan() failure modes

func TestPlan_LLMError(t *testing.T) {
	client := &mockLLMClient{err: fmt.Errorf("connection refused")}
	p := NewPlanner(client)
	_, err := p.Plan(context.Background(), testInput())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LLM generation failed")
}

func TestPlan_MalformedResponse(t *testing.T) {
	client := &mockLLMClient{response: "not json at all!!!"}
	p := NewPlanner(client)
	_, err := p.Plan(context.Background(), testInput())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse LLM response")
}

func TestPlan_AllStepsDropped(t *testing.T) {
	// Valid JSON but all steps reference nonexistent templates
	client := &mockLLMClient{response: `{"reasoning":"test","steps":[{"id":"s1","method":"GET","path":"/fake","template_id":"fake","attacker_role":"fake"}]}`}
	p := NewPlanner(client)
	plan, err := p.Plan(context.Background(), testInput())
	require.NoError(t, err)
	assert.Empty(t, plan.Steps)
	assert.Equal(t, "test", plan.Reasoning) // reasoning preserved
}

// TEST-003: parsePlan includes both errors

func TestParsePlan_BothErrorsIncluded(t *testing.T) {
	_, err := parsePlan(`{"not_steps": true}this is not json either`)
	require.Error(t, err)
	// Should contain info about both parse attempts
	assert.Contains(t, err.Error(), "AttackPlan")
	assert.Contains(t, err.Error(), "AttackStep")
}

// TEST-004: Additional validatePlan edge cases

func TestValidatePlan_EmptyVictimRole(t *testing.T) {
	plan := &AttackPlan{
		Steps: []AttackStep{
			{ID: "s1", TemplateID: "api1-bola-read", AttackerRole: "user", VictimRole: "", Method: "GET", Path: "/api/users/{id}"},
		},
	}
	result := validatePlan(plan, testInput())
	require.Len(t, result.Steps, 1) // empty victim is allowed
}

func TestValidatePlan_TrailingSlashNormalized(t *testing.T) {
	plan := &AttackPlan{
		Steps: []AttackStep{
			{ID: "s1", TemplateID: "api1-bola-read", AttackerRole: "user", Method: "GET", Path: "/api/users/{id}/"},
		},
	}
	result := validatePlan(plan, testInput())
	require.Len(t, result.Steps, 1) // trailing slash normalized
}

func TestValidatePlan_CaseInsensitiveMethod(t *testing.T) {
	plan := &AttackPlan{
		Steps: []AttackStep{
			{ID: "s1", TemplateID: "api1-bola-read", AttackerRole: "user", Method: "get", Path: "/api/users/{id}"},
		},
	}
	result := validatePlan(plan, testInput())
	require.Len(t, result.Steps, 1) // lowercase method normalized
}

func TestValidatePlan_ReasoningPreservedOnEmpty(t *testing.T) {
	plan := &AttackPlan{
		Reasoning: "No matching templates",
		Steps: []AttackStep{
			{ID: "s1", TemplateID: "nonexistent", AttackerRole: "user", Method: "GET", Path: "/api/users/{id}"},
		},
	}
	result := validatePlan(plan, testInput())
	assert.Empty(t, result.Steps)
	assert.Equal(t, "No matching templates", result.Reasoning)
}

func TestStripCodeFences(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"no fences", `{"steps":[]}`, `{"steps":[]}`},
		{"json fence", "```json\n{\"steps\":[]}\n```", `{"steps":[]}`},
		{"bare fence", "```\n{\"steps\":[]}\n```", `{"steps":[]}`},
		{"fence no closing", "```json\n{\"steps\":[]}", `{"steps":[]}`},
		{"empty string", "", ""},
		{"whitespace around fence", "   ```json\n{\"x\":1}\n```   ", `{"x":1}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, stripCodeFences(tc.input))
		})
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"plain text", "hello world", 100, "hello world"},
		{"empty", "", 100, ""},
		{"shorter than maxLen", "hi", 100, "hi"},
		{"strips ANSI", "\x1b[31mred\x1b[0m", 100, "red"},
		{"strips control chars", "a\x00b\x01c", 100, "abc"},
		{"strips DEL", "a\x7fb", 100, "ab"},
		{"truncates long", "abcdefghij", 5, "abcde..."},
		{"multi-byte preserved", "héllo", 100, "héllo"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeForLog(tc.input, tc.maxLen))
		})
	}
}

func TestAttackStepJSONRoundTrip(t *testing.T) {
	step := AttackStep{
		ID:           "step-1",
		Method:       "GET",
		Path:         "/api/users/{id}",
		TemplateID:   "api1-bola-read",
		AttackerRole: "user",
		VictimRole:   "admin",
		DependsOn:    []string{"step-0"},
		Extract:      map[string]string{"user_id": "data.id"},
	}

	data, err := json.Marshal(step)
	require.NoError(t, err)

	var decoded AttackStep
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, step.ID, decoded.ID)
	assert.Equal(t, step.TemplateID, decoded.TemplateID)
	assert.Equal(t, step.DependsOn, decoded.DependsOn)
	assert.Equal(t, step.Extract, decoded.Extract)
}
