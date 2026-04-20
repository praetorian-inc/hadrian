package planner

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
)

func TestBuildPrompt_CapsOperations(t *testing.T) {
	ops := make([]*model.Operation, 300)
	for i := range ops {
		ops[i] = &model.Operation{Method: "GET", Path: "/api/test/" + string(rune('A'+i%26)), RequiresAuth: true}
	}
	input := &PlannerInput{
		Spec:      &model.APISpec{Operations: ops},
		Roles:     &roles.RoleConfig{Roles: []*roles.Role{{Name: "user", Level: 10}}},
		Templates: []*templates.CompiledTemplate{},
	}

	prompt := buildPrompt(input)
	lines := strings.Split(prompt, "\n")

	// Count endpoint lines (start with "- GET")
	count := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "- GET /api/test/") {
			count++
		}
	}
	assert.Equal(t, maxOperationsInPrompt, count)
}

func TestBuildPrompt_CapsCustomContext(t *testing.T) {
	longCtx := strings.Repeat("x", 5000)
	input := &PlannerInput{
		Spec:      &model.APISpec{},
		Roles:     &roles.RoleConfig{},
		Templates: []*templates.CompiledTemplate{},
		Options:   PlannerOptions{CustomContext: longCtx},
	}

	prompt := buildPrompt(input)
	// The truncated context should be maxCustomContextLen runes
	assert.True(t, len([]rune(prompt)) < len([]rune(longCtx)))
	assert.NotContains(t, prompt, strings.Repeat("x", maxCustomContextLen+1))
}

func TestBuildPrompt_CustomContextUTF8Safe(t *testing.T) {
	// Multi-byte characters — truncation should not split them
	longCtx := strings.Repeat("é", maxCustomContextLen+100)
	input := &PlannerInput{
		Spec:      &model.APISpec{},
		Roles:     &roles.RoleConfig{},
		Templates: []*templates.CompiledTemplate{},
		Options:   PlannerOptions{CustomContext: longCtx},
	}

	prompt := buildPrompt(input)
	assert.True(t, utf8.ValidString(prompt), "prompt must be valid UTF-8 after truncation")
	// Truncated context should have exactly maxCustomContextLen runes of 'é'
	assert.Equal(t, maxCustomContextLen, strings.Count(prompt, "é"))
}

func TestBuildPrompt_CapsTemplates(t *testing.T) {
	tmpls := make([]*templates.CompiledTemplate, 150)
	for i := range tmpls {
		tmpls[i] = &templates.CompiledTemplate{Template: &templates.Template{
			ID:   "t" + string(rune('0'+i%10)),
			Info: templates.TemplateInfo{Name: "test", Category: "API1", Severity: "HIGH"},
		}}
	}
	input := &PlannerInput{
		Spec:      &model.APISpec{},
		Roles:     &roles.RoleConfig{},
		Templates: tmpls,
	}

	prompt := buildPrompt(input)
	// Count template lines
	count := 0
	for _, l := range strings.Split(prompt, "\n") {
		if strings.HasPrefix(l, "- id=") {
			count++
		}
	}
	assert.Equal(t, maxTemplatesInPrompt, count)
}

func TestBuildPrompt_CapsPriorResults(t *testing.T) {
	results := make([]*model.Finding, 80)
	for i := range results {
		results[i] = &model.Finding{Method: "GET", Endpoint: "/test", Category: "API1"}
	}
	input := &PlannerInput{
		Spec:         &model.APISpec{},
		Roles:        &roles.RoleConfig{},
		Templates:    []*templates.CompiledTemplate{},
		PriorResults: results,
	}

	prompt := buildPrompt(input)
	count := strings.Count(prompt, "- GET /test")
	assert.Equal(t, maxPriorResultsInPrompt, count)
}
