package llm

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTriagePrompt_ContainsFields(t *testing.T) {
	prompt := BuildTriagePrompt(testTriageRequest(), reporter.NewRedactor(), "")
	assert.Contains(t, prompt, "API1")
	assert.Contains(t, prompt, "GET /api/test")
	assert.Contains(t, prompt, "user")
	assert.Contains(t, prompt, "admin")
}

func TestBuildTriagePrompt_CustomContext(t *testing.T) {
	prompt := BuildTriagePrompt(testTriageRequest(), reporter.NewRedactor(), "This is PCI data")
	assert.Contains(t, prompt, "ADDITIONAL CONTEXT:")
	assert.Contains(t, prompt, "This is PCI data")
}

func TestBuildTriagePrompt_EmptyContext(t *testing.T) {
	prompt := BuildTriagePrompt(testTriageRequest(), reporter.NewRedactor(), "")
	assert.NotContains(t, prompt, "ADDITIONAL CONTEXT:")
}

func TestParseTriageJSON_HappyPath(t *testing.T) {
	raw := `{"is_vulnerability":true,"confidence":0.9,"reasoning":"BOLA","severity":"HIGH","recommendations":"Fix it"}`
	result, err := ParseTriageJSON(raw, "test")
	require.NoError(t, err)
	assert.True(t, result.IsVulnerability)
	assert.Equal(t, 0.9, result.Confidence)
	assert.Equal(t, "BOLA", result.Reasoning)
	assert.Equal(t, model.SeverityHigh, result.Severity)
	assert.Equal(t, "test", result.Provider)
}

func TestParseTriageJSON_ReasoningAsArray(t *testing.T) {
	raw := `{"is_vulnerability":true,"confidence":0.8,"reasoning":["step1","step2"],"severity":"MEDIUM","recommendations":"do this"}`
	result, err := ParseTriageJSON(raw, "test")
	require.NoError(t, err)
	assert.Equal(t, "step1; step2", result.Reasoning)
}

func TestParseTriageJSON_RecommendationsAsArray(t *testing.T) {
	raw := `{"is_vulnerability":false,"confidence":0.5,"reasoning":"ok","severity":"LOW","recommendations":["a","b"]}`
	result, err := ParseTriageJSON(raw, "test")
	require.NoError(t, err)
	assert.Equal(t, "a; b", result.Recommendations)
}

func TestParseTriageJSON_UnknownSeverity(t *testing.T) {
	raw := `{"is_vulnerability":true,"confidence":0.5,"reasoning":"x","severity":"UNKNOWN","recommendations":"y"}`
	result, err := ParseTriageJSON(raw, "test")
	require.NoError(t, err)
	assert.Equal(t, model.SeverityMedium, result.Severity) // default fallback
}

func TestParseTriageJSON_MalformedJSON(t *testing.T) {
	_, err := ParseTriageJSON(`{not json}`, "test")
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "failed to parse LLM JSON response"))
}
