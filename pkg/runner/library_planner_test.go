package runner

import (
	"testing"
	"time"

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
	client, err := newPlannerLLMClient("openai", "", 60*time.Second)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewPlannerLLMClient_EmptyDefaultsToOpenAI(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	client, err := newPlannerLLMClient("", "", 60*time.Second)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewPlannerLLMClient_Anthropic(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	client, err := newPlannerLLMClient("anthropic", "", 60*time.Second)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewPlannerLLMClient_Ollama(t *testing.T) {
	client, err := newPlannerLLMClient("ollama", "", 60*time.Second)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewPlannerLLMClient_Unknown(t *testing.T) {
	_, err := newPlannerLLMClient("bogus", "", 60*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown planner provider")
	assert.Contains(t, err.Error(), "bogus")
}
