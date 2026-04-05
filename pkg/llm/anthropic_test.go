package llm

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/reporter"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnthropicClient_Name(t *testing.T) {
	client := &AnthropicClient{}
	assert.Equal(t, "anthropic", client.Name())
}

func TestNewAnthropicClient_RequiresAPIKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	_, err := NewAnthropicClient("", "claude-sonnet-4-20250514", 120*time.Second, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ANTHROPIC_API_KEY not set")
}

func TestNewAnthropicClient_UsesEnvKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test-123")
	client, err := NewAnthropicClient("", "", 0, "")
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-test-123", client.apiKey)
	assert.Equal(t, "claude-sonnet-4-20250514", client.model)
}

func TestNewAnthropicClient_DefaultTimeout(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	client, err := NewAnthropicClient("", "", 0, "")
	require.NoError(t, err)
	assert.Equal(t, 120*time.Second, client.client.Timeout)
}

func TestAnthropicClient_Triage_ConnectionError(t *testing.T) {
	client := &AnthropicClient{
		apiKey:   "test-key",
		model:    "claude-sonnet-4-20250514",
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 1 * time.Second},
	}

	finding := &model.Finding{
		Category: "API1", Method: "GET", Endpoint: "/test",
		Evidence: model.Evidence{Response: model.HTTPResponse{StatusCode: 200, Body: "test"}},
	}
	req := &TriageRequest{
		Finding:      finding,
		AttackerRole: &roles.Role{Name: "user"},
		VictimRole:   &roles.Role{Name: "admin"},
	}

	_, err := client.Triage(context.Background(), req)
	assert.Error(t, err)
}
