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

func TestOpenAIClient_Name(t *testing.T) {
	client := &OpenAIClient{}
	assert.Equal(t, "openai", client.Name())
}

func TestNewOpenAIClient_RequiresAPIKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	_, err := NewOpenAIClient("", "gpt-4o", 120*time.Second, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OPENAI_API_KEY not set")
}

func TestNewOpenAIClient_UsesEnvKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test-123")
	client, err := NewOpenAIClient("", "", 0, "")
	require.NoError(t, err)
	assert.Equal(t, "sk-test-123", client.apiKey)
	assert.Equal(t, "gpt-4o", client.model)
}

func TestNewOpenAIClient_DefaultTimeout(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	client, err := NewOpenAIClient("", "", 0, "")
	require.NoError(t, err)
	assert.Equal(t, 120*time.Second, client.client.Timeout)
}

func TestOpenAIClient_Triage_ConnectionError(t *testing.T) {
	client := &OpenAIClient{
		apiKey:   "test-key",
		model:    "gpt-4o",
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
