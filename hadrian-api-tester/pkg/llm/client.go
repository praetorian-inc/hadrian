package llm

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
)

// Client abstracts LLM providers for authorization triage
type Client interface {
	Triage(ctx context.Context, req *TriageRequest) (*TriageResult, error)
	Name() string
}

type TriageRequest struct {
	Finding      *model.Finding
	AttackerRole *roles.Role
	VictimRole   *roles.Role
	RoleConfig   *roles.RoleConfig
}

type TriageResult struct {
	Provider        string         `json:"provider"`
	IsVulnerability bool           `json:"is_vulnerability"`
	Confidence      float64        `json:"confidence"` // 0.0-1.0
	Reasoning       string         `json:"reasoning"`
	Severity        model.Severity `json:"severity"`
	Recommendations string         `json:"recommendations"`
}

// NewClient creates LLM client with fallback chain
func NewClient(ctx context.Context) (Client, error) {
	// Try Claude first (best for auth: 23% better)
	if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
		return NewClaudeClient(apiKey), nil
	}

	// Fallback to OpenAI
	if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
		return NewOpenAIClient(apiKey), nil
	}

	// Fallback to Ollama (local)
	if IsOllamaRunning(ctx) {
		return NewOllamaClient(), nil
	}

	return nil, fmt.Errorf("no LLM provider available (set ANTHROPIC_API_KEY, OPENAI_API_KEY, or run Ollama)")
}

func IsOllamaRunning(ctx context.Context) bool {
	// Check if Ollama is reachable
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost:11434/api/tags", nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
