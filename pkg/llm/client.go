package llm

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
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
	// Try Ollama (local)
	if IsOllamaRunning(ctx) {
		return NewOllamaClient(), nil
	}

	return nil, fmt.Errorf("no LLM provider available (run Ollama)")
}

// NewClientWithConfig creates LLM client with explicit configuration
func NewClientWithConfig(ctx context.Context, host, model string, timeout time.Duration, customContext string) (Client, error) {
	// If host is specified, assume Ollama at that host
	if host != "" {
		if IsOllamaRunningAt(ctx, host) {
			return NewOllamaClientWithConfig(host, model, timeout, customContext), nil
		}
		return nil, fmt.Errorf("ollama not reachable at %s", host)
	}
	// Fall back to existing env var logic
	return NewClient(ctx)
}

// NewClientWithProvider creates an LLM client for the specified provider.
func NewClientWithProvider(ctx context.Context, provider, host, model string, timeout time.Duration, customContext string) (Client, error) {
	switch provider {
	case "openai":
		return NewOpenAIClient("", model, timeout, customContext)
	case "anthropic":
		return NewAnthropicClient("", model, timeout, customContext)
	case "ollama", "":
		return NewClientWithConfig(ctx, host, model, timeout, customContext)
	default:
		return nil, fmt.Errorf("unknown LLM provider %q (use ollama, openai, or anthropic)", provider)
	}
}

// IsOllamaRunningAt checks if Ollama is reachable at the given URL
func IsOllamaRunningAt(ctx context.Context, baseURL string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/tags", nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == 200
}

// IsOllamaRunning checks if Ollama is reachable
func IsOllamaRunning(ctx context.Context) bool {
	baseURL := os.Getenv("OLLAMA_HOST")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return IsOllamaRunningAt(ctx, baseURL)
}

// Helper functions for building prompts
func formatPermissions(perms []roles.Permission) string {
	strs := make([]string, len(perms))
	for i, p := range perms {
		strs[i] = p.Raw
	}
	return strings.Join(strs, ", ")
}

func getAttackerRoleName(role *roles.Role) string {
	if role == nil {
		return "(none)"
	}
	return role.Name
}

func getAttackerRolePermissions(role *roles.Role) string {
	if role == nil {
		return "(none)"
	}
	return formatPermissions(role.Permissions)
}

func getVictimRoleName(role *roles.Role) string {
	if role == nil {
		return "(none)"
	}
	return role.Name
}

func getVictimRolePermissions(role *roles.Role) string {
	if role == nil {
		return "(none)"
	}
	return formatPermissions(role.Permissions)
}
