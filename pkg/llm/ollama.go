package llm

import (
	"context"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

type OllamaClient struct {
}

func NewOllamaClient() *OllamaClient {
	return &OllamaClient{}
}

func (o *OllamaClient) Name() string {
	return "ollama"
}

func (o *OllamaClient) Triage(ctx context.Context, req *TriageRequest) (*TriageResult, error) {
	// Stub implementation - actual Ollama API integration to be added later
	result := &TriageResult{
		Provider:        "ollama",
		IsVulnerability: true,
		Confidence:      0.7,
		Reasoning:       "Mock Ollama response - implement actual API call here",
		Severity:        model.SeverityMedium,
		Recommendations: "Implement proper authorization checks",
	}

	return result, nil
}
