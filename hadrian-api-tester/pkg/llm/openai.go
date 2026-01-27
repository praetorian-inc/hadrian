package llm

import (
	"context"

	"github.com/praetorian-inc/hadrian/pkg/model"
)

type OpenAIClient struct {
	apiKey string
}

func NewOpenAIClient(apiKey string) *OpenAIClient {
	return &OpenAIClient{
		apiKey: apiKey,
	}
}

func (o *OpenAIClient) Name() string {
	return "openai"
}

func (o *OpenAIClient) Triage(ctx context.Context, req *TriageRequest) (*TriageResult, error) {
	// Stub implementation - actual OpenAI API integration to be added later
	result := &TriageResult{
		Provider:        "openai",
		IsVulnerability: true,
		Confidence:      0.75,
		Reasoning:       "Mock OpenAI response - implement actual API call here",
		Severity:        model.SeverityHigh,
		Recommendations: "Implement proper authorization checks",
	}

	return result, nil
}
