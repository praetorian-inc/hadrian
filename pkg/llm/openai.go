package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/reporter"
)

// OpenAIClient implements Client using the OpenAI chat completions API.
type OpenAIClient struct {
	apiKey        string
	model         string
	redactor      *reporter.Redactor
	client        *http.Client
	customContext string
}

// NewOpenAIClient creates an OpenAI triage client.
func NewOpenAIClient(apiKey, model string, timeout time.Duration, customContext string) (*OpenAIClient, error) {
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY not set")
	}
	if model == "" {
		model = "gpt-4o"
	}
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	return &OpenAIClient{
		apiKey:        apiKey,
		model:         model,
		redactor:      reporter.NewRedactor(),
		client:        &http.Client{Timeout: timeout},
		customContext: customContext,
	}, nil
}

func (c *OpenAIClient) Name() string {
	return "openai"
}

func (c *OpenAIClient) Triage(ctx context.Context, req *TriageRequest) (*TriageResult, error) {
	prompt := BuildTriagePrompt(req, c.redactor, c.customContext)

	reqBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security expert. Respond with valid JSON only."},
			{"role": "user", "content": prompt},
		},
		"temperature":     0.2,
		"response_format": map[string]string{"type": "json_object"},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OpenAI API call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxLLMResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OpenAI API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAI response: %w", err)
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("OpenAI returned no choices")
	}

	return ParseTriageJSON(result.Choices[0].Message.Content, "openai")
}
