package planner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	openAIEndpoint     = "https://api.openai.com/v1/chat/completions"
	defaultOpenAIModel = "gpt-4o"
)

// OpenAIClient implements LLMClient using the OpenAI chat completions API.
type OpenAIClient struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
}

// NewOpenAIClient creates an OpenAI client. If apiKey is empty, reads OPENAI_API_KEY env var.
// If model is empty, defaults to gpt-4o. If timeout is 0, defaults to 120s.
func NewOpenAIClient(apiKey, model string, timeout time.Duration) (*OpenAIClient, error) {
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY not set")
	}
	if model == "" {
		model = defaultOpenAIModel
	}
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	return &OpenAIClient{
		apiKey:   apiKey,
		model:    model,
		endpoint: openAIEndpoint,
		client:   &http.Client{Timeout: timeout},
	}, nil
}

func (c *OpenAIClient) Generate(ctx context.Context, prompt string) (string, error) {
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
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("OpenAI API call failed: %w", err) //nolint:staticcheck // proper noun
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", &APIError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("OpenAI API returned status %d: %.500s", resp.StatusCode, string(respBody))} //nolint:staticcheck // proper noun
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse OpenAI response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("OpenAI returned no choices") //nolint:staticcheck // proper noun
	}

	return result.Choices[0].Message.Content, nil
}
