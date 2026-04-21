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
	anthropicEndpoint     = "https://api.anthropic.com/v1/messages"
	defaultAnthropicModel = "claude-sonnet-4-20250514"
	anthropicAPIVersion   = "2023-06-01"
)

// AnthropicClient implements LLMClient using the Anthropic Messages API.
type AnthropicClient struct {
	apiKey   string
	model    string
	endpoint string
	client   *http.Client
}

// NewAnthropicClient creates an Anthropic client. If apiKey is empty, reads ANTHROPIC_API_KEY env var.
// If model is empty, defaults to claude-sonnet-4-20250514. If timeout is 0, defaults to 120s.
func NewAnthropicClient(apiKey, model string, timeout time.Duration) (*AnthropicClient, error) {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}
	if model == "" {
		model = defaultAnthropicModel
	}
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	return &AnthropicClient{
		apiKey:   apiKey,
		model:    model,
		endpoint: anthropicEndpoint,
		client:   &http.Client{Timeout: timeout},
	}, nil
}

func (c *AnthropicClient) Generate(ctx context.Context, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model":       c.model,
		"max_tokens":  4096,
		"temperature": 0.2,
		"system":      "You are a security expert. Respond with valid JSON only.",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
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
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("Anthropic API call failed: %w", err) //nolint:staticcheck // proper noun
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if int64(len(respBody)) > maxResponseSize {
		return "", fmt.Errorf("Anthropic response exceeded %d byte limit", maxResponseSize) //nolint:staticcheck // proper noun
	}

	if resp.StatusCode != http.StatusOK {
		return "", &APIError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("Anthropic API returned status %d: %.500s", resp.StatusCode, string(respBody))} //nolint:staticcheck // proper noun
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse Anthropic response: %w", err)
	}

	if result.StopReason == "max_tokens" {
		return "", fmt.Errorf("Anthropic response truncated (hit max_tokens limit)") //nolint:staticcheck // proper noun
	}

	for _, block := range result.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}

	return "", fmt.Errorf("Anthropic returned no text content") //nolint:staticcheck // proper noun
}
