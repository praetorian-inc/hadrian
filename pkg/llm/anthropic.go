package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/reporter"
)

// AnthropicClient implements Client using the Anthropic Messages API.
type AnthropicClient struct {
	apiKey        string
	model         string
	endpoint      string // defaults to "https://api.anthropic.com/v1/messages"
	redactor      *reporter.Redactor
	client        *http.Client
	customContext string
}

// NewAnthropicClient creates an Anthropic triage client.
func NewAnthropicClient(apiKey, model string, timeout time.Duration, customContext string) (*AnthropicClient, error) {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY not set")
	}
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	if timeout == 0 {
		timeout = 120 * time.Second
	}
	return &AnthropicClient{
		apiKey:   apiKey,
		model:    model,
		endpoint: "https://api.anthropic.com/v1/messages",
		redactor: reporter.NewRedactor(),
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				DialContext:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			},
		},
		customContext: customContext,
	}, nil
}

func (c *AnthropicClient) Name() string {
	return "anthropic"
}

func (c *AnthropicClient) Triage(ctx context.Context, req *TriageRequest) (*TriageResult, error) {
	prompt := BuildTriagePrompt(req, c.redactor, c.customContext)

	reqBody := map[string]interface{}{
		"model":      c.model,
		"max_tokens": 4096,
		"system":     "You are a security expert. Respond with valid JSON only. Do NOT wrap the response in markdown code fences or backticks.",
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Anthropic API call failed: %w", err) //nolint:staticcheck // proper noun
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxLLMResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Anthropic API returned status %d: %.500s", resp.StatusCode, string(respBody)) //nolint:staticcheck // proper noun
	}

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse Anthropic response: %w", err)
	}

	if result.StopReason == "max_tokens" {
		return nil, fmt.Errorf("Anthropic response truncated (hit max_tokens limit)") //nolint:staticcheck // proper noun
	}

	for _, block := range result.Content {
		if block.Type == "text" {
			return ParseTriageJSON(block.Text, "anthropic")
		}
	}

	return nil, fmt.Errorf("Anthropic returned no text content") //nolint:staticcheck // proper noun
}
