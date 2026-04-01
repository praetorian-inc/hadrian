package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/reporter"
)

// MaxLLMResponseBodySize is the maximum size for LLM API responses (1MB)
// LLM responses should be smaller than general HTTP responses
const MaxLLMResponseBodySize = 1 * 1024 * 1024

type OllamaClient struct {
	baseURL       string
	model         string
	redactor      *reporter.Redactor
	client        *http.Client
	customContext string
}

// NewOllamaClientWithURL creates an Ollama client with custom base URL (for testing)
func NewOllamaClientWithURL(baseURL string) *OllamaClient {
	model := os.Getenv("OLLAMA_MODEL")
	if model == "" {
		model = "llama3.2:latest"
	}

	return &OllamaClient{
		baseURL:  baseURL,
		model:    model,
		redactor: reporter.NewRedactor(),
		client:   &http.Client{Timeout: 60 * time.Second},
	}
}

// NewOllamaClient creates an Ollama client using OLLAMA_HOST env var or default localhost:11434
func NewOllamaClient() *OllamaClient {
	baseURL := os.Getenv("OLLAMA_HOST")
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return NewOllamaClientWithURL(baseURL)
}

// NewOllamaClientWithConfig creates an Ollama client with explicit host, model, and timeout
func NewOllamaClientWithConfig(baseURL, modelName string, timeout time.Duration, customContext string) *OllamaClient {
	if modelName == "" {
		modelName = os.Getenv("OLLAMA_MODEL")
		if modelName == "" {
			modelName = "llama3.2:latest"
		}
	}
	return &OllamaClient{
		baseURL:       baseURL,
		model:         modelName,
		redactor:      reporter.NewRedactor(),
		client:        &http.Client{Timeout: timeout},
		customContext: customContext,
	}
}

func (o *OllamaClient) Name() string {
	return "ollama"
}

func (o *OllamaClient) Triage(ctx context.Context, req *TriageRequest) (*TriageResult, error) {
	prompt := BuildTriagePrompt(req, o.redactor, o.customContext)

	ollamaReq := map[string]interface{}{
		"model":  o.model,
		"prompt": prompt,
		"stream": false,
		"format": "json",
	}

	body, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call Ollama API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxLLMResponseBodySize))
		return nil, fmt.Errorf("ollama API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Ollama wraps the response in {"response": "<json string>"}
	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxLLMResponseBodySize)).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to decode Ollama response: %w", err)
	}

	return ParseTriageJSON(ollamaResp.Response, "ollama")
}

// parseStringOrArray handles JSON fields that can be either string or []string
func parseStringOrArray(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}

	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return strings.Join(arr, "; ")
	}

	return ""
}
