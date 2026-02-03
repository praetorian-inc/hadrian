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

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/reporter"
)

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
	// Build prompt with PII redaction (CR-1: MANDATORY)
	prompt := o.buildPrompt(req)

	// Prepare Ollama API request
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

	// Make HTTP POST to /api/generate
	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call Ollama API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Ollama API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse Ollama response
	result, err := o.parseResponse(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ollama response: %w", err)
	}

	return result, nil
}

func (o *OllamaClient) buildPrompt(req *TriageRequest) string {
	// CRITICAL: Redact PII from response before LLM (CR-1)
	redactedResponse := o.redactor.RedactForLLM(req.Finding.Evidence.Response.Body)

	// Add custom context section if provided
	contextSection := ""
	if o.customContext != "" {
		contextSection = fmt.Sprintf("\nADDITIONAL CONTEXT:\n%s\n", o.customContext)
	}

	prompt := fmt.Sprintf(`You are a security expert analyzing API authorization.

FINDING:
- Category: %s
- Operation: %s %s
- Attacker Role: %s (permissions: %s)
- Victim Role: %s (permissions: %s)

REQUEST:
%s %s
Authorization: [REDACTED]

RESPONSE (PII REDACTED):
Status: %d
Body: %s
%s
Think step-by-step:
1. Could this be legitimate business logic? (e.g., public resource, shared data)
2. Does the response contain sensitive data for this role?
3. Are the roles truly unauthorized for this access?
4. What is the potential impact if exploited?

Respond with JSON only:
{
  "is_vulnerability": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "your analysis",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "recommendations": "specific mitigation guidance"
}`,
		req.Finding.Category,
		req.Finding.Method,
		req.Finding.Endpoint,
		req.AttackerRole.Name,
		formatPermissions(req.AttackerRole.Permissions),
		getVictimRoleName(req.VictimRole),
		getVictimRolePermissions(req.VictimRole),
		req.Finding.Method,
		req.Finding.Endpoint,
		req.Finding.Evidence.Response.StatusCode,
		redactedResponse, // ← REDACTED PII
		contextSection,
	)

	return prompt
}

func (o *OllamaClient) parseResponse(body io.Reader) (*TriageResult, error) {
	// Ollama response format:
	// {
	//   "model": "llama3.2:latest",
	//   "response": "{\"is_vulnerability\": true, ...}",
	//   "done": true
	// }
	var ollamaResp struct {
		Model    string `json:"model"`
		Response string `json:"response"`
		Done     bool   `json:"done"`
	}

	if err := json.NewDecoder(body).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to decode Ollama response: %w", err)
	}

	// Parse the inner response JSON with flexible field types
	var triageData struct {
		IsVulnerability bool            `json:"is_vulnerability"`
		Confidence      float64         `json:"confidence"`
		Reasoning       json.RawMessage `json:"reasoning"`
		Severity        string          `json:"severity"`
		Recommendations json.RawMessage `json:"recommendations"`
	}

	if err := json.Unmarshal([]byte(ollamaResp.Response), &triageData); err != nil {
		return nil, fmt.Errorf("failed to parse LLM JSON response: %w", err)
	}

	// Handle reasoning field - can be string or array
	reasoning := parseStringOrArray(triageData.Reasoning)

	// Handle recommendations field - can be string or array
	recommendations := parseStringOrArray(triageData.Recommendations)

	// Map severity string to model.Severity
	severity := o.mapSeverity(triageData.Severity)

	result := &TriageResult{
		Provider:        "ollama",
		IsVulnerability: triageData.IsVulnerability,
		Confidence:      triageData.Confidence,
		Reasoning:       reasoning,
		Severity:        severity,
		Recommendations: recommendations,
	}

	return result, nil
}

// parseStringOrArray handles JSON fields that can be either string or []string
func parseStringOrArray(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	// Try parsing as string first
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str
	}

	// Try parsing as array
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return strings.Join(arr, "; ")
	}

	// If both fail, return empty string
	return ""
}

func (o *OllamaClient) mapSeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityMedium // Default fallback
	}
}
