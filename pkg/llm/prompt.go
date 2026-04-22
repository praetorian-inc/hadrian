package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/reporter"
)

// BuildTriagePrompt constructs the triage prompt with PII redaction.
// Note: Finding fields (category, endpoint, response body) are interpolated into the prompt.
// A malicious target API could craft responses to influence triage results. Impact is limited
// since triage is advisory and PII redaction is applied.
func BuildTriagePrompt(req *TriageRequest, redactor *reporter.Redactor, customContext string) string {
	redactedResponse := redactor.RedactForLLM(req.Finding.Evidence.Response.Body)

	contextSection := ""
	if customContext != "" {
		contextSection = fmt.Sprintf("\nADDITIONAL CONTEXT:\n%s\n", customContext)
	}

	return fmt.Sprintf(`You are a security expert analyzing API authorization.

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
		getAttackerRoleName(req.AttackerRole),
		getAttackerRolePermissions(req.AttackerRole),
		getVictimRoleName(req.VictimRole),
		getVictimRolePermissions(req.VictimRole),
		req.Finding.Method,
		req.Finding.Endpoint,
		req.Finding.Evidence.Response.StatusCode,
		redactedResponse,
		contextSection,
	)
}

// ParseTriageJSON parses the raw JSON string from any LLM into a TriageResult.
// Handles markdown code fences that Claude commonly wraps around JSON responses.
func ParseTriageJSON(raw string, provider string) (*TriageResult, error) {
	// Extract JSON object from potential markdown fences or surrounding text.
	// Claude routinely wraps responses in ```json ... ``` despite system prompt instructions.
	if start := strings.Index(raw, "{"); start >= 0 {
		if end := strings.LastIndex(raw, "}"); end > start {
			raw = raw[start : end+1]
		}
	}

	var triageData struct {
		IsVulnerability bool            `json:"is_vulnerability"`
		Confidence      float64         `json:"confidence"`
		Reasoning       json.RawMessage `json:"reasoning"`
		Severity        string          `json:"severity"`
		Recommendations json.RawMessage `json:"recommendations"`
	}

	if err := json.Unmarshal([]byte(raw), &triageData); err != nil {
		return nil, fmt.Errorf("failed to parse LLM JSON response: %w", err)
	}

	return &TriageResult{
		Provider:        provider,
		IsVulnerability: triageData.IsVulnerability,
		Confidence:      triageData.Confidence,
		Reasoning:       parseStringOrArray(triageData.Reasoning),
		Severity:        mapSeverity(triageData.Severity),
		Recommendations: parseStringOrArray(triageData.Recommendations),
	}, nil
}

func mapSeverity(s string) model.Severity {
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
		return model.SeverityMedium
	}
}
