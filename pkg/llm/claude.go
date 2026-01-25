package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/reporter"
	"github.com/praetorian-inc/hadrian/pkg/roles"
)

type ClaudeClient struct {
	apiKey   string
	redactor *reporter.Redactor
}

func NewClaudeClient(apiKey string) *ClaudeClient {
	return &ClaudeClient{
		apiKey:   apiKey,
		redactor: reporter.NewRedactor(),
	}
}

func (c *ClaudeClient) Name() string {
	return "claude"
}

func (c *ClaudeClient) Triage(ctx context.Context, req *TriageRequest) (*TriageResult, error) {
	// Build prompt with PII redaction (CR-1: MANDATORY)
	prompt := c.buildPrompt(req)
	_ = prompt // TODO: Use prompt with actual Claude API call

	// For now, return mock response (actual API integration in future)
	// This allows template-driven testing to work without API keys
	result := &TriageResult{
		Provider:        "claude",
		IsVulnerability: true,
		Confidence:      0.8,
		Reasoning:       "Mock LLM response - implement actual Claude API call here",
		Severity:        model.SeverityHigh,
		Recommendations: "Implement proper authorization checks",
	}

	return result, nil
}

func (c *ClaudeClient) buildPrompt(req *TriageRequest) string {
	// CRITICAL: Redact PII from response before LLM (CR-1)
	redactedResponse := c.redactor.RedactForLLM(req.Finding.Evidence.Response.Body)

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
	)

	return prompt
}

func formatPermissions(perms []roles.Permission) string {
	strs := make([]string, len(perms))
	for i, p := range perms {
		strs[i] = p.Raw
	}
	return strings.Join(strs, ", ")
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
