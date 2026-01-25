package model

import "time"

// Finding represents a security issue discovered during testing
type Finding struct {
	ID              string    `json:"id"`
	Category        string    `json:"category"`     // API1, API2, etc.
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Severity        Severity  `json:"severity"`
	Confidence      float64   `json:"confidence"`   // 0.0-1.0
	IsVulnerability bool      `json:"is_vulnerability"`

	// Evidence
	Endpoint     string    `json:"endpoint"`      // GET /api/users/{id}
	Method       string    `json:"method"`
	AttackerRole string    `json:"attacker_role"`
	VictimRole   string    `json:"victim_role,omitempty"`

	Evidence    Evidence   `json:"evidence"`
	LLMAnalysis *LLMTriage `json:"llm_analysis,omitempty"`

	Timestamp   time.Time `json:"timestamp"`
}

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Evidence struct {
	Request  HTTPRequest  `json:"request"`
	Response HTTPResponse `json:"response"`

	// For three-phase mutation tests
	SetupResponse  *HTTPResponse `json:"setup_response,omitempty"`
	AttackResponse *HTTPResponse `json:"attack_response,omitempty"`
	VerifyResponse *HTTPResponse `json:"verify_response,omitempty"`
	ResourceID     string        `json:"resource_id,omitempty"`
}

type HTTPRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}

type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	BodyHash   string            `json:"body_hash"`   // SHA-256 for comparison
	Size       int               `json:"size"`
	Truncated  bool              `json:"truncated"`
}

type LLMTriage struct {
	Provider        string  `json:"provider"`  // claude, openai, ollama
	IsVulnerability bool    `json:"is_vulnerability"`
	Confidence      float64 `json:"confidence"`
	Reasoning       string  `json:"reasoning"`
	Recommendations string  `json:"recommendations"`
}
