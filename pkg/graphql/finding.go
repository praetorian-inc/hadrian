package graphql

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// FindingType represents the type of security finding
type FindingType string

const (
	// FindingTypeIntrospectionDisclosure indicates GraphQL introspection is enabled
	FindingTypeIntrospectionDisclosure FindingType = "introspection-disclosure"
	// FindingTypeNoDepthLimit indicates no query depth limit is enforced
	FindingTypeNoDepthLimit FindingType = "no-depth-limit"
	// FindingTypeNoBatchingLimit indicates no batching limit is enforced
	FindingTypeNoBatchingLimit FindingType = "no-batching-limit"
	// FindingTypeNoComplexityLimit indicates no complexity limit is enforced
	FindingTypeNoComplexityLimit FindingType = "no-complexity-limit"
	// FindingTypeBOLA indicates Broken Object Level Authorization vulnerability
	FindingTypeBOLA FindingType = "bola"
	// FindingTypeBFLA indicates Broken Function Level Authorization vulnerability
	FindingTypeBFLA FindingType = "bfla"
)

// String returns the string representation of FindingType
func (f FindingType) String() string {
	return string(f)
}

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// String returns the string representation of Severity
func (s Severity) String() string {
	return string(s)
}

// Finding represents a security finding from GraphQL testing
type Finding struct {
	ID          string
	Type        FindingType
	Severity    Severity
	Evidence    string
	Remediation string
	Details     map[string]interface{}
}

// NewFinding creates a new Finding with a unique ID
func NewFinding(findingType FindingType, severity Severity, evidence string) *Finding {
	return &Finding{
		ID:       generateID(),
		Type:     findingType,
		Severity: severity,
		Evidence: evidence,
		Details:  make(map[string]interface{}),
	}
}

// WithRemediation adds remediation guidance to the finding (fluent builder)
func (f *Finding) WithRemediation(remediation string) *Finding {
	f.Remediation = remediation
	return f
}

// WithDetails adds additional details to the finding (fluent builder)
func (f *Finding) WithDetails(details map[string]interface{}) *Finding {
	f.Details = details
	return f
}

// generateID generates a unique hexadecimal ID for the finding
func generateID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// crypto/rand.Read only fails if system randomness source fails
		// This is catastrophic and should panic since ID uniqueness is critical
		panic(fmt.Sprintf("failed to generate random ID: %v", err))
	}
	return hex.EncodeToString(b)
}

// Format returns a formatted string for terminal display
func (f *Finding) Format() string {
	return fmt.Sprintf("[%s] %s: %s", f.Severity, f.Type, f.Evidence)
}

// FormatFindings returns formatted output for multiple findings
func FormatFindings(findings []*Finding) string {
	if len(findings) == 0 {
		return "No security findings detected."
	}

	result := fmt.Sprintf("=== Security Findings (%d) ===\n\n", len(findings))
	for _, f := range findings {
		result += f.Format() + "\n"
	}
	return result
}
