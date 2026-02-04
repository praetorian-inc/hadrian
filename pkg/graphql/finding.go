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
	ID           string
	Type         FindingType
	Severity     Severity
	Evidence     string
	Remediation  string
	Details      map[string]interface{}
	Description  string   // Explanation of the vulnerability
	RequestIDs   []string // Request IDs for correlation
	AttackerRole string   // For BOLA/BFLA tests
	VictimRole   string   // For BOLA/BFLA tests
	Endpoint     string   // The endpoint tested
	Method       string   // HTTP method (POST for GraphQL)
	Category     string   // OWASP category (e.g., "API1", "API5")
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
// Output format matches REST runner:
// [SEVERITY] Category - Name METHOD Endpoint
//
//	Description: explanation text
//	Roles: attacker=user, victim=admin (if applicable)
//	Request IDs: req-abc123 (if available)
func (f *Finding) Format() string {
	// Build category-name prefix
	categoryName := string(f.Type)
	if f.Category != "" {
		categoryName = fmt.Sprintf("%s - %s", f.Category, f.Type)
	}

	// Build method-endpoint suffix
	methodEndpoint := ""
	if f.Method != "" && f.Endpoint != "" {
		methodEndpoint = fmt.Sprintf(" %s %s", f.Method, f.Endpoint)
	}

	// First line: [SEVERITY] Category - Name METHOD Endpoint
	result := fmt.Sprintf("[%s] %s%s", f.Severity, categoryName, methodEndpoint)

	// Add description if available (otherwise fall back to Evidence)
	if f.Description != "" {
		result += fmt.Sprintf("\n  Description: %s", f.Description)
	} else if f.Evidence != "" {
		result += fmt.Sprintf("\n  Description: %s", f.Evidence)
	}

	// Add roles if applicable (for BOLA/BFLA tests)
	if f.AttackerRole != "" || f.VictimRole != "" {
		rolesLine := "  Roles:"
		if f.AttackerRole != "" {
			rolesLine += fmt.Sprintf(" attacker=%s", f.AttackerRole)
		}
		if f.VictimRole != "" {
			if f.AttackerRole != "" {
				rolesLine += ","
			}
			rolesLine += fmt.Sprintf(" victim=%s", f.VictimRole)
		}
		result += "\n" + rolesLine
	}

	// Add request IDs if available
	if len(f.RequestIDs) > 0 {
		result += fmt.Sprintf("\n  Request IDs: %s", f.RequestIDs[0])
		for i := 1; i < len(f.RequestIDs); i++ {
			result += fmt.Sprintf(", %s", f.RequestIDs[i])
		}
	}

	return result
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
