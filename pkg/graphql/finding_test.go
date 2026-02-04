package graphql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFinding_CreatesWithRequiredFields(t *testing.T) {
	finding := NewFinding(
		FindingTypeIntrospectionDisclosure,
		SeverityMedium,
		"Introspection is enabled",
	)

	assert.Equal(t, FindingTypeIntrospectionDisclosure, finding.Type)
	assert.Equal(t, SeverityMedium, finding.Severity)
	assert.Equal(t, "Introspection is enabled", finding.Evidence)
	assert.NotEmpty(t, finding.ID)
}

func TestNewFinding_GeneratesUniqueIDs(t *testing.T) {
	f1 := NewFinding(FindingTypeIntrospectionDisclosure, SeverityMedium, "test1")
	f2 := NewFinding(FindingTypeIntrospectionDisclosure, SeverityMedium, "test2")

	assert.NotEqual(t, f1.ID, f2.ID)
}

func TestFindingType_String(t *testing.T) {
	tests := []struct {
		findingType FindingType
		expected    string
	}{
		{FindingTypeIntrospectionDisclosure, "introspection-disclosure"},
		{FindingTypeNoDepthLimit, "no-depth-limit"},
		{FindingTypeNoBatchingLimit, "no-batching-limit"},
		{FindingTypeNoComplexityLimit, "no-complexity-limit"},
		{FindingTypeBOLA, "bola"},
		{FindingTypeBFLA, "bfla"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.findingType.String())
		})
	}
}

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityInfo, "INFO"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.String())
		})
	}
}

func TestFinding_WithRemediation(t *testing.T) {
	finding := NewFinding(
		FindingTypeIntrospectionDisclosure,
		SeverityMedium,
		"Introspection is enabled",
	).WithRemediation("Disable introspection in production")

	assert.Equal(t, "Disable introspection in production", finding.Remediation)
}

func TestFinding_WithDetails(t *testing.T) {
	finding := NewFinding(
		FindingTypeNoDepthLimit,
		SeverityHigh,
		"Query depth 50 accepted",
	).WithDetails(map[string]interface{}{
		"depth_tested":  50,
		"response_time": "1.2s",
	})

	assert.Equal(t, 50, finding.Details["depth_tested"])
	assert.Equal(t, "1.2s", finding.Details["response_time"])
}

func TestFinding_Format(t *testing.T) {
	tests := []struct {
		name     string
		finding  *Finding
		expected string
	}{
		{
			name: "formats finding with all fields",
			finding: NewFinding(
				FindingTypeIntrospectionDisclosure,
				SeverityMedium,
				"Introspection query succeeded",
			),
			expected: "[MEDIUM] introspection-disclosure\n  Description: Introspection query succeeded",
		},
		{
			name: "formats critical finding",
			finding: NewFinding(
				FindingTypeNoBatchingLimit,
				SeverityCritical,
				"Batch of 1000 queries accepted",
			),
			expected: "[CRITICAL] no-batching-limit\n  Description: Batch of 1000 queries accepted",
		},
		{
			name: "formats info level finding",
			finding: NewFinding(
				FindingTypeBOLA,
				SeverityInfo,
				"Object access patterns observed",
			),
			expected: "[INFO] bola\n  Description: Object access patterns observed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.finding.Format()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []*Finding
		expected string
	}{
		{
			name:     "empty findings list",
			findings: []*Finding{},
			expected: "No security findings detected.",
		},
		{
			name: "single finding",
			findings: []*Finding{
				NewFinding(
					FindingTypeIntrospectionDisclosure,
					SeverityMedium,
					"Introspection enabled",
				),
			},
			expected: `=== Security Findings (1) ===

[MEDIUM] introspection-disclosure
  Description: Introspection enabled
`,
		},
		{
			name: "multiple findings",
			findings: []*Finding{
				NewFinding(
					FindingTypeNoBatchingLimit,
					SeverityCritical,
					"Batch of 1000 queries accepted",
				),
				NewFinding(
					FindingTypeNoDepthLimit,
					SeverityHigh,
					"Query depth 50 accepted",
				),
			},
			expected: `=== Security Findings (2) ===

[CRITICAL] no-batching-limit
  Description: Batch of 1000 queries accepted
[HIGH] no-depth-limit
  Description: Query depth 50 accepted
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatFindings(tt.findings)
			assert.Equal(t, tt.expected, result)
		})
	}
}
