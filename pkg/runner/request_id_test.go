package runner

import (
	"bytes"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinding_RequestIDsFlowToTerminalOutput verifies that request IDs
// in a Finding are displayed by the terminal reporter
func TestFinding_RequestIDsFlowToTerminalOutput(t *testing.T) {
	// Create a finding with request IDs (simulating what runner creates)
	finding := &model.Finding{
		ID:          "test-finding",
		Category:    "API1",
		Name:        "Test Vulnerability",
		Severity:    model.SeverityHigh,
		Endpoint:    "/api/users/123",
		Method:      "GET",
		Confidence:  0.95,
		RequestIDs:  []string{"req-abc123", "req-def456"},
		Evidence: model.Evidence{
			Response: model.HTTPResponse{
				StatusCode: 200,
				Body:       `{"user": "admin"}`,
			},
		},
	}

	// Create terminal reporter
	var buf bytes.Buffer
	terminalReporter := reporter.NewTerminalReporter(&buf, false)

	// Report the finding
	err := terminalReporter.ReportFinding(finding)
	require.NoError(t, err)

	// Verify output contains request IDs
	output := buf.String()
	assert.Contains(t, output, "Request IDs:", "output should label request IDs section")
	assert.Contains(t, output, "req-abc123", "output should contain first request ID")
	assert.Contains(t, output, "req-def456", "output should contain second request ID")
}
