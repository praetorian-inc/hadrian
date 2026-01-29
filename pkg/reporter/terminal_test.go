package reporter

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTerminalReporter(t *testing.T) {
	var buf bytes.Buffer

	reporter := NewTerminalReporter(&buf, true)

	require.NotNil(t, reporter)
	assert.Equal(t, &buf, reporter.writer)
	assert.True(t, reporter.useColor)
	assert.NotNil(t, reporter.redactor)
}

func TestNewTerminalReporter_NoColor(t *testing.T) {
	var buf bytes.Buffer

	reporter := NewTerminalReporter(&buf, false)

	require.NotNil(t, reporter)
	assert.False(t, reporter.useColor)
}

func TestTerminalReporter_ReportFinding_OutputsFindingImmediately(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)
	finding := createTestFinding(model.SeverityHigh, "API1")

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "HIGH", "Should contain severity")
	assert.Contains(t, output, "Test Finding", "Should contain finding name")
	assert.Contains(t, output, "API1", "Should contain category")
}

func TestTerminalReporter_ReportFinding_CriticalSeverityColorRed(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, true)
	finding := createTestFinding(model.SeverityCritical, "API1")

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	// ANSI red bold: \033[1;31m
	assert.Contains(t, output, "\033[1;31m", "CRITICAL should use bold red")
	assert.Contains(t, output, "CRITICAL")
}

func TestTerminalReporter_ReportFinding_HighSeverityColorRed(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, true)
	finding := createTestFinding(model.SeverityHigh, "API1")

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	// ANSI red: \033[31m
	assert.Contains(t, output, "\033[31m", "HIGH should use red")
	assert.Contains(t, output, "HIGH")
}

func TestTerminalReporter_ReportFinding_MediumSeverityColorYellow(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, true)
	finding := createTestFinding(model.SeverityMedium, "API1")

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	// ANSI yellow: \033[33m
	assert.Contains(t, output, "\033[33m", "MEDIUM should use yellow")
	assert.Contains(t, output, "MEDIUM")
}

func TestTerminalReporter_ReportFinding_LowSeverityColorCyan(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, true)
	finding := createTestFinding(model.SeverityLow, "API1")

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	// ANSI cyan: \033[36m
	assert.Contains(t, output, "\033[36m", "LOW should use cyan")
	assert.Contains(t, output, "LOW")
}

func TestTerminalReporter_ReportFinding_NoColorMode(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)
	finding := createTestFinding(model.SeverityCritical, "API1")

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	// Should not contain ANSI escape codes
	assert.NotContains(t, output, "\033[", "Should not contain ANSI codes when color disabled")
	assert.Contains(t, output, "CRITICAL")
}

func TestTerminalReporter_ReportFinding_RedactsSensitiveData(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)
	finding := createTestFinding(model.SeverityHigh, "API1")
	finding.Evidence.Response.Body = `{"ssn": "123-45-6789"}`

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	assert.NotContains(t, output, "123-45-6789", "SSN should be redacted")
}

func TestTerminalReporter_GenerateReport_PrintsSummaryBanner(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)

	findings := []*model.Finding{
		createTestFinding(model.SeverityCritical, "API1"),
		createTestFinding(model.SeverityHigh, "API2"),
	}
	stats := createTestStats()
	stats.TotalFindings = 2
	stats.BySeverity[model.SeverityCritical] = 1
	stats.BySeverity[model.SeverityHigh] = 1

	err := reporter.GenerateReport(findings, stats)

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "SUMMARY", "Should contain summary header")
	assert.Contains(t, output, "2", "Should contain total findings count")
	assert.Contains(t, output, "CRITICAL", "Should list severity counts")
	assert.Contains(t, output, "HIGH")
}

func TestTerminalReporter_GenerateReport_ShowsDuration(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)

	findings := []*model.Finding{}
	stats := NewStats()
	stats.Duration = 45 * time.Second

	err := reporter.GenerateReport(findings, stats)

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "45s", "Should show duration")
}

func TestTerminalReporter_GenerateReport_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)

	findings := []*model.Finding{}
	stats := NewStats()

	err := reporter.GenerateReport(findings, stats)

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "0", "Should show zero findings")
}

func TestTerminalReporter_ImplementsReporterInterface(t *testing.T) {
	var buf bytes.Buffer

	var r Reporter = NewTerminalReporter(&buf, true)

	assert.NotNil(t, r)
}

func TestTerminalReporter_ReportFinding_IncludesEndpoint(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)
	finding := createTestFinding(model.SeverityHigh, "API1")
	finding.Endpoint = "POST /api/users"

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "POST /api/users", "Should include endpoint")
}

func TestTerminalReporter_ReportFinding_InfoSeverity(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, true)
	finding := createTestFinding(model.SeverityInfo, "API1")

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	// INFO should use default/white color
	assert.Contains(t, output, "INFO")
}

func TestTerminalReporter_GenerateReport_ShowsOperationsAndTemplates(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)

	findings := []*model.Finding{}
	stats := NewStats()
	stats.TotalOperations = 150
	stats.TotalTemplates = 30

	err := reporter.GenerateReport(findings, stats)

	require.NoError(t, err)
	output := buf.String()
	// Check that operations and templates are mentioned
	assert.True(t, strings.Contains(output, "150") || strings.Contains(output, "Operations"),
		"Should mention operations count")
	assert.True(t, strings.Contains(output, "30") || strings.Contains(output, "Templates"),
		"Should mention templates count")
}

// TestTerminalReporter_ReportFinding_WithRequestIDs verifies that request IDs
// are displayed in terminal output when present
func TestTerminalReporter_ReportFinding_WithRequestIDs(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)
	
	finding := createTestFinding(model.SeverityHigh, "API1")
	finding.RequestIDs = []string{"req-abc123", "req-def456"}

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	assert.Contains(t, output, "Request IDs:", "Should label request IDs section")
	assert.Contains(t, output, "req-abc123", "Should include first request ID")
	assert.Contains(t, output, "req-def456", "Should include second request ID")
}

// TestTerminalReporter_ReportFinding_NoRequestIDs verifies that request ID section
// is omitted when there are no request IDs
func TestTerminalReporter_ReportFinding_NoRequestIDs(t *testing.T) {
	var buf bytes.Buffer
	reporter := NewTerminalReporter(&buf, false)
	
	finding := createTestFinding(model.SeverityHigh, "API1")
	finding.RequestIDs = []string{} // Empty

	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	output := buf.String()
	assert.NotContains(t, output, "Request IDs:", "Should not show request IDs section when empty")
}
