package reporter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMarkdownReporter(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")

	reporter := NewMarkdownReporter(outputPath)

	require.NotNil(t, reporter)
	assert.Equal(t, outputPath, reporter.outputPath)
	assert.NotNil(t, reporter.redactor)
}

func TestMarkdownReporter_ReportFinding_IsNoOp(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)
	finding := createTestFinding(model.SeverityHigh, "API1")

	// ReportFinding should be a no-op for Markdown (batch output only)
	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	// File should not exist yet since we haven't called GenerateReport
	_, err = os.Stat(outputPath)
	assert.True(t, os.IsNotExist(err), "File should not exist after ReportFinding")
}

func TestMarkdownReporter_GenerateReport_CreatesMarkdownFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	findings := []*model.Finding{
		createTestFinding(model.SeverityCritical, "API1"),
		createTestFinding(model.SeverityHigh, "API2"),
	}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)

	require.NoError(t, err)

	// Verify file exists and is readable
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "# Hadrian Security Report", "Should have main header")
}

func TestMarkdownReporter_GenerateReport_ContainsTimestamp(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	findings := []*model.Finding{}
	stats := NewStats()

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	// Should contain a date/time reference
	assert.Contains(t, content, "Generated:", "Should contain generation timestamp")
}

func TestMarkdownReporter_GenerateReport_ContainsSummarySection(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	findings := []*model.Finding{
		createTestFinding(model.SeverityCritical, "API1"),
	}
	stats := createTestStats()
	stats.TotalOperations = 100
	stats.TotalTemplates = 25
	stats.TotalFindings = 1

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "## Summary", "Should have summary section")
	assert.Contains(t, content, "100", "Should show operations count")
	assert.Contains(t, content, "25", "Should show templates count")
}

func TestMarkdownReporter_GenerateReport_GroupsFindingsBySeverity(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	findings := []*model.Finding{
		createTestFinding(model.SeverityCritical, "API1"),
		createTestFinding(model.SeverityHigh, "API2"),
		createTestFinding(model.SeverityMedium, "API3"),
	}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	// Should have severity section headers
	assert.Contains(t, content, "### Critical", "Should have Critical section")
	assert.Contains(t, content, "### High", "Should have High section")
	assert.Contains(t, content, "### Medium", "Should have Medium section")
}

func TestMarkdownReporter_GenerateReport_IncludesDescription(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	finding := createTestFinding(model.SeverityHigh, "API1")
	finding.Description = "A detailed description of the vulnerability"

	findings := []*model.Finding{finding}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "A detailed description", "Should include description")
}

func TestMarkdownReporter_GenerateReport_IncludesEvidence(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	finding := createTestFinding(model.SeverityHigh, "API1")
	finding.Endpoint = "GET /api/vulnerable"

	findings := []*model.Finding{finding}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "Evidence", "Should have evidence section")
	assert.Contains(t, content, "GET /api/vulnerable", "Should include endpoint")
}

func TestMarkdownReporter_GenerateReport_IncludesRemediation(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	finding := createTestFinding(model.SeverityHigh, "API1")
	finding.LLMAnalysis = &model.LLMTriage{
		Provider:        "claude",
		IsVulnerability: true,
		Confidence:      0.95,
		Reasoning:       "Test reasoning",
		Recommendations: "Apply proper authorization checks",
	}

	findings := []*model.Finding{finding}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "Remediation", "Should have remediation section")
	assert.Contains(t, content, "authorization checks", "Should include recommendations")
}

func TestMarkdownReporter_GenerateReport_RedactsSensitiveData(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	finding := createTestFinding(model.SeverityHigh, "API1")
	// Add sensitive data that should be redacted
	finding.Evidence.Response.Body = `{"ssn": "123-45-6789", "email": "secret@example.com"}`

	findings := []*model.Finding{finding}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	assert.NotContains(t, content, "123-45-6789", "SSN should be redacted")
	assert.NotContains(t, content, "secret@example.com", "Email should be redacted")
	assert.Contains(t, content, "[SSN-REDACTED]", "Should have SSN redaction marker")
	assert.Contains(t, content, "[EMAIL-REDACTED]", "Should have EMAIL redaction marker")
}

func TestMarkdownReporter_GenerateReport_EmptyFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	findings := []*model.Finding{}
	stats := NewStats()
	stats.Duration = 10 * time.Second

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "No findings", "Should indicate no findings")
}

func TestMarkdownReporter_ImplementsReporterInterface(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")

	var r Reporter = NewMarkdownReporter(outputPath)

	assert.NotNil(t, r)
}

func TestMarkdownReporter_GenerateReport_FormatsCodeBlocks(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.md")
	reporter := NewMarkdownReporter(outputPath)

	finding := createTestFinding(model.SeverityHigh, "API1")
	finding.Evidence.Request.Body = `{"test": "data"}`

	findings := []*model.Finding{finding}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	// Should use markdown code blocks for request/response bodies
	assert.Contains(t, content, "```", "Should use code blocks for evidence")
}
