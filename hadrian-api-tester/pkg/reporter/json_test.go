package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJSONReporter(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	reporter := NewJSONReporter(outputPath)

	require.NotNil(t, reporter)
	assert.Equal(t, outputPath, reporter.outputPath)
	assert.NotNil(t, reporter.redactor)
}

func TestJSONReporter_ReportFinding_IsNoOp(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")
	reporter := NewJSONReporter(outputPath)
	finding := createTestFinding(model.SeverityHigh, "API1")

	// ReportFinding should be a no-op for JSON (batch output only)
	err := reporter.ReportFinding(finding)

	require.NoError(t, err)
	// File should not exist yet since we haven't called GenerateReport
	_, err = os.Stat(outputPath)
	assert.True(t, os.IsNotExist(err), "File should not exist after ReportFinding")
}

func TestJSONReporter_GenerateReport_CreatesValidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")
	reporter := NewJSONReporter(outputPath)

	findings := []*model.Finding{
		createTestFinding(model.SeverityCritical, "API1"),
		createTestFinding(model.SeverityHigh, "API2"),
	}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)

	require.NoError(t, err)

	// Read and parse the output file
	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var report JSONReport
	err = json.Unmarshal(data, &report)
	require.NoError(t, err, "Output should be valid JSON")

	// Verify metadata
	assert.Equal(t, "hadrian", report.Metadata.Tool)
	assert.NotEmpty(t, report.Metadata.Version)
	assert.False(t, report.Metadata.Timestamp.IsZero())

	// Verify summary
	assert.Equal(t, stats.TotalOperations, report.Summary.TotalOperations)
	assert.Equal(t, stats.TotalTemplates, report.Summary.TotalTemplates)
	assert.Equal(t, len(findings), report.Summary.TotalFindings)

	// Verify findings
	assert.Len(t, report.Findings, 2)
}

func TestJSONReporter_GenerateReport_ContainsSeveritySummary(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")
	reporter := NewJSONReporter(outputPath)

	findings := []*model.Finding{
		createTestFinding(model.SeverityCritical, "API1"),
	}
	stats := createTestStats()
	stats.BySeverity[model.SeverityCritical] = 1
	stats.BySeverity[model.SeverityHigh] = 2

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var report JSONReport
	err = json.Unmarshal(data, &report)
	require.NoError(t, err)

	assert.Equal(t, 1, report.Summary.BySeverity[model.SeverityCritical])
	assert.Equal(t, 2, report.Summary.BySeverity[model.SeverityHigh])
}

func TestJSONReporter_GenerateReport_ContainsCategorySummary(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")
	reporter := NewJSONReporter(outputPath)

	findings := []*model.Finding{
		createTestFinding(model.SeverityHigh, "API1"),
	}
	stats := createTestStats()
	stats.ByCategory["API1"] = 3
	stats.ByCategory["API2"] = 2

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var report JSONReport
	err = json.Unmarshal(data, &report)
	require.NoError(t, err)

	assert.Equal(t, 3, report.Summary.ByCategory["API1"])
	assert.Equal(t, 2, report.Summary.ByCategory["API2"])
}

func TestJSONReporter_GenerateReport_RedactsSensitiveData(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")
	reporter := NewJSONReporter(outputPath)

	finding := createTestFinding(model.SeverityHigh, "API1")
	// Add sensitive data to response body
	// sk_key pattern requires 10+ chars after sk_ prefix
	finding.Evidence.Response.Body = `{"email": "user@example.com", "ssn": "123-45-6789", "key": "sk_live_abcdefghij123"}`

	findings := []*model.Finding{finding}
	stats := createTestStats()

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	content := string(data)
	// Should not contain raw sensitive data
	assert.NotContains(t, content, "123-45-6789", "SSN should be redacted")
	assert.NotContains(t, content, "sk_live_abcdefghij123", "SK key should be redacted")
	// Should contain redaction markers
	assert.Contains(t, content, "[SSN-REDACTED]", "Should have SSN redaction marker")
	assert.Contains(t, content, "[SK_KEY-REDACTED]", "Should have SK_KEY redaction marker")
}

func TestJSONReporter_GenerateReport_EmptyFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")
	reporter := NewJSONReporter(outputPath)

	findings := []*model.Finding{}
	stats := NewStats()
	stats.Duration = 10 * time.Second

	err := reporter.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputPath)
	require.NoError(t, err)

	var report JSONReport
	err = json.Unmarshal(data, &report)
	require.NoError(t, err)

	assert.Len(t, report.Findings, 0)
	assert.Equal(t, 0, report.Summary.TotalFindings)
}

func TestJSONReporter_ImplementsReporterInterface(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "report.json")

	var r Reporter = NewJSONReporter(outputPath)

	assert.NotNil(t, r)
}
