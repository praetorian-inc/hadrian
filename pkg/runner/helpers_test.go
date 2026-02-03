package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// parseAPISpec tests
// =============================================================================

func TestParseAPISpec_ValidOpenAPI(t *testing.T) {
	// Create a temporary OpenAPI spec file
	specContent := `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: http://localhost:8080/api
paths:
  /users:
    get:
      summary: List users
      responses:
        "200":
          description: Success
  /users/{id}:
    get:
      summary: Get user by ID
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Success
`
	tmpFile := filepath.Join(t.TempDir(), "api.yaml")
	err := os.WriteFile(tmpFile, []byte(specContent), 0644)
	require.NoError(t, err)

	spec, err := parseAPISpec(tmpFile)
	require.NoError(t, err)

	assert.Equal(t, "Test API", spec.Info.Title)
	assert.Equal(t, "1.0.0", spec.Info.Version)
	assert.Equal(t, "http://localhost:8080/api", spec.BaseURL)
	assert.Len(t, spec.Operations, 2)
}

func TestParseAPISpec_FileNotFound(t *testing.T) {
	_, err := parseAPISpec("/nonexistent/file.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read API spec")
}

func TestParseAPISpec_InvalidFormat(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "invalid.txt")
	err := os.WriteFile(tmpFile, []byte("not yaml"), 0644)
	require.NoError(t, err)

	_, err = parseAPISpec(tmpFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported API specification format")
}

// =============================================================================
// createHTTPClient tests
// =============================================================================

func TestCreateHTTPClient_Default(t *testing.T) {
	config := Config{
		Timeout: 30,
	}

	client, err := createHTTPClient(config)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestCreateHTTPClient_WithProxy(t *testing.T) {
	config := Config{
		Proxy:   "http://localhost:8080",
		Timeout: 30,
	}

	client, err := createHTTPClient(config)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestCreateHTTPClient_WithInsecure(t *testing.T) {
	config := Config{
		Insecure: true,
		Timeout:  30,
	}

	client, err := createHTTPClient(config)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

// =============================================================================
// createReporter tests
// =============================================================================

func TestCreateReporter_Terminal(t *testing.T) {
	rep, err := createReporter("terminal", "", 1)
	require.NoError(t, err)
	assert.NotNil(t, rep)
	assert.NoError(t, rep.Close())
}

func TestCreateReporter_JSON(t *testing.T) {
	rep, err := createReporter("json", "", 1)
	require.NoError(t, err)
	assert.NotNil(t, rep)
	assert.NoError(t, rep.Close())
}

func TestCreateReporter_Markdown(t *testing.T) {
	rep, err := createReporter("markdown", "", 1)
	require.NoError(t, err)
	assert.NotNil(t, rep)
	assert.NoError(t, rep.Close())
}

func TestCreateReporter_InvalidFormat(t *testing.T) {
	_, err := createReporter("invalid", "", 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported output format")
}

// =============================================================================
// calculateStats tests
// =============================================================================

func TestCalculateStats_Empty(t *testing.T) {
	findings := []*model.Finding{}
	startTime := time.Now().Add(-1 * time.Minute)

	stats := calculateStats(findings, startTime)

	assert.Equal(t, 0, stats.Findings)
	assert.Equal(t, 0, stats.Critical)
	assert.Equal(t, 0, stats.High)
	assert.Equal(t, 0, stats.Medium)
	assert.Equal(t, 0, stats.Low)
	assert.Equal(t, 0, stats.Info)
	assert.True(t, stats.Duration >= time.Minute)
}

func TestCalculateStats_WithFindings(t *testing.T) {
	findings := []*model.Finding{
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityCritical},
		{Severity: model.SeverityHigh},
		{Severity: model.SeverityMedium},
		{Severity: model.SeverityMedium},
		{Severity: model.SeverityMedium},
		{Severity: model.SeverityLow},
		{Severity: model.SeverityInfo},
	}
	startTime := time.Now()

	stats := calculateStats(findings, startTime)

	assert.Equal(t, 8, stats.Findings)
	assert.Equal(t, 2, stats.Critical)
	assert.Equal(t, 1, stats.High)
	assert.Equal(t, 3, stats.Medium)
	assert.Equal(t, 1, stats.Low)
	assert.Equal(t, 1, stats.Info)
}

// =============================================================================
// TerminalReporter tests
// =============================================================================

func TestTerminalReporter_ReportFinding(t *testing.T) {
	// Capture stdout
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()

	rep := NewTerminalReporter(tmpFile, 1)
	finding := &model.Finding{
		Severity:        model.SeverityHigh,
		Category:        "API1",
		Name:            "Broken Object Level Authorization",
		Method:          "GET",
		Endpoint:        "/api/users/{id}",
		IsVulnerability: true,
		Confidence:      0.95,
	}

	rep.ReportFinding(finding)

	// Read output
	tmpFile.Seek(0, 0)
	output := make([]byte, 1024)
	n, _ := tmpFile.Read(output)

	assert.Contains(t, string(output[:n]), "HIGH")
	assert.Contains(t, string(output[:n]), "API1")
}

func TestTerminalReporter_ReportFinding_WithLLMAnalysis(t *testing.T) {
	// Capture stdout
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()

	rep := NewTerminalReporter(tmpFile, 1)
	finding := &model.Finding{
		Severity:    model.SeverityHigh,
		Category:    "API1",
		Name:        "Broken Object Level Authorization",
		Method:      "GET",
		Endpoint:    "/api/users/{id}",
		LLMAnalysis: &model.LLMTriage{
			Provider:        "ollama",
			IsVulnerability: true,
			Confidence:      0.85,
			Reasoning:       "Attacker can access victim data",
		},
	}

	rep.ReportFinding(finding)

	// Read output
	tmpFile.Seek(0, 0)
	output := make([]byte, 1024)
	n, _ := tmpFile.Read(output)
	outputStr := string(output[:n])

	assert.Contains(t, outputStr, "LLM Analysis: Confidence 85%")
	assert.NotContains(t, outputStr, "Vulnerability confirmed")
}

func TestTerminalReporter_ReportFinding_WithoutLLMAnalysis(t *testing.T) {
	// Capture stdout
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()

	rep := NewTerminalReporter(tmpFile, 1)
	finding := &model.Finding{
		Severity:        model.SeverityHigh,
		Category:        "API1",
		Name:            "Broken Object Level Authorization",
		Method:          "GET",
		Endpoint:        "/api/users/{id}",
		IsVulnerability: true,
		Confidence:      0.95,
		LLMAnalysis:     nil, // No LLM analysis
	}

	rep.ReportFinding(finding)

	// Read output
	tmpFile.Seek(0, 0)
	output := make([]byte, 1024)
	n, _ := tmpFile.Read(output)
	outputStr := string(output[:n])

	// Should not show anything about LLM or confidence when no LLM analysis
	assert.NotContains(t, outputStr, "LLM Analysis")
	assert.NotContains(t, outputStr, "Confidence")
	assert.NotContains(t, outputStr, "Vulnerability confirmed")
}

func TestTerminalReporter_GenerateReport(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()

	rep := NewTerminalReporter(tmpFile, 1)
	stats := &Stats{
		Findings:        5,
		Critical:        1,
		High:            2,
		Medium:          1,
		Low:             1,
		Duration:        time.Second * 30,
		OperationCount:  10,
		RoleCount:       3,
		TemplatesLoaded: 5,
	}

	err = rep.GenerateReport([]*model.Finding{}, stats)
	require.NoError(t, err)

	// Read output
	tmpFile.Seek(0, 0)
	output := make([]byte, 4096)
	n, _ := tmpFile.Read(output)

	assert.Contains(t, string(output[:n]), "Hadrian Security Test Results")
	assert.Contains(t, string(output[:n]), "CRITICAL: 1")
	assert.Contains(t, string(output[:n]), "HIGH: 2")
}

func TestTerminalReporter_GenerateReport_WithLLMFindings(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()

	rep := NewTerminalReporter(tmpFile, 1)
	rep.SetLLMMode(true) // Enable LLM mode

	// Findings with LLM analysis (would have been printed during triage)
	findings := []*model.Finding{
		{
			Severity:    model.SeverityHigh,
			Category:    "API1",
			Name:        "Broken Object Level Authorization",
			Method:      "GET",
			Endpoint:    "/api/users/{id}",
			LLMAnalysis: &model.LLMTriage{
				Provider:        "ollama",
				IsVulnerability: true,
				Confidence:      0.85,
				Reasoning:       "Attacker can access victim data",
			},
		},
	}

	stats := &Stats{
		Findings:        1,
		High:            1,
		Duration:        time.Second * 30,
		OperationCount:  10,
		RoleCount:       3,
		TemplatesLoaded: 5,
	}

	err = rep.GenerateReport(findings, stats)
	require.NoError(t, err)

	// Read output
	tmpFile.Seek(0, 0)
	output := make([]byte, 4096)
	n, _ := tmpFile.Read(output)
	outputStr := string(output[:n])

	// Verify summary is shown (findings were already printed during triage)
	assert.Contains(t, outputStr, "Hadrian Security Test Results")
	assert.Contains(t, outputStr, "HIGH: 1")

	// Findings are NOT printed in GenerateReport anymore (printed in real-time during triage)
	// So we should NOT see finding details here
}

func TestTerminalReporter_GenerateReport_LLMModeWithoutAnalysis(t *testing.T) {
	// Test that when LLM mode is enabled, findings are printed during triage
	// (not in GenerateReport). Even if LLM calls fail, findings are printed
	// in triageWithLLM as they fail, so GenerateReport only shows summary.
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()

	rep := NewTerminalReporter(tmpFile, 1)
	rep.SetLLMMode(true) // LLM mode enabled

	// Findings WITHOUT LLM analysis (all LLM calls failed, but were printed during triage)
	findings := []*model.Finding{
		{
			Severity:    model.SeverityHigh,
			Category:    "API1",
			Name:        "Broken Object Level Authorization",
			Method:      "GET",
			Endpoint:    "/api/users/{id}",
			LLMAnalysis: nil, // No LLM analysis (all calls failed)
		},
	}

	stats := &Stats{
		Findings:        1,
		High:            1,
		Duration:        time.Second * 30,
		OperationCount:  10,
		RoleCount:       3,
		TemplatesLoaded: 5,
	}

	err = rep.GenerateReport(findings, stats)
	require.NoError(t, err)

	// Read output
	tmpFile.Seek(0, 0)
	output := make([]byte, 4096)
	n, _ := tmpFile.Read(output)
	outputStr := string(output[:n])

	// Verify summary still shown
	assert.Contains(t, outputStr, "Hadrian Security Test Results")
	assert.Contains(t, outputStr, "HIGH: 1")

	// Findings are printed during triage (not in GenerateReport anymore)
}

// =============================================================================
// JSONReporter tests
// =============================================================================

func TestJSONReporter_GenerateReport(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "report.json")

	rep, err := NewJSONReporter(outputFile, 1)
	require.NoError(t, err)

	findings := []*model.Finding{
		{
			ID:       "test-1",
			Category: "API1",
			Name:     "Test Finding",
			Severity: model.SeverityHigh,
		},
	}
	stats := &Stats{
		Findings: 1,
		High:     1,
		Duration: time.Second,
	}

	err = rep.GenerateReport(findings, stats)
	require.NoError(t, err)

	// Verify file was created with JSON content
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "findings")
	assert.Contains(t, string(data), "stats")
	assert.Contains(t, string(data), "test-1")
}

// =============================================================================
// MarkdownReporter tests
// =============================================================================

func TestMarkdownReporter_GenerateReport(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "report.md")

	rep, err := NewMarkdownReporter(outputFile, 1)
	require.NoError(t, err)

	findings := []*model.Finding{
		{
			ID:          "test-1",
			Category:    "API1",
			Name:        "BOLA Vulnerability",
			Severity:    model.SeverityCritical,
			Method:      "GET",
			Endpoint:    "/api/users/{id}",
			Description: "Test description",
		},
	}
	stats := &Stats{
		Findings: 1,
		Critical: 1,
		Duration: time.Second,
	}

	err = rep.GenerateReport(findings, stats)
	require.NoError(t, err)

	// Verify markdown content
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "# Hadrian Security Test Report")
	assert.Contains(t, string(data), "| Critical | 1 |")
	assert.Contains(t, string(data), "BOLA Vulnerability")
}

// =============================================================================
// Helper function tests
// =============================================================================

func TestGetTemplateDir_Default(t *testing.T) {
	// Unset env var
	os.Unsetenv("HADRIAN_TEMPLATES")

	dir := getTemplateDir()
	assert.Equal(t, "./templates/owasp", dir)
}

func TestGetTemplateDir_EnvOverride(t *testing.T) {
	os.Setenv("HADRIAN_TEMPLATES", "/custom/templates")
	defer os.Unsetenv("HADRIAN_TEMPLATES")

	dir := getTemplateDir()
	assert.Equal(t, "/custom/templates", dir)
}

func TestHasLLMConfig_NoConfig(t *testing.T) {
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")
	os.Unsetenv("OLLAMA_HOST")

	assert.False(t, hasLLMConfig())
}

func TestHasLLMConfig_WithAnthropic(t *testing.T) {
	os.Setenv("ANTHROPIC_API_KEY", "test-key")
	defer os.Unsetenv("ANTHROPIC_API_KEY")

	assert.True(t, hasLLMConfig())
}

func TestHasLLMConfig_WithOpenAI(t *testing.T) {
	os.Setenv("OPENAI_API_KEY", "test-key")
	defer os.Unsetenv("OPENAI_API_KEY")

	assert.True(t, hasLLMConfig())
}

// =============================================================================
// triageWithLLM tests (mocked)
// =============================================================================

func TestTriageWithLLM_NoProvider(t *testing.T) {
	// Ensure no LLM providers are configured
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")
	os.Unsetenv("OLLAMA_HOST")

	ctx := context.Background()
	findings := []*model.Finding{
		{ID: "test-1", Severity: model.SeverityHigh},
	}

	// Create a minimal role config
	rolesCfg := &roles.RoleConfig{
		Roles: []*roles.Role{
			{Name: "user"},
		},
	}

	// Create a mock reporter
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()
	rep := NewTerminalReporter(tmpFile, 1)

	// Should return findings unchanged (no LLM available)
	result, err := triageWithLLM(ctx, findings, rolesCfg, "", "", 180, "", rep)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "test-1", result[0].ID)
}

func TestTriageWithLLM_PrintsFindingsImmediately(t *testing.T) {
	// Test that when LLM triage is configured but fails/succeeds,
	// findings are printed immediately after each analysis.
	// This test simulates the case where LLM client fails per-finding
	// (not at initialization) by mocking findings that would trigger
	// the per-finding error path.

	// Note: This is a behavioral test. In reality, if no LLM is available,
	// findings are printed in real-time during detection (not in triageWithLLM).
	// This function only prints findings when LLM client is successfully created
	// and either succeeds or fails on a per-finding basis.

	// For now, we test that the signature accepts a Reporter and the function
	// doesn't panic. Integration tests would verify the full workflow.

	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")
	os.Unsetenv("OLLAMA_HOST")

	ctx := context.Background()
	findings := []*model.Finding{
		{ID: "test-1", Severity: model.SeverityHigh, Category: "API1", Name: "Finding 1", Method: "GET", Endpoint: "/api/test1"},
	}

	rolesCfg := &roles.RoleConfig{
		Roles: []*roles.Role{
			{Name: "user"},
		},
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()
	rep := NewTerminalReporter(tmpFile, 1)

	// Should not panic with reporter parameter
	result, err := triageWithLLM(ctx, findings, rolesCfg, "", "", 180, "", rep)
	require.NoError(t, err)
	assert.Len(t, result, 1)

	// When no LLM is available, findings are returned unchanged
	// (they would have been printed during detection in run.go)
}

func TestTriageWithLLM_WithContext(t *testing.T) {
	// Ensure no LLM providers are configured (so we don't make actual API calls)
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")
	os.Unsetenv("OLLAMA_HOST")

	ctx := context.Background()
	findings := []*model.Finding{
		{ID: "test-1", Severity: model.SeverityHigh},
	}

	// Create a minimal role config
	rolesCfg := &roles.RoleConfig{
		Roles: []*roles.Role{
			{Name: "user"},
		},
	}

	// Create a mock reporter
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()
	rep := NewTerminalReporter(tmpFile, 1)

	customContext := "This API handles PCI-DSS regulated payment data"

	// Should return findings unchanged (no LLM available)
	// This test verifies the signature accepts llmContext parameter
	result, err := triageWithLLM(ctx, findings, rolesCfg, "", "", 180, customContext, rep)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "test-1", result[0].ID)
}

// =============================================================================
// Integration test for runTest (with mock server)
// =============================================================================

func TestRunTest_ValidationError(t *testing.T) {
	ctx := context.Background()
	config := Config{
		API:   "/nonexistent/api.yaml",
		Roles: "/nonexistent/roles.yaml",
	}

	err := runTest(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration error")
}

// =============================================================================
// parseCmdHandler tests
// =============================================================================

func TestParseCmdHandler_ValidSpec(t *testing.T) {
	specContent := `
openapi: "3.0.0"
info:
  title: Test API
  version: "2.0.0"
servers:
  - url: http://localhost:8080
paths:
  /users:
    get:
      summary: List users
      responses:
        "200":
          description: Success
`
	tmpFile := filepath.Join(t.TempDir(), "api.yaml")
	err := os.WriteFile(tmpFile, []byte(specContent), 0644)
	require.NoError(t, err)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = parseCmdHandler(tmpFile)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	require.NoError(t, err)
	assert.Contains(t, output, "Test API")
	assert.Contains(t, output, "2.0.0")
	assert.Contains(t, output, "Operations: 1")
	assert.Contains(t, output, "GET /users")
}

func TestParseCmdHandler_InvalidFile(t *testing.T) {
	err := parseCmdHandler("/nonexistent/file.yaml")
	assert.Error(t, err)
}

// =============================================================================
// filterTemplatesByOWASP tests
// =============================================================================

func TestFilterTemplatesByOWASP_NoFilter(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API1:2023"}}},
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API2:2023"}}},
	}

	result := filterTemplatesByOWASP(tmpls, []string{})
	assert.Len(t, result, 2, "empty filter should return all templates")
}

func TestFilterTemplatesByOWASP_SingleCategory(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API1:2023"}}},
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API2:2023"}}},
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API5:2023"}}},
	}

	result := filterTemplatesByOWASP(tmpls, []string{"API1"})
	assert.Len(t, result, 1)
	assert.Equal(t, "API1:2023", result[0].Info.Category)
}

func TestFilterTemplatesByOWASP_MultipleCategories(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API1:2023"}}},
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API2:2023"}}},
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API5:2023"}}},
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API9:2023"}}},
	}

	result := filterTemplatesByOWASP(tmpls, []string{"API1", "API5"})
	assert.Len(t, result, 2)
}

func TestFilterTemplatesByOWASP_CaseInsensitive(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API1:2023"}}},
	}

	result := filterTemplatesByOWASP(tmpls, []string{"api1"})
	assert.Len(t, result, 1, "should match case-insensitively")
}

func TestFilterTemplatesByOWASP_NoMatch(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{Info: templates.TemplateInfo{Category: "API1:2023"}}},
	}

	result := filterTemplatesByOWASP(tmpls, []string{"API99"})
	assert.Len(t, result, 0, "non-matching filter should return empty")
}

// =============================================================================
// verboseLog tests
// =============================================================================

func TestVerboseLog_Enabled(t *testing.T) {
	var buf bytes.Buffer
	verboseLog(&buf, true, "Test message: %s", "hello")
	assert.Contains(t, buf.String(), "[VERBOSE] Test message: hello")
}

func TestVerboseLog_Disabled(t *testing.T) {
	var buf bytes.Buffer
	verboseLog(&buf, false, "Test message: %s", "hello")
	assert.Empty(t, buf.String(), "should not write when verbose is disabled")
}

func TestNewTestCmd_VerboseFlag(t *testing.T) {
	// After CLI refactoring, test flags are on "test rest" subcommand
	cmd := newTestRestCmd()

	// Find the verbose flag
	flag := cmd.Flags().Lookup("verbose")
	require.NotNil(t, flag, "verbose flag should exist")
	assert.Equal(t, "v", flag.Shorthand)
	assert.Equal(t, "false", flag.DefValue)
}

// =============================================================================
// dry-run tests
// =============================================================================

func TestNewTestCmd_DryRunFlag(t *testing.T) {
	// After CLI refactoring, test flags are on "test rest" subcommand
	cmd := newTestRestCmd()

	// Find the dry-run flag
	flag := cmd.Flags().Lookup("dry-run")
	require.NotNil(t, flag, "dry-run flag should exist")
	assert.Equal(t, "false", flag.DefValue)
}

// =============================================================================
// template-dir flag tests
// =============================================================================

func TestNewTestCmd_TemplateDirFlag(t *testing.T) {
	// After CLI refactoring, test flags are on "test rest" subcommand
	cmd := newTestRestCmd()

	// Find the template-dir flag
	flag := cmd.Flags().Lookup("template-dir")
	require.NotNil(t, flag, "template-dir flag should exist")
	assert.Equal(t, "", flag.DefValue, "default should be empty string")
}

func TestDryRunLog_Enabled(t *testing.T) {
	var buf bytes.Buffer
	dryRunLog(&buf, true, "Would execute: %s %s", "GET", "/api/users")
	assert.Contains(t, buf.String(), "[DRY-RUN] Would execute: GET /api/users")
}

func TestDryRunLog_Disabled(t *testing.T) {
	var buf bytes.Buffer
	dryRunLog(&buf, false, "Would execute: %s %s", "GET", "/api/users")
	assert.Empty(t, buf.String(), "should not write when dry-run is disabled")
}

// =============================================================================
// filterByTemplates tests
// =============================================================================

func TestFilterByTemplates_MatchByID(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "bola-idor-basic"}},
		{Template: &templates.Template{ID: "bola-idor-predictable"}},
		{Template: &templates.Template{ID: "rate-limiting-bypass"}},
	}

	result := filterByTemplates(tmpls, []string{"bola-idor-basic"})
	require.Len(t, result, 1)
	assert.Equal(t, "bola-idor-basic", result[0].ID)
}

func TestFilterByTemplates_MatchByFilename(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "bola-idor-basic"}, FilePath: "/templates/owasp/bola-idor-basic.yaml"},
		{Template: &templates.Template{ID: "rate-limiting"}, FilePath: "/templates/owasp/rate-limiting.yaml"},
	}

	// Match with extension
	result := filterByTemplates(tmpls, []string{"bola-idor-basic.yaml"})
	require.Len(t, result, 1)
	assert.Equal(t, "bola-idor-basic", result[0].ID)

	// Match without extension
	result = filterByTemplates(tmpls, []string{"rate-limiting"})
	require.Len(t, result, 1)
	assert.Equal(t, "rate-limiting", result[0].ID)
}

func TestFilterByTemplates_MatchByPathSuffix(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "bola-idor-basic"}, FilePath: "/path/to/templates/owasp/bola-idor-basic.yaml"},
		{Template: &templates.Template{ID: "other-template"}, FilePath: "/path/to/templates/custom/other.yaml"},
	}

	// Match by partial path
	result := filterByTemplates(tmpls, []string{"templates/owasp/bola-idor-basic.yaml"})
	require.Len(t, result, 1)
	assert.Equal(t, "bola-idor-basic", result[0].ID)

	// Match by shorter path suffix
	result = filterByTemplates(tmpls, []string{"owasp/bola-idor-basic.yaml"})
	require.Len(t, result, 1)
	assert.Equal(t, "bola-idor-basic", result[0].ID)
}

func TestFilterByTemplates_CaseInsensitive(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "BOLA-IDOR-Basic"}, FilePath: "/templates/BOLA-IDOR-Basic.yaml"},
	}

	// Lowercase filter should match uppercase ID
	result := filterByTemplates(tmpls, []string{"bola-idor-basic"})
	require.Len(t, result, 1)
	assert.Equal(t, "BOLA-IDOR-Basic", result[0].ID)
}

func TestFilterByTemplates_MultipleFilters(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "bola-idor-basic"}},
		{Template: &templates.Template{ID: "bola-idor-predictable"}},
		{Template: &templates.Template{ID: "rate-limiting-bypass"}},
	}

	result := filterByTemplates(tmpls, []string{"bola-idor-basic", "rate-limiting-bypass"})
	require.Len(t, result, 2)

	ids := []string{result[0].ID, result[1].ID}
	assert.Contains(t, ids, "bola-idor-basic")
	assert.Contains(t, ids, "rate-limiting-bypass")
}

func TestFilterByTemplates_EmptyFilter(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "bola-idor-basic"}},
		{Template: &templates.Template{ID: "rate-limiting"}},
	}

	// Empty filter should return all templates
	result := filterByTemplates(tmpls, []string{})
	assert.Len(t, result, 2)
}

func TestFilterByTemplates_NoMatch(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "bola-idor-basic"}},
	}

	result := filterByTemplates(tmpls, []string{"nonexistent-template"})
	assert.Len(t, result, 0)
}

func TestFilterByTemplates_EmptyTemplateList(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{}

	result := filterByTemplates(tmpls, []string{"some-filter"})
	assert.Len(t, result, 0)
}

func TestFilterByTemplates_MixedMatchTypes(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{Template: &templates.Template{ID: "bola-idor-basic"}, FilePath: "/templates/owasp/bola-idor-basic.yaml"},
		{Template: &templates.Template{ID: "rate-limiting"}, FilePath: "/templates/owasp/rate-limiting.yaml"},
		{Template: &templates.Template{ID: "custom-test"}, FilePath: "/templates/custom/custom-test.yaml"},
	}

	// Mix of ID match and filename match
	result := filterByTemplates(tmpls, []string{"bola-idor-basic", "custom-test.yaml"})
	require.Len(t, result, 2)

	ids := []string{result[0].ID, result[1].ID}
	assert.Contains(t, ids, "bola-idor-basic")
	assert.Contains(t, ids, "custom-test")
}

func TestFilterByTemplates_YmlExtension(t *testing.T) {
	tmpls := []*templates.CompiledTemplate{
		{
			Template: &templates.Template{ID: "bola-test"},
			FilePath: "/templates/bola.yml",
		},
	}

	// Match by filename without .yml extension
	result := filterByTemplates(tmpls, []string{"bola"})
	assert.Len(t, result, 1, "should match filename without .yml extension")
}

// =============================================================================
// templateMatchesFilter tests
// =============================================================================

func TestTemplateMatchesFilter_ByID(t *testing.T) {
	tmpl := &templates.CompiledTemplate{
		Template: &templates.Template{ID: "bola-detection"},
		FilePath: "/templates/test.yaml",
	}

	assert.True(t, templateMatchesFilter(tmpl, "bola-detection"))
	assert.True(t, templateMatchesFilter(tmpl, "BOLA-Detection")) // case insensitive
	assert.False(t, templateMatchesFilter(tmpl, "other-id"))
}

func TestTemplateMatchesFilter_ByFilename(t *testing.T) {
	tmpl := &templates.CompiledTemplate{
		Template: &templates.Template{ID: "other-id"},
		FilePath: "/templates/bola-detection.yaml",
	}

	assert.True(t, templateMatchesFilter(tmpl, "bola-detection.yaml"))
	assert.True(t, templateMatchesFilter(tmpl, "bola-detection"))
	assert.True(t, templateMatchesFilter(tmpl, "BOLA-DETECTION.YAML")) // case insensitive
}

func TestTemplateMatchesFilter_ByPathSuffix(t *testing.T) {
	tmpl := &templates.CompiledTemplate{
		Template: &templates.Template{ID: "other-id"},
		FilePath: "/templates/owasp/api1/bola.yaml",
	}

	assert.True(t, templateMatchesFilter(tmpl, "owasp/api1/bola.yaml"))
	assert.True(t, templateMatchesFilter(tmpl, "api1/bola.yaml"))
	assert.False(t, templateMatchesFilter(tmpl, "api2/bola.yaml"))
}
