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
	rep, err := createReporter("terminal", "")
	require.NoError(t, err)
	assert.NotNil(t, rep)
	assert.NoError(t, rep.Close())
}

func TestCreateReporter_JSON(t *testing.T) {
	rep, err := createReporter("json", "")
	require.NoError(t, err)
	assert.NotNil(t, rep)
	assert.NoError(t, rep.Close())
}

func TestCreateReporter_Markdown(t *testing.T) {
	rep, err := createReporter("markdown", "")
	require.NoError(t, err)
	assert.NotNil(t, rep)
	assert.NoError(t, rep.Close())
}

func TestCreateReporter_InvalidFormat(t *testing.T) {
	_, err := createReporter("invalid", "")
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

	rep := NewTerminalReporter(tmpFile)
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

func TestTerminalReporter_GenerateReport(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer tmpFile.Close()

	rep := NewTerminalReporter(tmpFile)
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

// =============================================================================
// JSONReporter tests
// =============================================================================

func TestJSONReporter_GenerateReport(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "report.json")

	rep, err := NewJSONReporter(outputFile)
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

	rep, err := NewMarkdownReporter(outputFile)
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

	// Should return findings unchanged (no LLM available)
	result, err := triageWithLLM(ctx, findings, rolesCfg)
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
	cmd := newTestCmd()

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
	cmd := newTestCmd()

	// Find the dry-run flag
	flag := cmd.Flags().Lookup("dry-run")
	require.NotNil(t, flag, "dry-run flag should exist")
	assert.Equal(t, "false", flag.DefValue)
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
