package runner

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/graphql"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// getSeverityColor tests (helpers.go)
// =============================================================================

func TestGetSeverityColor_AllSeverities(t *testing.T) {
	tests := []struct {
		severity model.Severity
		expected string
	}{
		{model.SeverityCritical, colorRed},
		{model.SeverityHigh, colorOrange},
		{model.SeverityMedium, colorYellow},
		{model.SeverityLow, colorBlue},
		{model.SeverityInfo, colorGreen},
		{model.Severity("UNKNOWN"), colorReset},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			assert.Equal(t, tt.expected, getSeverityColor(tt.severity))
		})
	}
}

// =============================================================================
// TerminalReporter.ReportFinding with roles and request IDs (helpers.go)
// =============================================================================

func TestTerminalReporter_ReportFinding_WithBothRoles(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer func() { _ = tmpFile.Close() }()

	rep := NewTerminalReporter(tmpFile, 2) // limit 2 request IDs
	finding := &model.Finding{
		Severity:     model.SeverityMedium,
		Category:     "API1",
		Name:         "BOLA",
		Method:       "GET",
		Endpoint:     "/api/users/{id}",
		AttackerRole: "user",
		VictimRole:   "admin",
		RequestIDs:   []string{"req-1", "req-2", "req-3"},
	}

	rep.ReportFinding(finding)

	_, _ = tmpFile.Seek(0, 0)
	output := make([]byte, 4096)
	n, _ := tmpFile.Read(output)
	outputStr := string(output[:n])

	assert.Contains(t, outputStr, "attacker=user, victim=admin")
	// Request IDs limited to 2, showing last 2
	assert.Contains(t, outputStr, "req-2, req-3")
	assert.NotContains(t, outputStr, "req-1")
}

func TestTerminalReporter_ReportFinding_OnlyAttacker(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer func() { _ = tmpFile.Close() }()

	rep := NewTerminalReporter(tmpFile, 0) // 0 = show all request IDs
	finding := &model.Finding{
		Severity:     model.SeverityLow,
		Category:     "API1",
		Name:         "Test",
		Method:       "GET",
		Endpoint:     "/api/test",
		AttackerRole: "user",
		VictimRole:   "", // No victim
		RequestIDs:   []string{"req-1"},
	}

	rep.ReportFinding(finding)

	_, _ = tmpFile.Seek(0, 0)
	output := make([]byte, 4096)
	n, _ := tmpFile.Read(output)
	outputStr := string(output[:n])

	assert.Contains(t, outputStr, "Role: user")
	assert.Contains(t, outputStr, "req-1")
}

// =============================================================================
// JSONReporter.ReportFinding / GenerateReport tests (helpers.go)
// =============================================================================

func TestJSONReporter_ReportFinding(t *testing.T) {
	rep, err := NewJSONReporter("", 1) // stdout
	require.NoError(t, err)

	finding := &model.Finding{
		ID:       "json-test",
		Category: "API1",
		Severity: model.SeverityHigh,
	}
	rep.ReportFinding(finding)

	assert.Len(t, rep.findings, 1)
	assert.Equal(t, "json-test", rep.findings[0].ID)
}

func TestJSONReporter_GenerateReport_WithRequestIDLimit(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "report.json")

	rep, err := NewJSONReporter(outputFile, 1) // Limit to 1 request ID
	require.NoError(t, err)

	findings := []*model.Finding{
		{
			ID:         "test-1",
			Category:   "API1",
			Severity:   model.SeverityHigh,
			RequestIDs: []string{"req-1", "req-2", "req-3"},
		},
	}
	stats := &Stats{Findings: 1, High: 1, Duration: time.Second}

	err = rep.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	// Should only contain "req-3" (last one, limit=1)
	assert.Contains(t, string(data), "req-3")
}

func TestJSONReporter_GenerateReport_Stdout(t *testing.T) {
	rep, err := NewJSONReporter("", 1)
	require.NoError(t, err)

	stats := &Stats{Findings: 0, Duration: time.Second}
	// Writing to stdout - should not panic
	err = rep.GenerateReport([]*model.Finding{}, stats)
	assert.NoError(t, err)
}

// =============================================================================
// MarkdownReporter.ReportFinding / GenerateReport tests (helpers.go)
// =============================================================================

func TestMarkdownReporter_ReportFinding(t *testing.T) {
	rep, err := NewMarkdownReporter("", 1)
	require.NoError(t, err)

	finding := &model.Finding{
		ID:       "md-test",
		Category: "API1",
		Severity: model.SeverityHigh,
	}
	rep.ReportFinding(finding)

	assert.Len(t, rep.findings, 1)
	assert.Equal(t, "md-test", rep.findings[0].ID)
}

func TestMarkdownReporter_GenerateReport_WithAllFields(t *testing.T) {
	outputFile := filepath.Join(t.TempDir(), "report.md")

	rep, err := NewMarkdownReporter(outputFile, 2)
	require.NoError(t, err)

	findings := []*model.Finding{
		{
			ID:           "test-1",
			Category:     "API1",
			Name:         "BOLA Test",
			Severity:     model.SeverityCritical,
			Method:       "GET",
			Endpoint:     "/api/users/{id}",
			Description:  "Test description",
			AttackerRole: "user",
			VictimRole:   "admin",
			RequestIDs:   []string{"req-1", "req-2", "req-3"},
			LLMAnalysis: &model.LLMTriage{
				Provider:        "test",
				IsVulnerability: true,
				Confidence:      0.95,
				Reasoning:       "Access confirmed",
			},
		},
	}
	stats := &Stats{
		Findings: 1, Critical: 1,
		Duration: time.Second,
	}

	err = rep.GenerateReport(findings, stats)
	require.NoError(t, err)

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	outputStr := string(data)

	assert.Contains(t, outputStr, "# Hadrian Security Test Report")
	assert.Contains(t, outputStr, "| Critical | 1 |")
	assert.Contains(t, outputStr, "BOLA Test")
	assert.Contains(t, outputStr, "**Attacker Role:** user")
	assert.Contains(t, outputStr, "**Victim Role:** admin")
	assert.Contains(t, outputStr, "req-2, req-3") // limited to last 2
	assert.Contains(t, outputStr, "Vulnerability: true")
	assert.Contains(t, outputStr, "95%")
	assert.Contains(t, outputStr, "Access confirmed")
}

func TestMarkdownReporter_GenerateReport_Stdout(t *testing.T) {
	rep, err := NewMarkdownReporter("", 1)
	require.NoError(t, err)

	stats := &Stats{Findings: 0, Duration: time.Second}
	err = rep.GenerateReport([]*model.Finding{}, stats)
	assert.NoError(t, err)
}

// =============================================================================
// GraphQL helper tests
// =============================================================================

func TestGraphqlVerboseLog_Enabled(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	graphqlVerboseLog(true, "test message: %s", "hello")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "test message: hello")
}

func TestGraphqlVerboseLog_Disabled(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	graphqlVerboseLog(false, "should not appear")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Empty(t, buf.String())
}

func TestGraphqlDryRunLog_Enabled(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	graphqlDryRunLog(true, "dry run: %s", "test")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "[DRY RUN] dry run: test")
}

func TestGraphqlDryRunLog_Disabled(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	graphqlDryRunLog(false, "should not appear")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Empty(t, buf.String())
}

func TestReportSchemaInfo(t *testing.T) {
	schema := &graphql.Schema{
		Queries:   []*graphql.FieldDef{{Name: "user"}},
		Mutations: []*graphql.FieldDef{{Name: "createUser"}},
		Types:     map[string]*graphql.TypeDef{"User": {}},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	reportSchemaInfo(schema, true)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "Schema loaded successfully")
	assert.Contains(t, output, "Queries: 1")
	assert.Contains(t, output, "Mutations: 1")
	assert.Contains(t, output, "Types: 1")
}

func TestReportAuthConfigsLoaded(t *testing.T) {
	authConfig := &AuthConfig{
		Method: "bearer",
		Roles:  map[string]*auth.RoleAuth{"admin": {Token: "test"}},
	}
	rolesConfig := &RolesConfig{
		Roles: []*roles.Role{{Name: "admin"}, {Name: "user"}},
	}
	authConfigs := map[string]*graphql.AuthInfo{
		"admin": {Method: "bearer"},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	reportAuthConfigsLoaded("auth.yaml", "roles.yaml", authConfig, rolesConfig, authConfigs, true)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.Contains(t, output, "Auth config loaded: auth.yaml")
	assert.Contains(t, output, "Roles config loaded: roles.yaml (2 roles)")
	assert.Contains(t, output, "Auth configs loaded: 1 roles available")
}

func TestCreateGraphQLHTTPClient(t *testing.T) {
	config := GraphQLConfig{
		Timeout: 30,
	}

	client, err := createGraphQLHTTPClient(config)
	assert.NoError(t, err)
	assert.NotNil(t, client)
}

func TestWrapWithRateLimiting(t *testing.T) {
	config := GraphQLConfig{
		RateLimit:            5.0,
		RateLimitBackoff:     "exponential",
		RateLimitMaxWait:     60 * time.Second,
		RateLimitMaxRetries:  5,
		RateLimitStatusCodes: []int{429},
	}

	// Use a simple HTTP client as base
	baseClient := &mockHTTPClient{
		responses: []*http.Response{makeResponse(200, "OK", nil)},
	}

	wrapped := wrapWithRateLimiting(baseClient, config)
	assert.NotNil(t, wrapped)

	// Verify it returns a RateLimitingClient
	_, ok := wrapped.(*RateLimitingClient)
	assert.True(t, ok, "should return a RateLimitingClient")
}

// =============================================================================
// filterGraphQLTemplatesByID tests (more coverage)
// =============================================================================

func TestFilterGraphQLTemplatesByID_EmptyFilter(t *testing.T) {
	tmpls := []*templates.Template{
		{ID: "template-1"},
		{ID: "template-2"},
	}

	result := filterGraphQLTemplatesByID(tmpls, []string{})
	assert.Len(t, result, 2)
}

func TestFilterGraphQLTemplatesByID_SingleMatch(t *testing.T) {
	tmpls := []*templates.Template{
		{ID: "template-1"},
		{ID: "template-2"},
		{ID: "template-3"},
	}

	result := filterGraphQLTemplatesByID(tmpls, []string{"template-2"})
	assert.Len(t, result, 1)
	assert.Equal(t, "template-2", result[0].ID)
}

func TestFilterGraphQLTemplatesByID_MultipleMatches(t *testing.T) {
	tmpls := []*templates.Template{
		{ID: "template-1"},
		{ID: "template-2"},
		{ID: "template-3"},
	}

	result := filterGraphQLTemplatesByID(tmpls, []string{"template-1", "template-3"})
	assert.Len(t, result, 2)
}

func TestFilterGraphQLTemplatesByID_NoMatch(t *testing.T) {
	tmpls := []*templates.Template{
		{ID: "template-1"},
	}

	result := filterGraphQLTemplatesByID(tmpls, []string{"nonexistent"})
	assert.Len(t, result, 0)
}

// =============================================================================
// gRPC helper tests
// =============================================================================

func TestGrpcVerboseLog_Enabled(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	grpcVerboseLog(true, "grpc verbose: %s", "test")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "grpc verbose: test")
}

func TestGrpcVerboseLog_Disabled(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	grpcVerboseLog(false, "should not appear")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Empty(t, buf.String())
}

func TestGrpcDryRunLog_Enabled(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	grpcDryRunLog(true, "dry run: %s", "test")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Contains(t, buf.String(), "[DRY RUN] dry run: test")
}

func TestGrpcDryRunLog_Disabled(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	grpcDryRunLog(false, "should not appear")

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	assert.Empty(t, buf.String())
}

// =============================================================================
// matchMethodPattern tests (grpc.go - at 42.9%)
// =============================================================================

func TestMatchMethodPattern_WildcardSuffix(t *testing.T) {
	assert.True(t, matchMethodPattern("DeleteUser", "Delete*"))
	assert.False(t, matchMethodPattern("GetUser", "Delete*"))
}

func TestMatchMethodPattern_WildcardPrefix(t *testing.T) {
	assert.True(t, matchMethodPattern("GetUser", "*User"))
	assert.True(t, matchMethodPattern("DeleteUser", "*User"))
	assert.False(t, matchMethodPattern("GetProfile", "*User"))
}

func TestMatchMethodPattern_ExactMatch(t *testing.T) {
	assert.True(t, matchMethodPattern("GetProfile", "GetProfile"))
	assert.False(t, matchMethodPattern("GetProfile", "GetUser"))
}

// =============================================================================
// generateGraphQLID tests
// =============================================================================

func TestGenerateGraphQLID_Unique(t *testing.T) {
	id1 := generateGraphQLID()
	id2 := generateGraphQLID()

	assert.Len(t, id1, 32) // 16 bytes = 32 hex chars
	assert.Len(t, id2, 32)
	assert.NotEqual(t, id1, id2, "generated IDs should be unique")
}

// =============================================================================
// TerminalReporter.GenerateReport edge cases
// =============================================================================

func TestTerminalReporter_GenerateReport_NoFindings(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer func() { _ = tmpFile.Close() }()

	rep := NewTerminalReporter(tmpFile, 1)
	stats := &Stats{
		Findings: 0,
		Duration: time.Second * 5,
	}

	err = rep.GenerateReport([]*model.Finding{}, stats)
	require.NoError(t, err)

	_, _ = tmpFile.Seek(0, 0)
	output := make([]byte, 4096)
	n, _ := tmpFile.Read(output)
	outputStr := string(output[:n])

	assert.Contains(t, outputStr, "Total findings: 0")
	// Should not contain severity counts since all are 0
	assert.NotContains(t, outputStr, "CRITICAL:")
	assert.NotContains(t, outputStr, "HIGH:")
}

func TestTerminalReporter_GenerateReport_AllSeverities(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "output")
	require.NoError(t, err)
	defer func() { _ = tmpFile.Close() }()

	rep := NewTerminalReporter(tmpFile, 1)
	stats := &Stats{
		Findings: 5,
		Critical: 1,
		High:     1,
		Medium:   1,
		Low:      1,
		Info:     1,
		Duration: time.Minute,
	}

	err = rep.GenerateReport([]*model.Finding{}, stats)
	require.NoError(t, err)

	_, _ = tmpFile.Seek(0, 0)
	output := make([]byte, 4096)
	n, _ := tmpFile.Read(output)
	outputStr := string(output[:n])

	assert.Contains(t, outputStr, "CRITICAL: 1")
	assert.Contains(t, outputStr, "HIGH: 1")
	assert.Contains(t, outputStr, "MEDIUM: 1")
	assert.Contains(t, outputStr, "LOW: 1")
	assert.Contains(t, outputStr, "INFO: 1")
	assert.Contains(t, outputStr, "Total findings: 5")
}
