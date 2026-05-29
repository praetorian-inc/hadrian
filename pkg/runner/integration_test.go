//go:build integration

package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Integration tests — in-process httptest fixtures, no Docker.
//
// These exercise Hadrian's real templates (templates/rest/) against the seeded
// vulnerable API from fixtures_test.go, asserting that BOLA/IDOR, broken
// authentication, excessive data exposure (BOPLA), and BFLA are detected
// without launching any container.
// =============================================================================

// runFixtureTemplates runs the given REST templates against the vulnerable
// fixture server and returns the resulting findings.
func runFixtureTemplates(t *testing.T, templateIDs ...string) []*model.Finding {
	t.Helper()
	server := newVulnerableRESTServer(t)
	apiPath, rolesPath, authPath := writeFixtureConfigs(t, server.URL)

	config := Config{
		API:         apiPath,
		Roles:       rolesPath,
		Auth:        authPath,
		TemplateDir: restTemplateDir,
		Categories:  []string{"all"},
		Templates:   templateIDs,
		RateLimit:   50.0,
		Timeout:     30,
		Output:      "json",
	}

	findings, err := RunTest(context.Background(), config)
	require.NoError(t, err, "RunTest should not error against in-process fixture")
	return findings
}

// findingsByCategory counts findings per OWASP category.
func findingsByCategory(findings []*model.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Category]++
	}
	return counts
}

func TestIntegration_BOLADetection(t *testing.T) {
	findings := runFixtureTemplates(t, "01-api1-bola-read")
	counts := findingsByCategory(findings)
	assert.Positive(t, counts["API1:2023"],
		"BOLA template should detect cross-user object access on the vulnerable fixture; got %v", counts)
}

func TestIntegration_BrokenAuthDetection(t *testing.T) {
	findings := runFixtureTemplates(t, "04-api2-broken-auth-no-token")
	counts := findingsByCategory(findings)
	assert.Positive(t, counts["API2:2023"],
		"broken-auth template should detect the unauthenticated /api/internal/config access; got %v", counts)
}

func TestIntegration_ExcessiveDataExposure(t *testing.T) {
	findings := runFixtureTemplates(t, "05-api3-excessive-data-exposure")
	counts := findingsByCategory(findings)
	assert.Positive(t, counts["API3:2023"],
		"excessive-data template should detect the leaked SSN/credit_card fields; got %v", counts)
}

func TestIntegration_BFLADetection(t *testing.T) {
	findings := runFixtureTemplates(t, "06-api5-bfla-admin-access")
	counts := findingsByCategory(findings)
	assert.Positive(t, counts["API5:2023"],
		"BFLA template should detect non-admin access to /api/admin/users; got %v", counts)
}

func TestIntegration_BOLAWriteDetection(t *testing.T) {
	// PUT to /api/documents/{id} succeeds for a non-owner → BOLA write.
	findings := runFixtureTemplates(t, "02-api1-bola-write")
	counts := findingsByCategory(findings)
	assert.Positive(t, counts["API1:2023"],
		"BOLA-write template should detect cross-user object modification; got %v", counts)
}

func TestIntegration_BOLADeleteDetection(t *testing.T) {
	// DELETE to /api/orders/{id} succeeds for a non-owner → BOLA delete.
	findings := runFixtureTemplates(t, "03-api1-bola-delete")
	counts := findingsByCategory(findings)
	assert.Positive(t, counts["API1:2023"],
		"BOLA-delete template should detect cross-user object deletion; got %v", counts)
}

// TestIntegration_NoRegression_AllTemplates runs the full REST template suite
// against the fixture and asserts the detection rate has not regressed: each of
// the core OWASP categories the fixture seeds must still produce findings.
func TestIntegration_NoRegression_AllTemplates(t *testing.T) {
	findings := runFixtureTemplates(t) // no filter → all templates
	require.NotEmpty(t, findings, "running all templates against the vulnerable fixture should yield findings")

	counts := findingsByCategory(findings)
	t.Logf("findings by category: %v (total=%d)", counts, len(findings))

	for _, category := range []string{"API1:2023", "API2:2023", "API3:2023", "API5:2023"} {
		assert.Positivef(t, counts[category],
			"expected at least one %s finding against the seeded fixture (regression?); got %v", category, counts)
	}

	for _, f := range findings {
		assert.True(t, f.IsVulnerability, "returned findings should be vulnerabilities")
	}
}

// TestIntegration_SecuredServer_NoFindings is the control case for
// TestIntegration_NoRegression_AllTemplates: the SAME templates, run against a
// properly-secured server (401/403 on every endpoint), must produce ZERO
// findings. This proves the detection assertions are differential (vulnerable →
// findings, secured → none) and guards against an over-detection regression
// that would emit findings regardless of the response.
func TestIntegration_SecuredServer_NoFindings(t *testing.T) {
	server := newSecuredRESTServer(t)
	apiPath, rolesPath, authPath := writeFixtureConfigs(t, server.URL)

	config := Config{
		API:         apiPath,
		Roles:       rolesPath,
		Auth:        authPath,
		TemplateDir: restTemplateDir,
		Categories:  []string{"all"},
		RateLimit:   50.0,
		Timeout:     30,
		Output:      "json",
	}

	findings, err := RunTest(context.Background(), config)
	require.NoError(t, err)
	assert.Empty(t, findings,
		"a properly-secured server (401/403) must yield no findings; got %v", findingsByCategory(findings))
}

// TestIntegration_JSONOutput verifies the CLI path (runTest) produces valid JSON
// against the in-process fixture.
func TestIntegration_JSONOutput(t *testing.T) {
	server := newVulnerableRESTServer(t)
	apiPath, rolesPath, authPath := writeFixtureConfigs(t, server.URL)
	outputFile := filepath.Join(t.TempDir(), "report.json")

	config := Config{
		API:         apiPath,
		Roles:       rolesPath,
		Auth:        authPath,
		TemplateDir: restTemplateDir,
		Categories:  []string{"all"},
		RateLimit:   50.0,
		Timeout:     30,
		Output:      "json",
		OutputFile:  outputFile,
	}

	require.NoError(t, runTest(context.Background(), config))

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	var result interface{}
	assert.NoError(t, json.Unmarshal(data, &result), "output should be valid JSON")
}

// TestIntegration_MarkdownOutput verifies the markdown reporter path.
func TestIntegration_MarkdownOutput(t *testing.T) {
	server := newVulnerableRESTServer(t)
	apiPath, rolesPath, authPath := writeFixtureConfigs(t, server.URL)
	outputFile := filepath.Join(t.TempDir(), "report.md")

	config := Config{
		API:         apiPath,
		Roles:       rolesPath,
		Auth:        authPath,
		TemplateDir: restTemplateDir,
		Categories:  []string{"all"},
		RateLimit:   50.0,
		Timeout:     30,
		Output:      "markdown",
		OutputFile:  outputFile,
	}

	require.NoError(t, runTest(context.Background(), config))

	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	content := string(data)
	assert.Contains(t, content, "# Hadrian Security Test Report", "markdown report should contain the report header")
	assert.Contains(t, content, "## Summary", "markdown report should contain the summary section")
}

// TestIntegration_DryRunMode verifies dry-run sends NO requests to the target.
func TestIntegration_DryRunMode(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		vulnerableRESTHandler().ServeHTTP(w, r)
	}))
	defer server.Close()

	apiPath, rolesPath, authPath := writeFixtureConfigs(t, server.URL)

	config := Config{
		API:         apiPath,
		Roles:       rolesPath,
		Auth:        authPath,
		TemplateDir: restTemplateDir,
		Categories:  []string{"all"},
		RateLimit:   50.0,
		Timeout:     30,
		Output:      "terminal",
		DryRun:      true,
	}

	require.NoError(t, runTest(context.Background(), config))
	assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount),
		"dry-run mode must not send any HTTP request to the target")
}
