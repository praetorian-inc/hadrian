//go:build integration

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Integration Test Fixtures
// =============================================================================

const testOpenAPISpec = `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: "%s"
paths:
  /api/users:
    get:
      summary: List users
      security:
        - bearerAuth: []
      responses:
        "200":
          description: Success
  /api/users/{id}:
    get:
      summary: Get user by ID
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Success
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
`

const testRolesConfig = `
objects:
  - users
roles:
  - name: admin
    permissions:
      - "read:users:all"
      - "write:users:all"
  - name: user
    permissions:
      - "read:users:own"
  - name: guest
    permissions: []
`

const testAuthConfig = `
auth_method: bearer_token
roles:
  admin:
    token: "admin-token-12345"
  user:
    token: "user-token-67890"
  guest:
    token: "guest-token-00000"
`

// =============================================================================
// Integration Tests
// =============================================================================

func TestIntegration_FullWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "123", "name": "test user"}`))
	}))
	defer server.Close()

	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Write API spec with server URL
	apiSpecPath := filepath.Join(tmpDir, "api.yaml")
	specContent := strings.Replace(testOpenAPISpec, "%s", server.URL, 1)
	err := os.WriteFile(apiSpecPath, []byte(specContent), 0644)
	require.NoError(t, err)

	// Write roles config
	rolesPath := filepath.Join(tmpDir, "roles.yaml")
	err = os.WriteFile(rolesPath, []byte(testRolesConfig), 0644)
	require.NoError(t, err)

	// Write auth config
	authPath := filepath.Join(tmpDir, "auth.yaml")
	err = os.WriteFile(authPath, []byte(testAuthConfig), 0644)
	require.NoError(t, err)

	// Create templates directory with a simple template
	templatesDir := filepath.Join(tmpDir, "templates", "rest")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)

	// Set HADRIAN_TEMPLATES env var
	os.Setenv("HADRIAN_TEMPLATES", templatesDir)
	defer os.Unsetenv("HADRIAN_TEMPLATES")

	// Create config
	config := Config{
		API:             apiSpecPath,
		Roles:           rolesPath,
		Auth:            authPath,
		Concurrency:     1,
		RateLimit:       10.0,
		Timeout:         30,
		AllowProduction: true, // Allow testing against mock server
		AllowInternal:   true, // Allow localhost for testing
		Output:          "terminal",
		Categories:      []string{"owasp"},
	}

	// Run the test
	ctx := context.Background()
	err = runTest(ctx, config)

	// Should complete without error (may have no findings if no templates)
	// The main goal is to verify the workflow executes
	assert.NoError(t, err)
}

func TestIntegration_DryRunMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Track request count
	var requestCount int32

	// Create mock HTTP server that tracks requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "123"}`))
	}))
	defer server.Close()

	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Write API spec
	apiSpecPath := filepath.Join(tmpDir, "api.yaml")
	specContent := strings.Replace(testOpenAPISpec, "%s", server.URL, 1)
	err := os.WriteFile(apiSpecPath, []byte(specContent), 0644)
	require.NoError(t, err)

	// Write roles config
	rolesPath := filepath.Join(tmpDir, "roles.yaml")
	err = os.WriteFile(rolesPath, []byte(testRolesConfig), 0644)
	require.NoError(t, err)

	// Set empty templates dir
	templatesDir := filepath.Join(tmpDir, "templates")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)
	os.Setenv("HADRIAN_TEMPLATES", templatesDir)
	defer os.Unsetenv("HADRIAN_TEMPLATES")

	// Create config with DryRun enabled
	config := Config{
		API:             apiSpecPath,
		Roles:           rolesPath,
		Concurrency:     1,
		RateLimit:       10.0,
		Timeout:         30,
		AllowProduction: true,
		AllowInternal:   true,
		Output:          "terminal",
		Categories:      []string{"owasp"},
		DryRun:          true, // Enable dry-run mode
	}

	// Run the test
	ctx := context.Background()
	_ = runTest(ctx, config)

	// In dry-run mode, no HTTP requests should be made to the target
	// Note: The mock server may receive 0 requests if dry-run is properly implemented
	// This test verifies the dry-run flag is respected
	assert.Equal(t, int32(0), atomic.LoadInt32(&requestCount),
		"dry-run mode should not make HTTP requests to target server")
}

func TestIntegration_VerboseOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Write API spec
	apiSpecPath := filepath.Join(tmpDir, "api.yaml")
	specContent := strings.Replace(testOpenAPISpec, "%s", server.URL, 1)
	err := os.WriteFile(apiSpecPath, []byte(specContent), 0644)
	require.NoError(t, err)

	// Write roles config
	rolesPath := filepath.Join(tmpDir, "roles.yaml")
	err = os.WriteFile(rolesPath, []byte(testRolesConfig), 0644)
	require.NoError(t, err)

	// Set empty templates dir
	templatesDir := filepath.Join(tmpDir, "templates")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)
	os.Setenv("HADRIAN_TEMPLATES", templatesDir)
	defer os.Unsetenv("HADRIAN_TEMPLATES")

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Create config with Verbose enabled
	config := Config{
		API:             apiSpecPath,
		Roles:           rolesPath,
		Concurrency:     1,
		RateLimit:       10.0,
		Timeout:         30,
		AllowProduction: true,
		AllowInternal:   true,
		Output:          "terminal",
		Categories:      []string{"owasp"},
		Verbose:         true, // Enable verbose mode
	}

	// Run the test
	ctx := context.Background()
	_ = runTest(ctx, config)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verbose mode should produce output with INFO prefix
	// Note: The actual verbose output depends on implementation
	assert.NotEmpty(t, output, "verbose mode should produce output")
}

func TestIntegration_OWASPCategoryFiltering(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Write API spec
	apiSpecPath := filepath.Join(tmpDir, "api.yaml")
	specContent := strings.Replace(testOpenAPISpec, "%s", server.URL, 1)
	err := os.WriteFile(apiSpecPath, []byte(specContent), 0644)
	require.NoError(t, err)

	// Write roles config
	rolesPath := filepath.Join(tmpDir, "roles.yaml")
	err = os.WriteFile(rolesPath, []byte(testRolesConfig), 0644)
	require.NoError(t, err)

	// Create templates directory with multiple category templates
	templatesDir := filepath.Join(tmpDir, "templates", "rest")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)
	os.Setenv("HADRIAN_TEMPLATES", templatesDir)
	defer os.Unsetenv("HADRIAN_TEMPLATES")

	// Create API1 template
	api1Template := `
id: api1-test
info:
  name: "API1 Test"
  category: "API1:2023"
  severity: "HIGH"
endpoint_selector:
  has_path_parameter: true
  requires_auth: true
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
  victim_permission_level: "higher"
http:
  - method: "GET"
    path: "/test"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
`
	err = os.WriteFile(filepath.Join(templatesDir, "api1-test.yaml"), []byte(api1Template), 0644)
	require.NoError(t, err)

	// Create API2 template
	api2Template := `
id: api2-test
info:
  name: "API2 Test"
  category: "API2:2023"
  severity: "HIGH"
endpoint_selector:
  requires_auth: false
  methods: ["GET"]
role_selector:
  attacker_permission_level: "none"
http:
  - method: "GET"
    path: "/test"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
`
	err = os.WriteFile(filepath.Join(templatesDir, "api2-test.yaml"), []byte(api2Template), 0644)
	require.NoError(t, err)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Create config with OWASP filter for API1 only
	config := Config{
		API:             apiSpecPath,
		Roles:           rolesPath,
		Concurrency:     1,
		RateLimit:       10.0,
		Timeout:         30,
		AllowProduction: true,
		AllowInternal:   true,
		Output:          "terminal",
		Categories:      []string{"owasp"},
		OWASPCategories: []string{"API1"}, // Filter to API1 only
	}

	// Run the test
	ctx := context.Background()
	_ = runTest(ctx, config)

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// The output should mention filtering to API1 templates
	assert.Contains(t, output, "API1", "output should mention API1 category filter")
}

func TestIntegration_JSONOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Write API spec
	apiSpecPath := filepath.Join(tmpDir, "api.yaml")
	specContent := strings.Replace(testOpenAPISpec, "%s", server.URL, 1)
	err := os.WriteFile(apiSpecPath, []byte(specContent), 0644)
	require.NoError(t, err)

	// Write roles config
	rolesPath := filepath.Join(tmpDir, "roles.yaml")
	err = os.WriteFile(rolesPath, []byte(testRolesConfig), 0644)
	require.NoError(t, err)

	// Set empty templates dir
	templatesDir := filepath.Join(tmpDir, "templates")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)
	os.Setenv("HADRIAN_TEMPLATES", templatesDir)
	defer os.Unsetenv("HADRIAN_TEMPLATES")

	// Create output file path
	outputFile := filepath.Join(tmpDir, "report.json")

	// Create config with JSON output
	config := Config{
		API:             apiSpecPath,
		Roles:           rolesPath,
		Concurrency:     1,
		RateLimit:       10.0,
		Timeout:         30,
		AllowProduction: true,
		AllowInternal:   true,
		Output:          "json",
		OutputFile:      outputFile,
		Categories:      []string{"owasp"},
	}

	// Run the test
	ctx := context.Background()
	err = runTest(ctx, config)
	require.NoError(t, err)

	// Read and verify JSON output
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	// Verify it's valid JSON
	var result interface{}
	err = json.Unmarshal(data, &result)
	assert.NoError(t, err, "output should be valid JSON")
}

func TestIntegration_MarkdownOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Write API spec
	apiSpecPath := filepath.Join(tmpDir, "api.yaml")
	specContent := strings.Replace(testOpenAPISpec, "%s", server.URL, 1)
	err := os.WriteFile(apiSpecPath, []byte(specContent), 0644)
	require.NoError(t, err)

	// Write roles config
	rolesPath := filepath.Join(tmpDir, "roles.yaml")
	err = os.WriteFile(rolesPath, []byte(testRolesConfig), 0644)
	require.NoError(t, err)

	// Set empty templates dir
	templatesDir := filepath.Join(tmpDir, "templates")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)
	os.Setenv("HADRIAN_TEMPLATES", templatesDir)
	defer os.Unsetenv("HADRIAN_TEMPLATES")

	// Create output file path
	outputFile := filepath.Join(tmpDir, "report.md")

	// Create config with Markdown output
	config := Config{
		API:             apiSpecPath,
		Roles:           rolesPath,
		Concurrency:     1,
		RateLimit:       10.0,
		Timeout:         30,
		AllowProduction: true,
		AllowInternal:   true,
		Output:          "markdown",
		OutputFile:      outputFile,
		Categories:      []string{"owasp"},
	}

	// Run the test
	ctx := context.Background()
	err = runTest(ctx, config)
	require.NoError(t, err)

	// Read and verify Markdown output
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	content := string(data)
	// Verify it contains Markdown headers
	assert.Contains(t, content, "#", "output should contain Markdown headers")
}
