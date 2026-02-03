//go:build integration

package runner

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_RequestIDsInTerminalOutput verifies that request IDs flow
// from template execution through to terminal reporter output
func TestE2E_RequestIDsInTerminalOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Track request IDs received by server
	var capturedRequestIDs []string

	// Create mock HTTP server that responds with vulnerability pattern
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture request ID header
		requestID := r.Header.Get("X-Hadrian-Request-Id")
		if requestID != "" {
			capturedRequestIDs = append(capturedRequestIDs, requestID)
		}

		// Return vulnerable response (200 OK for anonymous access)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id": "123", "name": "admin", "role": "administrator"}`))
	}))
	defer server.Close()

	// Create temp directory for test files
	tmpDir := t.TempDir()

	// Write API spec with server URL
	apiSpec := `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
servers:
  - url: "` + server.URL + `"
paths:
  /api/users/{id}:
    get:
      summary: Get user
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
	apiSpecPath := filepath.Join(tmpDir, "api.yaml")
	err := os.WriteFile(apiSpecPath, []byte(apiSpec), 0644)
	require.NoError(t, err)

	// Write roles config
	rolesConfig := `
objects:
  - users
roles:
  - name: admin
    permissions:
      - "read:users:all"
  - name: user
    permissions:
      - "read:users:own"
`
	rolesPath := filepath.Join(tmpDir, "roles.yaml")
	err = os.WriteFile(rolesPath, []byte(rolesConfig), 0644)
	require.NoError(t, err)

	// Write auth config
	authConfig := `
auth_method: bearer_token
roles:
  admin:
    token: "admin-token"
  user:
    token: "user-token"
`
	authPath := filepath.Join(tmpDir, "auth.yaml")
	err = os.WriteFile(authPath, []byte(authConfig), 0644)
	require.NoError(t, err)

	// Create templates directory
	templatesDir := filepath.Join(tmpDir, "templates", "owasp")
	err = os.MkdirAll(templatesDir, 0755)
	require.NoError(t, err)

	// Create simple template that will match
	template := `
id: test-vuln
info:
  name: "Test Vulnerability"
  category: "API1"
  severity: "HIGH"
http:
  - method: "GET"
    path: "` + server.URL + `/api/users/123"
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["admin"]
`
	templatePath := filepath.Join(templatesDir, "test.yaml")
	err = os.WriteFile(templatePath, []byte(template), 0644)
	require.NoError(t, err)

	// Set HADRIAN_TEMPLATES env var to parent directory
	os.Setenv("HADRIAN_TEMPLATES", filepath.Join(tmpDir, "templates"))
	defer os.Unsetenv("HADRIAN_TEMPLATES")

	// Capture terminal output
	var outputBuf bytes.Buffer

	// Create config
	config := Config{
		API:             apiSpecPath,
		Roles:           rolesPath,
		Auth:            authPath,
		Concurrency:     1,
		RateLimit:       10.0,
		Timeout:         30,
		AllowProduction: true,
		AllowInternal:   true,
		Output:          "terminal",
		Categories:      []string{"owasp"},
		Verbose:         true,
	}

	// Redirect stdout to capture terminal output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run the test
	ctx := context.Background()
	err = runTest(ctx, config)

	// Restore stdout and capture output
	w.Close()
	os.Stdout = oldStdout
	bytes, _ := os.ReadFile(r.Name())
	outputBuf.Write(bytes)

	require.NoError(t, err)

	// Verify request IDs were sent to server
	require.NotEmpty(t, capturedRequestIDs, "server should have received request ID headers")

	// Verify terminal output
	output := outputBuf.String()

	// Should contain finding
	assert.Contains(t, output, "BOLA Test", "output should contain finding name")
	assert.Contains(t, output, "HIGH", "output should contain severity")

	// CRITICAL: Should contain request IDs in output
	assert.Contains(t, output, "Request IDs:", "output should label request IDs section")

	// Verify at least one captured request ID appears in output
	foundRequestID := false
	for _, reqID := range capturedRequestIDs {
		if strings.Contains(output, reqID) {
			foundRequestID = true
			break
		}
	}
	assert.True(t, foundRequestID, "at least one request ID from server should appear in terminal output")
}
