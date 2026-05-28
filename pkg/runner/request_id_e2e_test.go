//go:build integration

package runner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_RequestIDsInTerminalOutput verifies that request IDs flow from
// template execution through to terminal reporter output. It runs the real
// BOLA template against the in-process vulnerable fixture (no Docker) and
// captures the X-Hadrian-Request-Id headers the executor sends.
func TestE2E_RequestIDsInTerminalOutput(t *testing.T) {
	var mu sync.Mutex
	var capturedRequestIDs []string

	// Wrap the vulnerable fixture handler (built once) to capture request ID headers.
	fixture := vulnerableRESTHandler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get("X-Hadrian-Request-Id"); id != "" {
			mu.Lock()
			capturedRequestIDs = append(capturedRequestIDs, id)
			mu.Unlock()
		}
		fixture.ServeHTTP(w, r)
	}))
	defer server.Close()

	apiPath, rolesPath, authPath := writeFixtureConfigs(t, server.URL)

	config := Config{
		API:         apiPath,
		Roles:       rolesPath,
		Auth:        authPath,
		TemplateDir: restTemplateDir,
		Categories:  []string{"all"},
		Templates:   []string{"01-api1-bola-read"},
		RateLimit:   50.0,
		Timeout:     30,
		Output:      "terminal",
		Verbose:     true,
	}

	// Capture stdout.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runTest(context.Background(), config)

	_ = w.Close()
	os.Stdout = oldStdout
	var outputBuf bytes.Buffer
	_, _ = io.Copy(&outputBuf, r)

	require.NoError(t, err)

	mu.Lock()
	ids := append([]string(nil), capturedRequestIDs...)
	mu.Unlock()
	require.NotEmpty(t, ids, "server should have received request ID headers")

	output := outputBuf.String()
	assert.Contains(t, output, "BOLA", "output should contain the BOLA finding name")
	assert.Contains(t, output, "HIGH", "output should contain severity")
	assert.Contains(t, output, "Request IDs:", "output should label request IDs section")

	foundRequestID := false
	for _, reqID := range ids {
		if strings.Contains(output, reqID) {
			foundRequestID = true
			break
		}
	}
	assert.True(t, foundRequestID, "at least one request ID from the server should appear in terminal output")
}
