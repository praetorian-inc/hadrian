package runner

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectProduction_NonProductionURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"localhost", "http://localhost:8080/api"},
		{"localhost no port", "http://localhost/api"},
		{"127.0.0.1", "http://127.0.0.1:3000"},
		{"0.0.0.0", "http://0.0.0.0:8080"},
		{"staging subdomain", "https://staging.example.com/api"},
		{"stage subdomain", "https://stage.example.com/api"},
		{"dev subdomain", "https://dev.example.com"},
		{"development subdomain", "https://development.example.com"},
		{"test subdomain", "https://test.example.com"},
		{"sandbox subdomain", "https://sandbox.example.com"},
		{"local domain", "https://api.local/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isProd, err := DetectProduction(tt.url)
			require.NoError(t, err)
			assert.False(t, isProd, "expected %q to be non-production", tt.url)
		})
	}
}

func TestDetectProduction_ProductionURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"prod subdomain", "https://prod.example.com/api"},
		{"production subdomain", "https://production.example.com/api"},
		{"live subdomain", "https://live.example.com/api"},
		{"unknown domain defaults to production", "https://api.acmecorp.com/v1"},
		{"bare domain defaults to production", "https://example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isProd, err := DetectProduction(tt.url)
			require.NoError(t, err)
			assert.True(t, isProd, "expected %q to be production", tt.url)
		})
	}
}

func TestDetectProduction_InvalidURL(t *testing.T) {
	// url.Parse is very lenient, but a truly unparseable URL should return an error
	_, err := DetectProduction("://missing-scheme")
	assert.Error(t, err)
}

func TestDetectProduction_FailSafe_UnknownDomain(t *testing.T) {
	// Unknown domains should default to production (fail-safe)
	isProd, err := DetectProduction("https://api.unknowncorp.io/v2")
	require.NoError(t, err)
	assert.True(t, isProd, "unknown domains should default to production")
}

func TestCheckProductionSafety_NonProductionSkipsPrompt(t *testing.T) {
	// Non-production URLs should pass without prompting
	err := CheckProductionSafety("http://localhost:8080")
	assert.NoError(t, err)
}

func TestCheckProductionSafety_ProductionUserConfirms(t *testing.T) {
	// Simulate user typing "yes\n" on stdin
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)

	_, err = w.Write([]byte("yes\n"))
	require.NoError(t, err)
	_ = w.Close()

	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Suppress stderr output during test
	oldStderr := os.Stderr
	os.Stderr = os.NewFile(0, os.DevNull)
	defer func() { os.Stderr = oldStderr }()

	err = CheckProductionSafety("https://api.acmecorp.com")
	assert.NoError(t, err)
}

func TestCheckProductionSafety_ProductionUserDeclines(t *testing.T) {
	// Simulate user typing "no\n" on stdin
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)

	_, err = w.Write([]byte("no\n"))
	require.NoError(t, err)
	_ = w.Close()

	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Suppress stderr output
	oldStderr := os.Stderr
	os.Stderr = os.NewFile(0, os.DevNull)
	defer func() { os.Stderr = oldStderr }()

	err = CheckProductionSafety("https://api.acmecorp.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aborted")
}

func TestCheckProductionSafety_ProductionReadFailure(t *testing.T) {
	// Simulate stdin EOF (pipe closed immediately)
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	_ = w.Close() // Close immediately — ReadString will fail

	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Capture stderr to verify error log
	stderrOutput := captureStderrFunc(t, func() {
		err = CheckProductionSafety("https://api.acmecorp.com")
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read confirmation input")
	assert.Contains(t, stderrOutput, "[ERROR]")
}

func TestCheckProductionSafety_DetectionErrorDefaultsToProduction(t *testing.T) {
	// An invalid URL that causes DetectProduction to error should still
	// trigger the production safety prompt (fail-safe behavior).
	// We simulate by providing "no" to decline.
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)

	_, err = w.Write([]byte("no\n"))
	require.NoError(t, err)
	_ = w.Close()

	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	// Suppress stderr output during test (prompt + error log)
	oldStderr := os.Stderr
	os.Stderr = os.NewFile(0, os.DevNull)
	defer func() { os.Stderr = oldStderr }()

	err = CheckProductionSafety("://bad-url")

	// Should error because user declined.
	// The key point: it prompted (treated as production) despite URL parse failure.
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aborted")
}

// captureStderrFunc captures stderr during function execution
func captureStderrFunc(t *testing.T, fn func()) string {
	t.Helper()

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	_ = r.Close()

	return buf.String()
}
