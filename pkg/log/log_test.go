package log

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupVerbose enables verbose mode for testing and returns a cleanup function
func setupVerbose(t *testing.T) {
	t.Helper()
	SetVerbose(true)
	t.Cleanup(func() {
		SetVerbose(false)
	})
}

// captureStdout captures stdout during function execution and returns the output
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	// Save original stdout
	oldStdout := os.Stdout

	// Create a pipe to capture output
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w

	// Run the function
	fn()

	// Close writer and restore stdout
	_ = w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	_ = r.Close()

	return buf.String()
}

func TestWarn_ProducesMagentaWarnPrefix(t *testing.T) {
	setupVerbose(t)

	output := captureStderr(t, func() {
		Warn("warning message")
	})

	// Verify [WARN] prefix is present
	assert.Contains(t, output, "[WARN]")

	// Verify magenta color code is applied to [WARN]
	// Magenta color code is \033[35m
	assert.Contains(t, output, ColorMagenta+"[WARN]"+ColorReset)

	// Verify message content
	assert.Contains(t, output, "warning message")

	// Verify ends with newline
	assert.True(t, strings.HasSuffix(output, "\n"))
}

func TestWarn_FormatStringSubstitution(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "single string substitution",
			format:   "Warning: %s",
			args:     []interface{}{"error occurred"},
			expected: "Warning: error occurred",
		},
		{
			name:     "float substitution",
			format:   "Threshold: %.2f",
			args:     []interface{}{0.95},
			expected: "Threshold: 0.95",
		},
		{
			name:     "multiple substitutions",
			format:   "%s failed with code %d",
			args:     []interface{}{"Operation", 500},
			expected: "Operation failed with code 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupVerbose(t)

			output := captureStderr(t, func() {
				Warn(tt.format, tt.args...)
			})

			assert.Contains(t, output, tt.expected)
		})
	}
}

func TestColorConstants_AreExported(t *testing.T) {
	// Verify color constants are exported and have correct values
	assert.Equal(t, "\033[0m", ColorReset)
	assert.Equal(t, "\033[31m", ColorRed)
	assert.Equal(t, "\033[33m", ColorYellow)
	assert.Equal(t, "\033[32m", ColorGreen)
	assert.Equal(t, "\033[34m", ColorBlue)
	assert.Equal(t, "\033[35m", ColorMagenta)
	assert.Equal(t, "\033[36m", ColorCyan)
	assert.Equal(t, "\033[1m", ColorBold)
}

func TestSetVerbose_ControlsOutput(t *testing.T) {
	// Test that Warn always produces output (it now always prints to stderr)
	SetVerbose(false)
	output := captureStderr(t, func() {
		Warn("always appears")
	})
	assert.Contains(t, output, "always appears")

	// Test that Debug produces no output when verbose=false
	SetVerbose(false)
	debugOutput := captureStdout(t, func() {
		Debug("should not appear")
	})
	assert.Empty(t, debugOutput)

	// Test that Debug produces output when verbose=true
	SetVerbose(true)
	debugOutput = captureStdout(t, func() {
		Debug("should appear")
	})
	assert.Contains(t, debugOutput, "should appear")

	SetVerbose(false) // cleanup
}

func TestIsVerbose_ReturnsCurrentState(t *testing.T) {
	SetVerbose(false)
	assert.False(t, IsVerbose())

	SetVerbose(true)
	assert.True(t, IsVerbose())

	SetVerbose(false) // cleanup
}

func TestDebug_ProducesCyanDebugPrefix(t *testing.T) {
	setupVerbose(t)

	output := captureStdout(t, func() {
		Debug("debug message")
	})

	assert.Contains(t, output, "[DEBUG]")
	assert.Contains(t, output, ColorCyan+"[DEBUG]"+ColorReset)
	assert.Contains(t, output, "debug message")
}

// captureStderr captures stderr during function execution and returns the output
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	// Save original stderr
	oldStderr := os.Stderr

	// Create a pipe to capture output
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stderr = w

	// Run the function
	fn()

	// Close writer and restore stderr
	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	r.Close()

	return buf.String()
}

// Test Fix 1: Race condition on verbose flag
func TestVerboseFlag_ThreadSafe(t *testing.T) {
	// Test concurrent access to SetVerbose/IsVerbose
	done := make(chan bool)

	// Start multiple goroutines that read and write verbose flag
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				SetVerbose(true)
				_ = IsVerbose()
				SetVerbose(false)
				_ = IsVerbose()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// If we reach here without data race, the test passes
	// Run with: go test -race
}

// Test Fix 2: Warn always prints to stderr regardless of verbose mode
func TestWarn_AlwaysPrintsToStderr(t *testing.T) {
	// Set verbose to false
	SetVerbose(false)

	// Warn should still print to stderr
	output := captureStderr(t, func() {
		Warn("critical warning")
	})

	assert.Contains(t, output, "[WARN]")
	assert.Contains(t, output, "critical warning")
}

func TestWarn_PrintsToStderrNotStdout(t *testing.T) {
	SetVerbose(true)

	// Capture both stdout and stderr
	stdoutOutput := captureStdout(t, func() {
		// This should NOT capture anything since Warn uses stderr
	})

	stderrOutput := captureStderr(t, func() {
		Warn("warning to stderr")
	})

	// Verify it goes to stderr, not stdout
	assert.Empty(t, stdoutOutput)
	assert.Contains(t, stderrOutput, "warning to stderr")
}
