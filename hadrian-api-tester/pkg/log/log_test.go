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
	w.Close()
	os.Stdout = oldStdout

	// Read captured output
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	r.Close()

	return buf.String()
}

func TestInfo_ProducesGreenInfoPrefix(t *testing.T) {
	output := captureStdout(t, func() {
		Info("test message")
	})

	// Verify [INFO] prefix is present
	assert.Contains(t, output, "[INFO]")

	// Verify green color code is applied to [INFO]
	// Green color code is \033[32m
	assert.Contains(t, output, ColorGreen+"[INFO]"+ColorReset)

	// Verify message content
	assert.Contains(t, output, "test message")

	// Verify ends with newline
	assert.True(t, strings.HasSuffix(output, "\n"))
}

func TestWarn_ProducesMagentaWarnPrefix(t *testing.T) {
	output := captureStdout(t, func() {
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

func TestInfo_FormatStringSubstitution(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "single string substitution",
			format:   "Hello %s",
			args:     []interface{}{"World"},
			expected: "Hello World",
		},
		{
			name:     "integer substitution",
			format:   "Count: %d",
			args:     []interface{}{42},
			expected: "Count: 42",
		},
		{
			name:     "multiple substitutions",
			format:   "%s has %d items",
			args:     []interface{}{"List", 5},
			expected: "List has 5 items",
		},
		{
			name:     "no substitution",
			format:   "Plain message",
			args:     []interface{}{},
			expected: "Plain message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStdout(t, func() {
				Info(tt.format, tt.args...)
			})

			assert.Contains(t, output, tt.expected)
		})
	}
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
			output := captureStdout(t, func() {
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
	assert.Equal(t, "\033[1m", ColorBold)
}
