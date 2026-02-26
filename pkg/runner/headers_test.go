package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCustomHeaders_Empty tests that an empty slice returns an empty map
func TestParseCustomHeaders_Empty(t *testing.T) {
	result, err := ParseCustomHeaders([]string{})
	require.NoError(t, err)
	assert.Empty(t, result)
}

// TestParseCustomHeaders_SingleHeader tests parsing a single well-formed header
func TestParseCustomHeaders_SingleHeader(t *testing.T) {
	result, err := ParseCustomHeaders([]string{"X-Custom-Header: my-value"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"X-Custom-Header": "my-value"}, result)
}

// TestParseCustomHeaders_MultipleHeaders tests parsing multiple headers
func TestParseCustomHeaders_MultipleHeaders(t *testing.T) {
	result, err := ParseCustomHeaders([]string{
		"X-Api-Key: secret123",
		"X-Tenant-Id: tenant-456",
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"X-Api-Key":   "secret123",
		"X-Tenant-Id": "tenant-456",
	}, result)
}

// TestParseCustomHeaders_ValueWithColons tests that values containing colons are preserved
func TestParseCustomHeaders_ValueWithColons(t *testing.T) {
	result, err := ParseCustomHeaders([]string{"Authorization: Bearer token:with:colons"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"Authorization": "Bearer token:with:colons"}, result)
}

// TestParseCustomHeaders_TrimsWhitespace tests that leading/trailing whitespace is trimmed
func TestParseCustomHeaders_TrimsWhitespace(t *testing.T) {
	result, err := ParseCustomHeaders([]string{"  X-Custom  :  my value  "})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"X-Custom": "my value"}, result)
}

// TestParseCustomHeaders_MalformedHeader tests that malformed headers return an error
func TestParseCustomHeaders_MalformedHeader(t *testing.T) {
	_, err := ParseCustomHeaders([]string{"InvalidHeaderWithoutColon"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid header format")
	assert.Contains(t, err.Error(), "expected 'Key: Value'")
}

// TestParseCustomHeaders_EmptyKey tests that headers with empty keys return an error
func TestParseCustomHeaders_EmptyKey(t *testing.T) {
	_, err := ParseCustomHeaders([]string{": some-value"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty key")
}

// TestParseCustomHeaders_DuplicateKeys tests that last value wins for duplicate keys
func TestParseCustomHeaders_DuplicateKeys(t *testing.T) {
	result, err := ParseCustomHeaders([]string{
		"X-Custom: first",
		"X-Custom: second",
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"X-Custom": "second"}, result)
}

// TestParseCustomHeaders_NilInput tests nil input returns empty map without error
func TestParseCustomHeaders_NilInput(t *testing.T) {
	result, err := ParseCustomHeaders(nil)
	require.NoError(t, err)
	assert.Empty(t, result)
}
