package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
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

// TestCustomHeaders_Integration tests that custom headers are sent to the server
func TestCustomHeaders_Integration(t *testing.T) {
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	customHeaders := map[string]string{
		"X-Tenant-Id":    "acme-corp",
		"X-Custom-Token": "abc123",
	}

	executor := templates.NewExecutor(server.Client(), customHeaders)
	tmpl := &templates.CompiledTemplate{
		Template: &templates.Template{
			ID: "test-headers",
			HTTP: []templates.HTTPTest{
				{
					Method: "GET",
					Path:   "{{operation.path}}",
				},
			},
		},
	}
	op := &model.Operation{
		Method: "GET",
		Path:   server.URL + "/test",
	}

	_, err := executor.Execute(context.Background(), tmpl, op, nil, nil)
	require.NoError(t, err)

	// Verify custom headers arrived at the server
	assert.Equal(t, "acme-corp", receivedHeaders.Get("X-Tenant-Id"))
	assert.Equal(t, "abc123", receivedHeaders.Get("X-Custom-Token"))

	// Verify X-Hadrian-Request-Id is also present (set after custom headers)
	assert.NotEmpty(t, receivedHeaders.Get("X-Hadrian-Request-Id"))
}
