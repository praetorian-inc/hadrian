// pkg/runner/grpc_helpers_test.go
package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

// TestMetadataToMap tests converting gRPC metadata to string map
func TestMetadataToMap(t *testing.T) {
	md := metadata.MD{
		"authorization": []string{"Bearer token123"},
		"x-request-id":  []string{"req-456"},
		"multi-value":   []string{"value1", "value2"},
	}

	m := metadataToMap(md)

	assert.Equal(t, "Bearer token123", m["authorization"])
	assert.Equal(t, "req-456", m["x-request-id"])
	// multi-value should use first value
	assert.Equal(t, "value1", m["multi-value"])
}

// TestMetadataToMap_Empty tests empty metadata
func TestMetadataToMap_Empty(t *testing.T) {
	md := metadata.MD{}
	m := metadataToMap(md)
	assert.NotNil(t, m)
	assert.Empty(t, m)
}

// TestMapToMetadata tests converting string map to gRPC metadata
func TestMapToMetadata(t *testing.T) {
	m := map[string]string{
		"authorization": "Bearer token123",
		"x-request-id":  "req-456",
	}

	md := mapToMetadata(m)

	assert.Equal(t, []string{"Bearer token123"}, md.Get("authorization"))
	assert.Equal(t, []string{"req-456"}, md.Get("x-request-id"))
}

// TestMapToMetadata_Empty tests empty map
func TestMapToMetadata_Empty(t *testing.T) {
	m := map[string]string{}
	md := mapToMetadata(m)
	assert.NotNil(t, md)
	assert.Len(t, md, 0)
}

// TestGRPCStatusToString tests status code to name conversion
func TestGRPCStatusToString(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{0, "OK"},
		{1, "CANCELED"},
		{2, "UNKNOWN"},
		{3, "INVALID_ARGUMENT"},
		{4, "DEADLINE_EXCEEDED"},
		{5, "NOT_FOUND"},
		{6, "ALREADY_EXISTS"},
		{7, "PERMISSION_DENIED"},
		{8, "RESOURCE_EXHAUSTED"},
		{9, "FAILED_PRECONDITION"},
		{10, "ABORTED"},
		{11, "OUT_OF_RANGE"},
		{12, "UNIMPLEMENTED"},
		{13, "INTERNAL"},
		{14, "UNAVAILABLE"},
		{15, "DATA_LOSS"},
		{16, "UNAUTHENTICATED"},
		{99, "UNKNOWN(99)"},
		{-1, "UNKNOWN(-1)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := grpcStatusToString(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}
