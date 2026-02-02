package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasUnresolvedPlaceholders(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "no placeholders",
			path:     "/api/v1/resources",
			expected: "",
		},
		{
			name:     "single placeholder",
			path:     "/api/v1/resources/{id}",
			expected: "id",
		},
		{
			name:     "multiple placeholders returns first",
			path:     "/api/v1/resources/{id}/items/{item_id}",
			expected: "id",
		},
		{
			name:     "placeholder at start",
			path:     "{version}/resources",
			expected: "version",
		},
		{
			name:     "unclosed brace",
			path:     "/api/v1/resources/{id",
			expected: "",
		},
		{
			name:     "empty string",
			path:     "",
			expected: "",
		},
		{
			name:     "resolved placeholder",
			path:     "/api/v1/resources/resource123",
			expected: "",
		},
		{
			name:     "nested braces",
			path:     "/api/v1/{outer{inner}}",
			expected: "outer{inner",
		},
		{
			name:     "empty placeholder",
			path:     "/api/v1/resources/{}",
			expected: "",
		},
		{
			name:     "placeholder with underscore",
			path:     "/api/v1/resources/{video_id}",
			expected: "video_id",
		},
		{
			name:     "placeholder with hyphen",
			path:     "/api/v1/resources/{user-id}",
			expected: "user-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasUnresolvedPlaceholders(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}
