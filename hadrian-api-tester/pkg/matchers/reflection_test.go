package matchers

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReflectionMatcher_Match_Exact(t *testing.T) {
	matcher := NewReflectionMatcher("{{7*7}}", "49", false)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "exact match in body",
			body:     "Result: 49",
			expected: true,
		},
		{
			name:     "no match",
			body:     "Result: {{7*7}}",
			expected: false,
		},
		{
			name:     "match in middle",
			body:     "The answer is 49 exactly",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.Match(resp, tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReflectionMatcher_Match_URLEncoded(t *testing.T) {
	matcher := NewReflectionMatcher("<script>", "alert", true)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "exact match",
			body:     "alert(1)",
			expected: true,
		},
		{
			name:     "URL encoded match",
			body:     "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
			expected: true,
		},
		{
			name:     "HTML encoded match",
			body:     "&lt;script&gt;alert(1)&lt;/script&gt;",
			expected: true,
		},
		{
			name:     "no match",
			body:     "safe content",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.Match(resp, tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReflectionMatcher_Match_Headers(t *testing.T) {
	matcher := NewReflectionMatcher("test", "reflected", false)

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
	}
	resp.Header.Set("X-Custom", "reflected-value")

	result := matcher.Match(resp, "no match in body")

	assert.True(t, result, "Should match in headers")
}
