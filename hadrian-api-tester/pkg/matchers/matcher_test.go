package matchers

import (
	"net/http"
	"testing"
)

// TestMatcherInterface verifies all matchers implement the interface
func TestMatcherInterface(t *testing.T) {
	var _ Matcher = (*WordMatcher)(nil)
	var _ Matcher = (*RegexMatcher)(nil)
	var _ Matcher = (*StatusMatcher)(nil)
}

// mockResponse creates a test HTTP response
func mockResponse(statusCode int, headers map[string]string, body string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
	}

	for key, value := range headers {
		resp.Header.Set(key, value)
	}

	return resp
}
