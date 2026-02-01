package matchers

import (
	"net/http"
	"net/url"
	"strings"
)

// ReflectionMatcher detects payload reflection or execution in responses
type ReflectionMatcher struct {
	payload        string
	expected       string
	checkEncodings bool
}

// NewReflectionMatcher creates a new reflection matcher
func NewReflectionMatcher(payload, expected string, checkEncodings bool) *ReflectionMatcher {
	return &ReflectionMatcher{
		payload:        payload,
		expected:       expected,
		checkEncodings: checkEncodings,
	}
}

// Match checks if the expected value appears in the response
func (m *ReflectionMatcher) Match(response *http.Response, body string) bool {
	// Check body
	if m.matchInContent(body) {
		return true
	}

	// Check headers
	headers := buildHeaders(response)
	return m.matchInContent(headers)
}

func (m *ReflectionMatcher) matchInContent(content string) bool {
	// Exact match
	if strings.Contains(content, m.expected) {
		return true
	}

	if !m.checkEncodings {
		return false
	}

	// URL encoded match
	urlEncoded := url.QueryEscape(m.expected)
	if strings.Contains(content, urlEncoded) {
		return true
	}

	// HTML encoded match
	htmlEncoded := htmlEncode(m.expected)
	if strings.Contains(content, htmlEncoded) {
		return true
	}

	return false
}

// htmlEncode encodes common HTML entities
func htmlEncode(s string) string {
	replacements := map[string]string{
		"<":  "&lt;",
		">":  "&gt;",
		"\"": "&quot;",
		"'":  "&#39;",
		"&":  "&amp;",
	}

	result := s
	for old, new := range replacements {
		result = strings.ReplaceAll(result, old, new)
	}
	return result
}
