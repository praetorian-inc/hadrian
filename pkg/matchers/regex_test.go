package matchers

import (
	"regexp"
	"testing"
)

func TestRegexMatcher_SinglePattern_Match(t *testing.T) {
	pattern := regexp.MustCompile(`error\s+\d+`)
	matcher := NewRegexMatcher([]*regexp.Regexp{pattern}, "body", "or")

	// Should match when pattern matches
	resp := mockResponse(200, nil, "error 404 occurred")
	if !matcher.Match(resp, "error 404 occurred") {
		t.Error("Expected match for pattern")
	}
}

func TestRegexMatcher_SinglePattern_NoMatch(t *testing.T) {
	pattern := regexp.MustCompile(`error\s+\d+`)
	matcher := NewRegexMatcher([]*regexp.Regexp{pattern}, "body", "or")

	// Should not match when pattern doesn't match
	resp := mockResponse(200, nil, "success")
	if matcher.Match(resp, "success") {
		t.Error("Expected no match")
	}

	// Should not match when format wrong
	resp = mockResponse(200, nil, "error occurred")
	if matcher.Match(resp, "error occurred") {
		t.Error("Expected no match when format wrong")
	}
}

func TestRegexMatcher_MultiplePatterns_AND(t *testing.T) {
	pattern1 := regexp.MustCompile(`user\s+\d+`)
	pattern2 := regexp.MustCompile(`email.*@.*\.com`)
	matcher := NewRegexMatcher([]*regexp.Regexp{pattern1, pattern2}, "body", "and")

	// Should match when both patterns match
	resp := mockResponse(200, nil, "user 123 has email john@example.com")
	if !matcher.Match(resp, "user 123 has email john@example.com") {
		t.Error("Expected match when both patterns match")
	}

	// Should not match when only first matches
	resp = mockResponse(200, nil, "user 123 has no email")
	if matcher.Match(resp, "user 123 has no email") {
		t.Error("Expected no match when only first pattern matches")
	}
}

func TestRegexMatcher_MultiplePatterns_OR(t *testing.T) {
	pattern1 := regexp.MustCompile(`error\s+\d+`)
	pattern2 := regexp.MustCompile(`failed`)
	matcher := NewRegexMatcher([]*regexp.Regexp{pattern1, pattern2}, "body", "or")

	// Should match when first pattern matches
	resp := mockResponse(200, nil, "error 500 occurred")
	if !matcher.Match(resp, "error 500 occurred") {
		t.Error("Expected match for first pattern")
	}

	// Should match when second pattern matches
	resp = mockResponse(200, nil, "operation failed")
	if !matcher.Match(resp, "operation failed") {
		t.Error("Expected match for second pattern")
	}

	// Should not match when neither matches
	resp = mockResponse(200, nil, "success")
	if matcher.Match(resp, "success") {
		t.Error("Expected no match when neither pattern matches")
	}
}

func TestRegexMatcher_PartSelection(t *testing.T) {
	pattern := regexp.MustCompile(`Bearer\s+[A-Za-z0-9]+`)

	// Test body matching
	bodyMatcher := NewRegexMatcher([]*regexp.Regexp{pattern}, "body", "or")
	resp := mockResponse(200, nil, "Bearer abc123")
	if !bodyMatcher.Match(resp, "Bearer abc123") {
		t.Error("Expected match in body")
	}

	// Test header matching
	headerMatcher := NewRegexMatcher([]*regexp.Regexp{pattern}, "header", "or")
	resp = mockResponse(200, map[string]string{"Authorization": "Bearer xyz789"}, "normal content")
	if !headerMatcher.Match(resp, "normal content") {
		t.Error("Expected match in header")
	}

	// Test all matching (should match in either)
	allMatcher := NewRegexMatcher([]*regexp.Regexp{pattern}, "all", "or")
	resp = mockResponse(200, map[string]string{"Authorization": "Bearer token123"}, "no token")
	if !allMatcher.Match(resp, "no token") {
		t.Error("Expected match in all (header)")
	}

	resp = mockResponse(200, nil, "Bearer bodytoken")
	if !allMatcher.Match(resp, "Bearer bodytoken") {
		t.Error("Expected match in all (body)")
	}
}

func TestRegexMatcher_ShortCircuit(t *testing.T) {
	pattern1 := regexp.MustCompile(`first`)
	pattern2 := regexp.MustCompile(`second`)
	pattern3 := regexp.MustCompile(`third`)

	// Test OR short-circuit
	orMatcher := NewRegexMatcher([]*regexp.Regexp{pattern1, pattern2, pattern3}, "body", "or")
	resp := mockResponse(200, nil, "first match found")
	if !orMatcher.Match(resp, "first match found") {
		t.Error("Expected match on first pattern (OR)")
	}

	// Test AND short-circuit
	andMatcher := NewRegexMatcher([]*regexp.Regexp{pattern1, pattern2, pattern3}, "body", "and")
	resp = mockResponse(200, nil, "first is here")
	if andMatcher.Match(resp, "first is here") {
		t.Error("Expected no match when second pattern missing (AND)")
	}
}
