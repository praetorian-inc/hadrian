package matchers

import (
	"testing"
)

func TestWordMatcher_SingleWord_OR(t *testing.T) {
	matcher := NewWordMatcher([]string{"error"}, "body", "or")

	// Should match when word is present
	resp := mockResponse(200, nil, "an error occurred")
	if !matcher.Match(resp, "an error occurred") {
		t.Error("Expected match when word is present")
	}

	// Should not match when word is absent
	resp = mockResponse(200, nil, "success")
	if matcher.Match(resp, "success") {
		t.Error("Expected no match when word is absent")
	}
}

func TestWordMatcher_MultipleWords_AND(t *testing.T) {
	matcher := NewWordMatcher([]string{"success", "complete"}, "body", "and")

	// Should match when both words present
	resp := mockResponse(200, nil, "operation success and complete")
	if !matcher.Match(resp, "operation success and complete") {
		t.Error("Expected match when both words present")
	}

	// Should not match when only one word present
	resp = mockResponse(200, nil, "operation success")
	if matcher.Match(resp, "operation success") {
		t.Error("Expected no match when only one word present")
	}
}

func TestWordMatcher_MultipleWords_OR(t *testing.T) {
	matcher := NewWordMatcher([]string{"error", "failure"}, "body", "or")

	// Should match when first word present
	resp := mockResponse(200, nil, "error occurred")
	if !matcher.Match(resp, "error occurred") {
		t.Error("Expected match for first word")
	}

	// Should match when second word present
	resp = mockResponse(200, nil, "failure detected")
	if !matcher.Match(resp, "failure detected") {
		t.Error("Expected match for second word")
	}

	// Should not match when neither word present
	resp = mockResponse(200, nil, "success")
	if matcher.Match(resp, "success") {
		t.Error("Expected no match when neither word present")
	}
}

func TestWordMatcher_PartBody(t *testing.T) {
	matcher := NewWordMatcher([]string{"password"}, "body", "or")

	// Should match in body
	resp := mockResponse(200, map[string]string{"Content-Type": "text/html"}, "enter your password")
	if !matcher.Match(resp, "enter your password") {
		t.Error("Expected match in body")
	}

	// Should not match in header only
	resp = mockResponse(200, map[string]string{"X-Password": "value"}, "safe content")
	if matcher.Match(resp, "safe content") {
		t.Error("Expected no match when word only in header")
	}
}

func TestWordMatcher_PartHeader(t *testing.T) {
	matcher := NewWordMatcher([]string{"Bearer"}, "header", "or")

	// Should match in header
	resp := mockResponse(200, map[string]string{"Authorization": "Bearer token123"}, "body content")
	if !matcher.Match(resp, "body content") {
		t.Error("Expected match in header")
	}

	// Should not match in body only
	resp = mockResponse(200, map[string]string{"Content-Type": "text/html"}, "Bearer token in body")
	if matcher.Match(resp, "Bearer token in body") {
		t.Error("Expected no match when word only in body")
	}
}

func TestWordMatcher_PartAll(t *testing.T) {
	matcher := NewWordMatcher([]string{"Secret"}, "all", "or")

	// Should match in body
	resp := mockResponse(200, nil, "Secret data")
	if !matcher.Match(resp, "Secret data") {
		t.Error("Expected match in body")
	}

	// Should match in header
	resp = mockResponse(200, map[string]string{"X-Secret": "value"}, "normal content")
	if !matcher.Match(resp, "normal content") {
		t.Error("Expected match in header")
	}
}

func TestWordMatcher_ShortCircuitOR(t *testing.T) {
	matcher := NewWordMatcher([]string{"first", "second", "third"}, "body", "or")

	// Should return true on first match (implementation detail verification)
	resp := mockResponse(200, nil, "first word found")
	if !matcher.Match(resp, "first word found") {
		t.Error("Expected match on first word")
	}
}

func TestWordMatcher_ShortCircuitAND(t *testing.T) {
	matcher := NewWordMatcher([]string{"required", "missing", "other"}, "body", "and")

	// Should return false on first non-match (implementation detail verification)
	resp := mockResponse(200, nil, "required is here")
	if matcher.Match(resp, "required is here") {
		t.Error("Expected no match when second word missing")
	}
}
