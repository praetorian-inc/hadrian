package matchers

import (
	"testing"
)

func TestStatusMatcher_Match(t *testing.T) {
	matcher := NewStatusMatcher([]int{200, 201, 204})

	// Should match 200
	resp := mockResponse(200, nil, "")
	if !matcher.Match(resp, "") {
		t.Error("Expected match for status 200")
	}

	// Should match 201
	resp = mockResponse(201, nil, "")
	if !matcher.Match(resp, "") {
		t.Error("Expected match for status 201")
	}

	// Should match 204
	resp = mockResponse(204, nil, "")
	if !matcher.Match(resp, "") {
		t.Error("Expected match for status 204")
	}
}

func TestStatusMatcher_NoMatch(t *testing.T) {
	matcher := NewStatusMatcher([]int{200, 201})

	// Should not match 404
	resp := mockResponse(404, nil, "")
	if matcher.Match(resp, "") {
		t.Error("Expected no match for status 404")
	}

	// Should not match 500
	resp = mockResponse(500, nil, "")
	if matcher.Match(resp, "") {
		t.Error("Expected no match for status 500")
	}
}

func TestStatusMatcher_MultipleStatuses(t *testing.T) {
	matcher := NewStatusMatcher([]int{400, 401, 403, 404, 500})

	// Should match any error status
	errorStatuses := []int{400, 401, 403, 404, 500}
	for _, status := range errorStatuses {
		resp := mockResponse(status, nil, "")
		if !matcher.Match(resp, "") {
			t.Errorf("Expected match for status %d", status)
		}
	}

	// Should not match success status
	resp := mockResponse(200, nil, "")
	if matcher.Match(resp, "") {
		t.Error("Expected no match for status 200")
	}
}
