package matchers

import "net/http"

type StatusMatcher struct {
	statuses []int
}

func NewStatusMatcher(statuses []int) *StatusMatcher {
	return &StatusMatcher{
		statuses: statuses,
	}
}

func (m *StatusMatcher) Match(response *http.Response, body string) bool {
	for _, status := range m.statuses {
		if response.StatusCode == status {
			return true
		}
	}
	return false
}
