package matchers

import (
	"net/http"
	"strings"
)

type WordMatcher struct {
	words     []string
	part      string
	condition string // and, or
}

func NewWordMatcher(words []string, part, condition string) *WordMatcher {
	return &WordMatcher{
		words:     words,
		part:      part,
		condition: condition,
	}
}

func (m *WordMatcher) Match(response *http.Response, body string) bool {
	content := m.getContent(response, body)

	matched := 0
	for _, word := range m.words {
		if strings.Contains(content, word) {
			matched++

			if m.condition == "or" {
				return true // Short-circuit on first match
			}
		} else if m.condition == "and" {
			return false // Short-circuit on first non-match
		}
	}

	// AND: all must match, OR: at least one must match
	if m.condition == "and" {
		return matched == len(m.words)
	}
	return matched > 0
}

func (m *WordMatcher) getContent(response *http.Response, body string) string {
	switch m.part {
	case "body":
		return body
	case "header":
		return buildHeaders(response)
	default: // "all"
		return body + "\n" + buildHeaders(response)
	}
}
