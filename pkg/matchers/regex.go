package matchers

import (
	"net/http"
	"regexp"
)

type RegexMatcher struct {
	patterns  []*regexp.Regexp
	part      string
	condition string // and, or
}

func NewRegexMatcher(patterns []*regexp.Regexp, part, condition string) *RegexMatcher {
	return &RegexMatcher{
		patterns:  patterns,
		part:      part,
		condition: condition,
	}
}

func (m *RegexMatcher) Match(response *http.Response, body string) bool {
	content := m.getContent(response, body)

	matched := 0
	for _, pattern := range m.patterns {
		if pattern.MatchString(content) {
			matched++

			if m.condition == "or" {
				return true // Short-circuit
			}
		} else {
			if m.condition == "and" {
				return false // Short-circuit
			}
		}
	}

	if m.condition == "and" {
		return matched == len(m.patterns)
	}
	return matched > 0
}

func (m *RegexMatcher) getContent(response *http.Response, body string) string {
	switch m.part {
	case "body":
		return body
	case "header":
		return buildHeaders(response)
	default: // "all"
		return body + "\n" + buildHeaders(response)
	}
}
