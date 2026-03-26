package matchers

import "net/http"

// Matcher evaluates if HTTP response matches criteria
type Matcher interface {
	Match(response *http.Response, body string) bool
}

// MatcherConfig from YAML (for reference, not used directly)
type MatcherConfig struct {
	Type      string
	Words     []string
	Regex     []string
	Status    []int
	Part      string // body, header, all
	Condition string // and, or
}
