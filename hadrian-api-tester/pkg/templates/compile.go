package templates

import (
	"fmt"
	"regexp"
)

// CompiledTemplate has pre-compiled regex patterns for performance
type CompiledTemplate struct {
	*Template
	CompiledMatchers []*CompiledMatcher
	FilePath         string // Path to the template file (for --template filtering)
}

// CompiledMatcher holds pre-compiled regex patterns
type CompiledMatcher struct {
	Type          string
	Words         []string
	CompiledRegex []*regexp.Regexp // Pre-compiled for 100x perf
	Status        []int
	Part          string
	Condition     string
}

// Compile pre-compiles regex patterns and validates template
func Compile(tmpl *Template) (*CompiledTemplate, error) {
	compiled := &CompiledTemplate{
		Template:         tmpl,
		CompiledMatchers: make([]*CompiledMatcher, 0, len(tmpl.HTTP)),
	}

	// Compile all matchers
	for i, test := range tmpl.HTTP {
		for j, matcher := range test.Matchers {
			cm := &CompiledMatcher{
				Type:      matcher.Type,
				Words:     matcher.Words,
				Status:    matcher.Status,
				Part:      matcher.Part,
				Condition: matcher.Condition,
			}

			// Pre-compile regex patterns (100x performance gain)
			if matcher.Type == "regex" {
				cm.CompiledRegex = make([]*regexp.Regexp, 0, len(matcher.Regex))
				for _, pattern := range matcher.Regex {
					re, err := regexp.Compile(pattern)
					if err != nil {
						return nil, fmt.Errorf("HTTP[%d].matchers[%d]: invalid regex %q: %w", i, j, pattern, err)
					}
					cm.CompiledRegex = append(cm.CompiledRegex, re)
				}
			}

			compiled.CompiledMatchers = append(compiled.CompiledMatchers, cm)
		}
	}

	return compiled, nil
}
