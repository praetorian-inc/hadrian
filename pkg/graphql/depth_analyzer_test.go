package graphql

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDepthAnalyzer_CalculateDepth(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected int
	}{
		{
			name:     "simple query",
			query:    "{ user { id } }",
			expected: 2,
		},
		{
			name:     "nested query",
			query:    "{ user { posts { comments { author { id } } } } }",
			expected: 5,
		},
		{
			name:     "flat query",
			query:    "{ id name email }",
			expected: 1,
		},
		{
			name:     "deeply nested",
			query:    "{ a { b { c { d { e { f { g { h } } } } } } } }",
			expected: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			depth := CalculateDepth(tt.query)
			assert.Equal(t, tt.expected, depth)
		})
	}
}

func TestDepthAnalyzer_AnalyzeQuery(t *testing.T) {
	analyzer := NewDepthAnalyzer(5, 100)

	// Query within limits
	result := analyzer.AnalyzeQuery("{ user { id name } }")
	assert.Equal(t, 2, result.Depth)
	assert.False(t, result.TooDeep)
	assert.False(t, result.TooComplex)

	// Query exceeding depth
	deepQuery := "{ a { b { c { d { e { f { g } } } } } } }"
	result = analyzer.AnalyzeQuery(deepQuery)
	assert.True(t, result.TooDeep)
}

func TestDepthAnalyzer_IsDoSCandidate(t *testing.T) {
	analyzer := NewDepthAnalyzer(3, 50)

	// Normal query
	assert.False(t, analyzer.IsDoSCandidate("{ user { id } }"))

	// Deep query
	assert.True(t, analyzer.IsDoSCandidate("{ a { b { c { d { e } } } } }"))
}
