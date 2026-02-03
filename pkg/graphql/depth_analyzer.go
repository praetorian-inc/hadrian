package graphql

import (
	"strings"
)

// DepthAnalyzer analyzes GraphQL query depth and complexity
type DepthAnalyzer struct {
	maxDepth      int
	maxComplexity int
}

// NewDepthAnalyzer creates a new depth analyzer
func NewDepthAnalyzer(maxDepth, maxComplexity int) *DepthAnalyzer {
	return &DepthAnalyzer{
		maxDepth:      maxDepth,
		maxComplexity: maxComplexity,
	}
}

// AnalysisResult contains query analysis results
type AnalysisResult struct {
	Depth      int
	Complexity int
	TooDeep    bool
	TooComplex bool
}

// AnalyzeQuery analyzes a query string for depth and complexity
func (a *DepthAnalyzer) AnalyzeQuery(query string) *AnalysisResult {
	depth := calculateDepth(query)
	complexity := calculateComplexity(query)

	return &AnalysisResult{
		Depth:      depth,
		Complexity: complexity,
		TooDeep:    a.maxDepth > 0 && depth > a.maxDepth,
		TooComplex: a.maxComplexity > 0 && complexity > a.maxComplexity,
	}
}

// CalculateDepth returns the maximum nesting depth of a query
func CalculateDepth(query string) int {
	return calculateDepth(query)
}

func calculateDepth(query string) int {
	maxDepth := 0
	currentDepth := 0

	for _, char := range query {
		if char == '{' {
			currentDepth++
			if currentDepth > maxDepth {
				maxDepth = currentDepth
			}
		} else if char == '}' {
			currentDepth--
		}
	}

	return maxDepth
}

// CalculateComplexity returns an approximate complexity score
// Based on number of fields and depth
func CalculateComplexity(query string) int {
	return calculateComplexity(query)
}

func calculateComplexity(query string) int {
	// Count field selections (approximation)
	// Fields are identified as words followed by { or end of selection
	fieldCount := 0
	depth := 0

	// Simple heuristic: count words that appear before { or end
	words := strings.Fields(query)
	for i, word := range words {
		// Skip query/mutation keywords
		if word == "query" || word == "mutation" || word == "{" || word == "}" {
			continue
		}
		// Count depth-weighted fields
		if strings.HasSuffix(word, "{") {
			depth++
			fieldCount += depth // Fields at deeper levels cost more
		} else if word == "}" {
			depth--
		} else if !strings.HasPrefix(word, "$") && !strings.Contains(word, ":") {
			// This looks like a field name
			if i+1 < len(words) && (words[i+1] == "{" || words[i+1][0] == '}') {
				fieldCount += max(1, depth)
			} else {
				fieldCount++ // Scalar field
			}
		}
	}

	return fieldCount
}

// IsDoSCandidate returns true if the query could be a DoS attack
func (a *DepthAnalyzer) IsDoSCandidate(query string) bool {
	result := a.AnalyzeQuery(query)
	return result.TooDeep || result.TooComplex
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
