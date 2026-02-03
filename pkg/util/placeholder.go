package util

import "strings"

// HasUnresolvedPlaceholders checks if a path contains unresolved {placeholder} patterns.
// Returns the first unresolved placeholder name if found, or empty string if all resolved.
func HasUnresolvedPlaceholders(path string) string {
	start := strings.Index(path, "{")
	if start == -1 {
		return ""
	}
	end := strings.Index(path[start:], "}")
	if end == -1 {
		return ""
	}
	return path[start+1 : start+end]
}
