package runner

import (
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// =============================================================================
// TEMPLATE MATCHING
// =============================================================================

// templateMatchesAnyFilter checks if template matches any of the filters
func templateMatchesAnyFilter(tmpl *templates.CompiledTemplate, filters []string) bool {
	for _, filter := range filters {
		if templateMatchesFilter(tmpl, filter) {
			return true
		}
	}
	return false
}

// templateMatchesFilter checks if template matches a single filter
// Matches by: template ID (exact, case-insensitive), filename with/without extension, path suffix
func templateMatchesFilter(tmpl *templates.CompiledTemplate, filter string) bool {
	// 1. Match by template ID (case-insensitive)
	if strings.EqualFold(tmpl.ID, filter) {
		return true
	}

	// 2. Match by filename (with or without .yaml/.yml extension)
	filename := filepath.Base(tmpl.FilePath)
	filenameNoExt := strings.TrimSuffix(strings.TrimSuffix(filename, ".yaml"), ".yml")
	if strings.EqualFold(filename, filter) || strings.EqualFold(filenameNoExt, filter) {
		return true
	}

	// 3. Match by path suffix
	if strings.HasSuffix(tmpl.FilePath, filter) {
		return true
	}

	return false
}
