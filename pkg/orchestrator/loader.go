// Package owasp provides OWASP test orchestration for API security testing.
// It loads templates by category, matches them to API operations, and coordinates
// test execution across role combinations.
package orchestrator

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/templates"
)

// =============================================================================
// PUBLIC API
// =============================================================================

// LoadTemplates loads and compiles all YAML templates matching the given glob pattern.
// Returns compiled templates ready for execution.
func LoadTemplates(pattern string) ([]*templates.CompiledTemplate, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid glob pattern: %w", err)
	}

	// Sort files alphabetically for deterministic execution order
	sort.Strings(files)

	result := make([]*templates.CompiledTemplate, 0, len(files))
	for _, file := range files {
		tmpl, err := templates.Parse(file)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", file, err)
		}

		compiled, err := templates.Compile(tmpl)
		if err != nil {
			return nil, fmt.Errorf("failed to compile template %s: %w", file, err)
		}

		result = append(result, compiled)
	}

	return result, nil
}

// LoadTemplatesByCategory loads templates for a specific OWASP category (e.g., "API1", "API2").
// Maps OWASP categories to file patterns and loads matching templates.
func LoadTemplatesByCategory(templateDir, category string) ([]*templates.CompiledTemplate, error) {
	pattern := filepath.Join(templateDir, categoryToPattern(category))

	allTemplates, err := LoadTemplates(pattern)
	if err != nil {
		return nil, err
	}

	// Filter templates by category in case file naming doesn't perfectly match
	filtered := make([]*templates.CompiledTemplate, 0, len(allTemplates))
	for _, tmpl := range allTemplates {
		if matchesCategory(tmpl.Info.Category, category) {
			filtered = append(filtered, tmpl)
		}
	}

	return filtered, nil
}

// =============================================================================
// HELPERS
// =============================================================================

// categoryToPattern converts OWASP category (e.g., "API1") to glob pattern.
// Supports both plain names (api1-bola.yaml) and NN-prefixed names (01-api1-bola.yaml).
func categoryToPattern(category string) string {
	// Normalize to lowercase for file matching
	normalized := strings.ToLower(category)

	// Use wildcard prefix to match both "api1-*.yaml" and "01-api1-*.yaml"
	return "*" + normalized + "-*.yaml"
}

// matchesCategory checks if template category matches the requested category.
// Handles formats like "API1:2023", "API1", etc.
func matchesCategory(templateCategory, requestedCategory string) bool {
	// Normalize both to uppercase for comparison
	tmplCat := strings.ToUpper(templateCategory)
	reqCat := strings.ToUpper(requestedCategory)

	// Check if template category starts with or contains requested category
	// This handles "API1:2023" matching "API1"
	return strings.HasPrefix(tmplCat, reqCat) || strings.Contains(tmplCat, reqCat)
}
