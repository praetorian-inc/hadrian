package templates

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	MaxYAMLDepth = 20          // Prevent YAML bombs
	MaxYAMLSize  = 1024 * 1024 // 1MB limit
)

// Parse loads and parses a YAML template file (CR-2: YAML Security)
func Parse(filePath string) (*Template, error) {
	// Check file size (CR-2: DoS prevention)
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat template file: %w", err)
	}

	if info.Size() > MaxYAMLSize {
		return nil, fmt.Errorf("template file too large: %d bytes (max: %d)", info.Size(), MaxYAMLSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %w", err)
	}

	return ParseYAML(data)
}

// ParseYAML parses YAML bytes with security controls (CR-2)
func ParseYAML(data []byte) (*Template, error) {
	// Use safe YAML decoder
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true) // Reject unknown fields (typo detection)

	var template Template
	if err := decoder.Decode(&template); err != nil {
		// Preserve line number information for errors
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}

	// Validate DSL expressions (CR-2: Injection prevention)
	if err := validateTemplate(&template); err != nil {
		return nil, err
	}

	return &template, nil
}

// validateTemplate checks for security issues (CR-2)
func validateTemplate(tmpl *Template) error {
	// Validate required fields
	if tmpl.ID == "" {
		return fmt.Errorf("template missing required field: id")
	}
	if tmpl.Info.Name == "" {
		return fmt.Errorf("template missing required field: info.name")
	}
	if tmpl.Info.Category == "" {
		return fmt.Errorf("template missing required field: info.category")
	}

	// Reject DSL matchers - feature is incomplete and poses injection risk (CR-2)
	for i, test := range tmpl.HTTP {
		for j, matcher := range test.Matchers {
			if matcher.Type == "dsl" {
				return fmt.Errorf("DSL matchers are not supported (template %s, test %d, matcher %d)", tmpl.ID, i+1, j+1)
			}
		}
	}

	return nil
}

// containsDangerousFunction detects code execution attempts (CR-2)
func containsDangerousFunction(expr string) bool {
	dangerousFuncs := []string{
		"system", "exec", "eval", "os.", "cmd.", "shell",
		"import", "require", "load", "__import__",
	}

	exprLower := strings.ToLower(expr)
	for _, fn := range dangerousFuncs {
		if strings.Contains(exprLower, fn) {
			return true
		}
	}

	return false
}
