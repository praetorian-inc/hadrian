package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTemplates(t *testing.T) {
	t.Run("loads all YAML files matching pattern", func(t *testing.T) {
		// Arrange
		pattern := "testdata/*.yaml"

		// Act
		templates, err := LoadTemplates(pattern)

		// Assert
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(templates), 2, "should load at least 2 templates")

		// Verify templates have expected fields
		for _, tmpl := range templates {
			assert.NotEmpty(t, tmpl.ID, "template ID should not be empty")
			assert.NotEmpty(t, tmpl.Info.Name, "template name should not be empty")
			assert.NotEmpty(t, tmpl.Info.Category, "template category should not be empty")
		}
	})

	t.Run("returns error for invalid pattern", func(t *testing.T) {
		// Arrange
		pattern := "/nonexistent/path/*.yaml"

		// Act
		templates, err := LoadTemplates(pattern)

		// Assert
		assert.NoError(t, err, "glob returns empty slice for no matches, not an error")
		assert.Empty(t, templates)
	})

	t.Run("returns error for invalid YAML", func(t *testing.T) {
		// Arrange - create temp file with invalid YAML
		tmpDir := t.TempDir()
		invalidFile := filepath.Join(tmpDir, "invalid.yaml")
		err := os.WriteFile(invalidFile, []byte("invalid: yaml: content: [unclosed"), 0644)
		require.NoError(t, err)

		// Act
		_, err = LoadTemplates(filepath.Join(tmpDir, "*.yaml"))

		// Assert
		assert.Error(t, err, "should return error for invalid YAML")
	})

	t.Run("compiles templates with valid regex", func(t *testing.T) {
		// Arrange
		pattern := "testdata/api1-bola-read.yaml"

		// Act
		templates, err := LoadTemplates(pattern)

		// Assert
		require.NoError(t, err)
		require.Len(t, templates, 1)
		// CompiledTemplate embeds Template, verify fields are accessible
		assert.Equal(t, "api1-bola-read", templates[0].ID)
	})
}

func TestLoadTemplatesByCategory(t *testing.T) {
	t.Run("loads API1 category templates", func(t *testing.T) {
		// Arrange
		templateDir := "testdata"
		category := "API1"

		// Act
		templates, err := LoadTemplatesByCategory(templateDir, category)

		// Assert
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(templates), 1)

		for _, tmpl := range templates {
			assert.Contains(t, tmpl.Info.Category, "API1", "category should contain API1")
		}
	})

	t.Run("loads API2 category templates", func(t *testing.T) {
		// Arrange
		templateDir := "testdata"
		category := "API2"

		// Act
		templates, err := LoadTemplatesByCategory(templateDir, category)

		// Assert
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(templates), 1)

		for _, tmpl := range templates {
			assert.Contains(t, tmpl.Info.Category, "API2")
		}
	})

	t.Run("returns empty slice for unknown category", func(t *testing.T) {
		// Arrange
		templateDir := "testdata"
		category := "API99"

		// Act
		templates, err := LoadTemplatesByCategory(templateDir, category)

		// Assert
		require.NoError(t, err)
		assert.Empty(t, templates)
	})

	t.Run("returns error for nonexistent directory", func(t *testing.T) {
		// Arrange
		templateDir := "/nonexistent/directory"
		category := "API1"

		// Act
		templates, err := LoadTemplatesByCategory(templateDir, category)

		// Assert
		assert.NoError(t, err, "should return empty, not error")
		assert.Empty(t, templates)
	})

	t.Run("maps OWASP categories to file patterns", func(t *testing.T) {
		// Test that category mapping works for common OWASP categories
		testCases := []struct {
			category       string
			expectedPrefix string
		}{
			{"API1", "api1"},
			{"API2", "api2"},
			{"API3", "api3"},
			{"API4", "api4"},
			{"API5", "api5"},
		}

		for _, tc := range testCases {
			t.Run(tc.category, func(t *testing.T) {
				pattern := categoryToPattern(tc.category)
				assert.Contains(t, pattern, tc.expectedPrefix)
			})
		}
	})
}
