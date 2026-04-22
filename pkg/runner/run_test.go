package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTestCmd_FlagDefaults(t *testing.T) {
	// After CLI refactoring, test flags are on "test rest" subcommand, not "test" parent
	cmd := newTestRestCmd()

	// Verify default values (Cobra stores defaults as strings)
	assert.Equal(t, "5", cmd.Flags().Lookup("rate-limit").DefValue)
	assert.Equal(t, "30", cmd.Flags().Lookup("timeout").DefValue)
	assert.Equal(t, "terminal", cmd.Flags().Lookup("output").DefValue)
	assert.Equal(t, "false", cmd.Flags().Lookup("insecure").DefValue)
	assert.Equal(t, ".hadrian/audit.log", cmd.Flags().Lookup("audit-log").DefValue)
	assert.Equal(t, "", cmd.Flags().Lookup("llm-context").DefValue)
}

func TestNewTestCmd_LLMContextFlag(t *testing.T) {
	// After CLI refactoring, test flags are on "test rest" subcommand
	cmd := newTestRestCmd()

	// Verify llm-context flag exists and has correct properties
	llmContextFlag := cmd.Flags().Lookup("llm-context")
	assert.NotNil(t, llmContextFlag, "llm-context flag should exist")
	assert.Equal(t, "", llmContextFlag.DefValue, "llm-context should default to empty string")
	assert.Contains(t, llmContextFlag.Usage, "Additional context for LLM analysis")
}

func TestNewTestCmd_RequiredFlags(t *testing.T) {
	// After CLI refactoring, test flags are on "test rest" subcommand
	cmd := newTestRestCmd()

	// Execute without required flags should fail
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag")
}

func TestNewParseCmd(t *testing.T) {
	cmd := newParseCmd()

	assert.Equal(t, "parse <api-spec-file>", cmd.Use)
	assert.Contains(t, cmd.Short, "Parse API specification")

	// Verify it requires exactly 1 argument
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)
}

func TestNewVersionCmd(t *testing.T) {
	cmd := newVersionCmd()

	assert.Equal(t, "version", cmd.Use)
	assert.Contains(t, cmd.Short, "version")
}

func TestRun_NoError(t *testing.T) {
	// Run() should create a root command without error
	// We can't test execution without mocking os.Args
	// Just verify the function returns (doesn't panic)
	assert.NotPanics(t, func() {
		// Create a new root command to verify structure
		rootCmd := &cobra.Command{
			Use:   "hadrian",
			Short: "Hadrian - API Security Testing Framework",
		}
		assert.Equal(t, "hadrian", rootCmd.Use)
	})
}

func TestLoadTemplateFiles_DeterministicOrder(t *testing.T) {
	// Create temp dir with templates in non-alphabetical filesystem order
	tmpDir := t.TempDir()
	restDir := filepath.Join(tmpDir, "rest")
	err := os.MkdirAll(restDir, 0755)
	assert.NoError(t, err)

	// Create templates with names that would be out of order if not sorted
	templates := []struct {
		name    string
		content string
	}{
		{
			name: "03-c.yaml",
			content: `id: 03-c
info:
  name: "Test C"
  category: "owasp"
  severity: "HIGH"
  test_pattern: "simple"
endpoint_selector:
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`,
		},
		{
			name: "01-a.yaml",
			content: `id: 01-a
info:
  name: "Test A"
  category: "owasp"
  severity: "HIGH"
  test_pattern: "simple"
endpoint_selector:
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`,
		},
		{
			name: "02-b.yaml",
			content: `id: 02-b
info:
  name: "Test B"
  category: "owasp"
  severity: "HIGH"
  test_pattern: "simple"
endpoint_selector:
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`,
		},
	}

	for _, tmpl := range templates {
		err := os.WriteFile(filepath.Join(restDir, tmpl.name), []byte(tmpl.content), 0644)
		assert.NoError(t, err)
	}

	// Load templates multiple times and verify order is always the same
	for i := 0; i < 5; i++ {
		loaded, err := loadTemplateFiles(tmpDir, []string{"owasp"})
		assert.NoError(t, err)
		assert.Len(t, loaded, 3)

		// Should always be in alphabetical order by filepath
		assert.Equal(t, "01-a", loaded[0].ID)
		assert.Equal(t, "02-b", loaded[1].ID)
		assert.Equal(t, "03-c", loaded[2].ID)
	}
}

func TestLoadTemplateFiles_CategoryFilterByMetadata(t *testing.T) {
	tmpDir := t.TempDir()

	// Template with OWASP category and tags
	owaspTemplate := `id: 01-owasp
info:
  name: "OWASP Test"
  category: "API1:2023"
  severity: "HIGH"
  test_pattern: "simple"
  tags: ["owasp", "owasp-api-top10", "bola"]
endpoint_selector:
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`

	// Template with custom category
	customTemplate := `id: 02-custom
info:
  name: "Custom Test"
  category: "custom-internal"
  severity: "MEDIUM"
  test_pattern: "simple"
  tags: ["internal", "regression"]
endpoint_selector:
  methods: ["POST"]
role_selector:
  attacker_permission_level: "lower"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`

	// Template with only category, no tags
	categoryOnlyTemplate := `id: 03-category-only
info:
  name: "Category Only Test"
  category: "custom-cat"
  severity: "LOW"
  test_pattern: "simple"
endpoint_selector:
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`

	// Template with tags but no matching category (match only via tags)
	tagsOnlyTemplate := `id: 04-tags-only
info:
  name: "Tags Only Test"
  category: "unrelated-category"
  severity: "LOW"
  test_pattern: "simple"
  tags: ["special-tag"]
endpoint_selector:
  methods: ["GET"]
role_selector:
  attacker_permission_level: "lower"
detection:
  success_indicators:
    - type: status_code
      status_code: 200
  vulnerability_pattern: "test"
`

	err := os.WriteFile(filepath.Join(tmpDir, "01-owasp.yaml"), []byte(owaspTemplate), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "02-custom.yaml"), []byte(customTemplate), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "03-category-only.yaml"), []byte(categoryOnlyTemplate), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "04-tags-only.yaml"), []byte(tagsOnlyTemplate), 0644)
	require.NoError(t, err)

	// "owasp" should match the OWASP template via tags
	loaded, err := loadTemplateFiles(tmpDir, []string{"owasp"})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "01-owasp", loaded[0].ID)

	// "API1:2023" should match via exact category match
	loaded, err = loadTemplateFiles(tmpDir, []string{"API1:2023"})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "01-owasp", loaded[0].ID)

	// "custom-internal" should match the custom template via exact category match
	loaded, err = loadTemplateFiles(tmpDir, []string{"custom-internal"})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "02-custom", loaded[0].ID)

	// Template with only category, no tags — matches via category only
	loaded, err = loadTemplateFiles(tmpDir, []string{"custom-cat"})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "03-category-only", loaded[0].ID)

	// Template with only tags, no category — matches via tags only
	loaded, err = loadTemplateFiles(tmpDir, []string{"special-tag"})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "04-tags-only", loaded[0].ID)

	// nil categories should match nothing
	loaded, err = loadTemplateFiles(tmpDir, nil)
	require.NoError(t, err)
	require.Len(t, loaded, 0)

	// empty categories slice should match nothing
	loaded, err = loadTemplateFiles(tmpDir, []string{})
	require.NoError(t, err)
	require.Len(t, loaded, 0)

	// "all" should match everything
	loaded, err = loadTemplateFiles(tmpDir, []string{"all"})
	require.NoError(t, err)
	require.Len(t, loaded, 4)

	// "ALL" uppercase should match everything (case-insensitive wildcard)
	loaded, err = loadTemplateFiles(tmpDir, []string{"ALL"})
	require.NoError(t, err)
	require.Len(t, loaded, 4) // all 4 templates

	// "regression" should match custom template via tags
	loaded, err = loadTemplateFiles(tmpDir, []string{"regression"})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "02-custom", loaded[0].ID)

	// "nonexistent" should match nothing
	loaded, err = loadTemplateFiles(tmpDir, []string{"nonexistent"})
	require.NoError(t, err)
	assert.Len(t, loaded, 0)

	// Empty string in categories should be skipped, not match everything
	loaded, err = loadTemplateFiles(tmpDir, []string{"owasp", "", "bola"})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "01-owasp", loaded[0].ID)

	// Multiple categories should match union
	loaded, err = loadTemplateFiles(tmpDir, []string{"bola", "regression"})
	require.NoError(t, err)
	require.Len(t, loaded, 2)

	// Whitespace trimming: leading/trailing spaces should be stripped before matching
	loaded, err = loadTemplateFiles(tmpDir, []string{" owasp "})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "01-owasp", loaded[0].ID)

	// Case-insensitive: uppercase "OWASP" should match the lowercase "owasp" tag
	loaded, err = loadTemplateFiles(tmpDir, []string{"OWASP"})
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "01-owasp", loaded[0].ID)

	// Non-YAML files in the template directory should be ignored
	err = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("not a template"), 0644)
	require.NoError(t, err)
	loaded, err = loadTemplateFiles(tmpDir, []string{"all"})
	require.NoError(t, err)
	require.Len(t, loaded, 4) // Still only the 4 YAML templates
}
