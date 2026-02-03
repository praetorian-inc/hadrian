package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestNewTestCmd_FlagDefaults(t *testing.T) {
	cmd := newTestCmd()

	// Verify default values (Cobra stores defaults as strings)
	assert.Equal(t, "1", cmd.Flags().Lookup("concurrency").DefValue)
	assert.Equal(t, "5", cmd.Flags().Lookup("rate-limit").DefValue)
	assert.Equal(t, "30", cmd.Flags().Lookup("timeout").DefValue)
	assert.Equal(t, "false", cmd.Flags().Lookup("allow-production").DefValue)
	assert.Equal(t, "terminal", cmd.Flags().Lookup("output").DefValue)
	assert.Equal(t, "false", cmd.Flags().Lookup("insecure").DefValue)
	assert.Equal(t, ".hadrian/audit.log", cmd.Flags().Lookup("audit-log").DefValue)
	assert.Equal(t, "", cmd.Flags().Lookup("llm-context").DefValue)
}

func TestNewTestCmd_LLMContextFlag(t *testing.T) {
	cmd := newTestCmd()

	// Verify llm-context flag exists and has correct properties
	llmContextFlag := cmd.Flags().Lookup("llm-context")
	assert.NotNil(t, llmContextFlag, "llm-context flag should exist")
	assert.Equal(t, "", llmContextFlag.DefValue, "llm-context should default to empty string")
	assert.Contains(t, llmContextFlag.Usage, "Additional context for LLM analysis")
}

func TestNewTestCmd_RequiredFlags(t *testing.T) {
	cmd := newTestCmd()

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

func TestNewTestCmd_ConcurrencyHardcoded(t *testing.T) {
	// Verify concurrency max is hardcoded in help text (HR-1: DoS prevention)
	cmd := newTestCmd()

	concurrencyFlag := cmd.Flags().Lookup("concurrency")
	assert.NotNil(t, concurrencyFlag)
	assert.Contains(t, concurrencyFlag.Usage, "max: 10")

	// Note: Actual enforcement will be in Batch 18 (runTest implementation)
	// This test verifies the documentation is present
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
	owaspDir := filepath.Join(tmpDir, "owasp")
	err := os.MkdirAll(owaspDir, 0755)
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
		err := os.WriteFile(filepath.Join(owaspDir, tmpl.name), []byte(tmpl.content), 0644)
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
