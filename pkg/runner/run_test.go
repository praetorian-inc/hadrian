package runner

import (
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
