// pkg/runner/grpc_test.go
package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewTestGRPCCmd tests the gRPC command creation
func TestNewTestGRPCCmd(t *testing.T) {
	cmd := newTestGRPCCmd()

	assert.Equal(t, "grpc", cmd.Use)
	assert.Contains(t, cmd.Short, "gRPC")

	// Verify required flags exist
	targetFlag := cmd.Flags().Lookup("target")
	assert.NotNil(t, targetFlag, "target flag should exist")

	protoFlag := cmd.Flags().Lookup("proto")
	assert.NotNil(t, protoFlag, "proto flag should exist")

	reflectionFlag := cmd.Flags().Lookup("reflection")
	assert.NotNil(t, reflectionFlag, "reflection flag should exist")

	rolesFlag := cmd.Flags().Lookup("roles")
	assert.NotNil(t, rolesFlag, "roles flag should exist")

	authFlag := cmd.Flags().Lookup("auth")
	assert.NotNil(t, authFlag, "auth flag should exist")
}

// TestGRPCConfig_Defaults tests default flag values
func TestGRPCConfig_Defaults(t *testing.T) {
	cmd := newTestGRPCCmd()

	rateLimit, err := cmd.Flags().GetFloat64("rate-limit")
	assert.NoError(t, err)
	assert.Equal(t, 5.0, rateLimit)

	timeout, err := cmd.Flags().GetInt("timeout")
	assert.NoError(t, err)
	assert.Equal(t, 30, timeout)

	output, err := cmd.Flags().GetString("output")
	assert.NoError(t, err)
	assert.Equal(t, "terminal", output)

	plaintext, err := cmd.Flags().GetBool("plaintext")
	assert.NoError(t, err)
	assert.False(t, plaintext, "plaintext should default to false")

	reflection, err := cmd.Flags().GetBool("reflection")
	assert.NoError(t, err)
	assert.False(t, reflection, "reflection should default to false")
}

// TestGRPCConfig_AllFlags tests that all expected flags are present
func TestGRPCConfig_AllFlags(t *testing.T) {
	cmd := newTestGRPCCmd()

	expectedFlags := []string{
		"target",
		"proto",
		"reflection",
		"roles",
		"auth",
		"templates",
		"plaintext",
		"tls-ca-cert",
		"rate-limit",
		"timeout",
		"output",
		"verbose",
		"dry-run",
		"proxy",
		"insecure",
		"allow-internal",
		"allow-production",
	}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "flag %s should exist", flagName)
	}
}
