// pkg/runner/graphql_test.go
package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGraphQLConfig_Defaults(t *testing.T) {
	// Test that GraphQLConfig has sensible defaults
	config := GraphQLConfig{
		Target:          "https://api.example.com",
		Endpoint:        "/graphql",
		DepthLimit:      10,
		ComplexityLimit: 1000,
		BatchSize:       100,
	}

	assert.Equal(t, "/graphql", config.Endpoint)
	assert.Equal(t, 10, config.DepthLimit)
	assert.Equal(t, 1000, config.ComplexityLimit)
}

func TestNewTestGraphQLCmd(t *testing.T) {
	cmd := newTestGraphQLCmd()

	assert.Equal(t, "graphql", cmd.Use)
	assert.Contains(t, cmd.Short, "GraphQL")

	// Verify required flag
	targetFlag := cmd.Flags().Lookup("target")
	assert.NotNil(t, targetFlag)
}

func TestNewTestGraphQLCmd_FlagDefaults(t *testing.T) {
	cmd := newTestGraphQLCmd()

	// Verify default values for GraphQL-specific flags
	assert.Equal(t, "/graphql", cmd.Flags().Lookup("endpoint").DefValue)
	assert.Equal(t, "10", cmd.Flags().Lookup("depth-limit").DefValue)
	assert.Equal(t, "1000", cmd.Flags().Lookup("complexity-limit").DefValue)
	assert.Equal(t, "100", cmd.Flags().Lookup("batch-size").DefValue)

	// Verify common flag defaults
	assert.Equal(t, "5", cmd.Flags().Lookup("rate-limit").DefValue)
	assert.Equal(t, "30", cmd.Flags().Lookup("timeout").DefValue)
	assert.Equal(t, "false", cmd.Flags().Lookup("insecure").DefValue)
	assert.Equal(t, "terminal", cmd.Flags().Lookup("output").DefValue)
	assert.Equal(t, "false", cmd.Flags().Lookup("allow-internal").DefValue)
}

func TestNewTestGraphQLCmd_RequiredFlags(t *testing.T) {
	cmd := newTestGraphQLCmd()

	// Execute without required flags should fail
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag")
}

func TestNewTestGraphQLCmd_CommandStructure(t *testing.T) {
	cmd := newTestGraphQLCmd()

	// Verify command has proper structure
	assert.Equal(t, "graphql", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	// Verify target flag exists and is required
	targetFlag := cmd.Flags().Lookup("target")
	assert.NotNil(t, targetFlag, "target flag should exist")

	// Verify endpoint flag exists
	endpointFlag := cmd.Flags().Lookup("endpoint")
	assert.NotNil(t, endpointFlag, "endpoint flag should exist")
	assert.Contains(t, endpointFlag.Usage, "GraphQL endpoint path")
}

func TestNewTestGraphQLCmd_HasAuthFlags(t *testing.T) {
	cmd := newTestGraphQLCmd()

	// Verify roles flag exists
	rolesFlag := cmd.Flags().Lookup("roles")
	assert.NotNil(t, rolesFlag, "roles flag should exist")
	assert.Contains(t, rolesFlag.Usage, "Roles")

	// Verify auth flag exists
	authFlag := cmd.Flags().Lookup("auth")
	assert.NotNil(t, authFlag, "auth flag should exist")
	assert.Contains(t, authFlag.Usage, "Authentication")
}

func TestNewTestGraphQLCmd_HasTemplatesFlag(t *testing.T) {
	cmd := newTestGraphQLCmd()

	// Verify templates flag exists
	templatesFlag := cmd.Flags().Lookup("templates")
	assert.NotNil(t, templatesFlag, "templates flag should exist")
	assert.Contains(t, templatesFlag.Usage, "GraphQL templates directory")
}

func TestLoadGraphQLTemplates_Empty(t *testing.T) {
	// Test with empty directory path
	templates, err := loadGraphQLTemplates("")
	assert.Error(t, err)
	assert.Nil(t, templates)
	assert.Contains(t, err.Error(), "templates directory not specified")
}

func TestLoadGraphQLTemplates_NonexistentDirectory(t *testing.T) {
	// Test with nonexistent directory
	templates, err := loadGraphQLTemplates("/nonexistent/path")
	assert.Error(t, err)
	assert.Nil(t, templates)
}

func TestLoadGraphQLTemplates_ValidDirectory(t *testing.T) {
	// Test with actual templates directory
	templates, err := loadGraphQLTemplates("../../templates/graphql")
	assert.NoError(t, err)
	assert.NotNil(t, templates)
	assert.Greater(t, len(templates), 0, "should load at least one template")

	// Verify template structure
	for _, tmpl := range templates {
		assert.NotEmpty(t, tmpl.ID)
		assert.NotEmpty(t, tmpl.Info.Name)
		assert.NotEmpty(t, tmpl.Info.Category)
	}
}

func TestGraphQLConfig_OOBEnabled(t *testing.T) {
	config := GraphQLConfig{
		Target:     "http://localhost:5013",
		Endpoint:   "/graphql",
		EnableOOB:  true,
		OOBTimeout: 10,
	}
	assert.True(t, config.EnableOOB)
	assert.Equal(t, 10, config.OOBTimeout)
}
