package runner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGraphQLConfigValidate pins the GraphQL output-format / SARIF-pairing
// validation, keeping the three protocols' SARIF behavior symmetric (REST and
// gRPC have equivalent tests). Without this, the GraphQL command was the only
// protocol with no test exercising its sarif output path.
func TestGraphQLConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    GraphQLConfig
		wantError bool
		errorMsg  string
	}{
		{name: "default terminal", config: GraphQLConfig{Output: "terminal"}, wantError: false},
		{name: "empty output tolerated", config: GraphQLConfig{Output: ""}, wantError: false},
		{name: "json", config: GraphQLConfig{Output: "json"}, wantError: false},
		{name: "invalid format", config: GraphQLConfig{Output: "xml"}, wantError: true, errorMsg: "invalid output format"},
		{name: "sarif without output-file", config: GraphQLConfig{Output: "sarif"}, wantError: true, errorMsg: "--output sarif requires --output-file"},
		{name: "sarif with output-file", config: GraphQLConfig{Output: "sarif", OutputFile: "report.sarif"}, wantError: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
