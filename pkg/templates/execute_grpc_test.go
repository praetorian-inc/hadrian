package templates

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewGRPCExecutor tests GRPCExecutor creation
func TestNewGRPCExecutor(t *testing.T) {
	config := GRPCExecutorConfig{
		Target:    "localhost:50051",
		Plaintext: true,
		Timeout:   0, // Should use default
	}

	executor, err := NewGRPCExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)
	assert.Equal(t, "localhost:50051", executor.target)
	assert.True(t, executor.plaintext)

	// Clean up
	err = executor.Close()
	assert.NoError(t, err)
}

// TestGRPCExecutor_Close tests that Close properly cleans up resources
func TestGRPCExecutor_Close(t *testing.T) {
	config := GRPCExecutorConfig{
		Target:    "localhost:50051",
		Plaintext: true,
	}

	executor, err := NewGRPCExecutor(config)
	require.NoError(t, err)

	err = executor.Close()
	// Close may return an error if the connection was already closing
	// which is acceptable behavior
	_ = err

	// Should be safe to call Close multiple times
	err = executor.Close()
	// Subsequent calls may also return errors, which is acceptable
	_ = err
}

// TestSubstituteVariables tests variable substitution
func TestSubstituteVariables(t *testing.T) {
	variables := map[string]string{
		"user_id": "123",
		"token":   "abc-token",
		"name":    "testuser",
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single variable",
			input:    "{{user_id}}",
			expected: "123",
		},
		{
			name:     "multiple variables",
			input:    `{"user_id": "{{user_id}}", "token": "{{token}}"}`,
			expected: `{"user_id": "123", "token": "abc-token"}`,
		},
		{
			name:     "no variables",
			input:    `{"static": "value"}`,
			expected: `{"static": "value"}`,
		},
		{
			name:     "undefined variable (no substitution)",
			input:    "{{undefined}}",
			expected: "{{undefined}}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := substituteVariables(tt.input, variables)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestGenerateRequestID tests request ID generation
func TestGenerateRequestID(t *testing.T) {
	id1 := util.GenerateRequestID()
	id2 := util.GenerateRequestID()

	// IDs should not be empty
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)

	// IDs should be unique
	assert.NotEqual(t, id1, id2)

	// IDs should be in UUID format (contains dashes)
	assert.Contains(t, id1, "-")
	assert.Contains(t, id2, "-")
}

// TestGRPCExecutor_EvaluateDetection tests detection section evaluation
func TestGRPCExecutor_EvaluateDetection(t *testing.T) {
	executor := &GRPCExecutor{}

	tests := []struct {
		name      string
		detection Detection
		result    *ExecutionResult
		expected  bool
	}{
		{
			name: "success indicator with grpc_status - match",
			detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type: "grpc_status",
						Code: 0,
					},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 0,
				},
			},
			expected: true,
		},
		{
			name: "success indicator with grpc_status array - match",
			detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type: "grpc_status",
						Code: []interface{}{0, 14},
					},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 14,
				},
			},
			expected: true,
		},
		{
			name: "success indicator with status_code - match",
			detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type:       "status_code",
						StatusCode: 200,
					},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 200,
				},
			},
			expected: true,
		},
		{
			name: "success indicator - no match",
			detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type: "grpc_status",
						Code: 0,
					},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 7,
				},
			},
			expected: false,
		},
		{
			name: "failure indicator blocks success",
			detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type: "grpc_status",
						Code: 0,
					},
				},
				FailureIndicators: []Indicator{
					{
						Type: "grpc_status",
						Code: 0,
					},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 0,
				},
			},
			expected: false,
		},
		{
			name: "body_field exists check - match",
			detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type:      "body_field",
						BodyField: "admin",
						Exists:    boolPtr(true),
					},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					Body: `{"admin": true}`,
				},
			},
			expected: true,
		},
		{
			name: "body_field with value - match",
			detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type:      "body_field",
						BodyField: "role",
						Value:     "admin",
					},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					Body: `{"role": "admin"}`,
				},
			},
			expected: true,
		},
		{
			name: "word patterns - match",
			detection: Detection{
				SuccessIndicators: []Indicator{
					{
						Type:     "word",
						Patterns: []string{"success", "completed"},
					},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					Body: `{"status": "success"}`,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := executor.evaluateDetection(&tt.detection, tt.result)
			assert.Equal(t, tt.expected, matched)
		})
	}
}

// Helper function for bool pointers
func boolPtr(b bool) *bool {
	return &b
}

// TestGRPCExecutor_EvaluateMatchers tests matcher evaluation
func TestGRPCExecutor_EvaluateMatchers(t *testing.T) {
	executor := &GRPCExecutor{}

	tests := []struct {
		name     string
		matchers []Matcher
		result   *ExecutionResult
		expected bool
	}{
		{
			name: "status code matcher - match",
			matchers: []Matcher{
				{
					Type: "status",
					Code: []int{0},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 0,
				},
			},
			expected: true,
		},
		{
			name: "status code matcher - no match",
			matchers: []Matcher{
				{
					Type: "status",
					Code: []int{0},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 7,
				},
			},
			expected: false,
		},
		{
			name: "grpc_status matcher - match",
			matchers: []Matcher{
				{
					Type: "grpc_status",
					Code: []int{0, 14},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 14,
				},
			},
			expected: true,
		},
		{
			name: "word matcher - match",
			matchers: []Matcher{
				{
					Type:  "word",
					Words: []string{"success", "completed"},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					Body: `{"status": "success"}`,
				},
			},
			expected: true,
		},
		{
			name: "word matcher - no match",
			matchers: []Matcher{
				{
					Type:  "word",
					Words: []string{"success"},
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					Body: `{"status": "failed"}`,
				},
			},
			expected: false,
		},
		{
			name: "AND condition - all must match",
			matchers: []Matcher{
				{
					Type:      "status",
					Code:      []int{0},
					Condition: "and",
				},
				{
					Type:      "word",
					Words:     []string{"success"},
					Condition: "and",
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 0,
					Body:       `{"status": "success"}`,
				},
			},
			expected: true,
		},
		{
			name: "AND condition - one fails",
			matchers: []Matcher{
				{
					Type:      "status",
					Code:      []int{0},
					Condition: "and",
				},
				{
					Type:      "word",
					Words:     []string{"success"},
					Condition: "and",
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 7,
					Body:       `{"status": "success"}`,
				},
			},
			expected: false,
		},
		{
			name: "OR condition - any match succeeds",
			matchers: []Matcher{
				{
					Type:      "status",
					Code:      []int{0},
					Condition: "or",
				},
				{
					Type:      "word",
					Words:     []string{"success"},
					Condition: "or",
				},
			},
			result: &ExecutionResult{
				Response: model.HTTPResponse{
					StatusCode: 7,
					Body:       `{"status": "success"}`,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := executor.evaluateMatchers(tt.matchers, tt.result)
			assert.Equal(t, tt.expected, matched)
		})
	}
}
