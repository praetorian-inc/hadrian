package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/builder"
	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// mockGRPCExecutor implements a simple mock for testing
type mockGRPCExecutor struct {
	responses map[string]*templates.ExecutionResult
	callCount int
}

func (m *mockGRPCExecutor) ExecuteGRPC(
	ctx context.Context,
	tmpl *templates.CompiledTemplate,
	methodDesc *desc.MethodDescriptor,
	authInfo *auth.AuthInfo,
	variables map[string]string,
) (*templates.ExecutionResult, error) {
	m.callCount++

	// Return response based on the method path in the template
	if len(tmpl.GRPC) > 0 {
		method := tmpl.GRPC[0].Method
		// Determine phase based on method name
		switch {
		case strings.Contains(method, "Create"):
			return m.responses["setup"], nil
		case strings.Contains(method, "Delete"):
			return m.responses["attack"], nil
		case strings.Contains(method, "Get"):
			return m.responses["verify"], nil
		}
	}

	return &templates.ExecutionResult{}, nil
}

func TestNewGRPCMutationExecutor(t *testing.T) {
	mockExec := &mockGRPCExecutor{}
	executor := NewGRPCMutationExecutor(mockExec)

	assert.NotNil(t, executor)
	assert.NotNil(t, executor.tracker)
}

func TestExecuteGRPCMutation_ThreePhases(t *testing.T) {
	// Create mock executor with predefined responses
	mockExec := &mockGRPCExecutor{
		responses: map[string]*templates.ExecutionResult{
			"setup": {
				Response: model.HTTPResponse{
					StatusCode: int(codes.OK),
					Body:       `{"id": "resource-123", "name": "test"}`,
				},
			},
			"attack": {
				Response: model.HTTPResponse{
					StatusCode: int(codes.PermissionDenied),
					Body:       `{"error": "permission denied"}`,
				},
			},
			"verify": {
				Response: model.HTTPResponse{
					StatusCode: int(codes.OK),
					Body:       `{"id": "resource-123", "name": "test"}`,
				},
			},
		},
	}

	executor := NewGRPCMutationExecutor(mockExec)

	// Create test template with three phases
	tmpl := &templates.Template{
		ID: "test-mutation",
		Info: templates.TemplateInfo{
			TestPattern: "mutation",
		},
		TestPhases: &templates.TestPhases{
			Setup: []*templates.Phase{
				{
					Path:               "/test.Service/CreateResource",
					Operation:          "create",
					Auth:               "victim",
					StoreResponseField: "id",
				},
			},
			Attack: &templates.Phase{
				Path:           "/test.Service/DeleteResource",
				Operation:      "delete",
				Auth:           "attacker",
				UseStoredField: "id",
			},
			Verify: &templates.Phase{
				Path:           "/test.Service/GetResource",
				Operation:      "read",
				Auth:           "victim",
				UseStoredField: "id",
			},
		},
	}

	// Create minimal method descriptor for testing
	methodDesc := createTestMethodDescriptor(t, "TestService", "CreateResource")

	authInfos := map[string]*auth.AuthInfo{
		"victim": {
			Method: "bearer",
			Value:  "Bearer victim-token",
		},
		"attacker": {
			Method: "bearer",
			Value:  "Bearer attacker-token",
		},
	}

	result, err := executor.ExecuteGRPCMutation(
		context.Background(),
		tmpl,
		methodDesc,
		authInfos,
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "test-mutation", result.TemplateID)
	assert.Equal(t, "resource-123", result.ResourceID)
	assert.NotNil(t, result.SetupResponse)
	assert.NotNil(t, result.AttackResponse)
	assert.NotNil(t, result.VerifyResponse)
}

func TestExecuteGRPCMutation_ResourceTracking(t *testing.T) {
	// Mock executor that checks if resource ID is substituted correctly
	mockExec := &mockGRPCExecutor{
		responses: map[string]*templates.ExecutionResult{
			"setup": {
				Response: model.HTTPResponse{
					StatusCode: int(codes.OK),
					Body:       `{"video_id": "vid-456", "user_id": "user-789"}`,
				},
			},
			"attack": {
				Response: model.HTTPResponse{
					StatusCode: int(codes.OK), // Attack succeeded - vulnerability!
					Body:       `{"deleted": true}`,
				},
			},
			"verify": {
				Response: model.HTTPResponse{
					StatusCode: int(codes.NotFound), // Resource was deleted
					Body:       `{"error": "not found"}`,
				},
			},
		},
	}

	executor := NewGRPCMutationExecutor(mockExec)

	// Template with multiple stored fields
	tmpl := &templates.Template{
		ID: "bola-delete-test",
		Info: templates.TemplateInfo{
			TestPattern: "mutation",
		},
		TestPhases: &templates.TestPhases{
			Setup: []*templates.Phase{
				{
					Path:               "/test.VideoService/CreateVideo",
					Operation:          "create",
					Auth:               "victim",
					StoreResponseField: "video_id", // Primary resource ID
					StoreResponseFields: map[string]string{
						"user_id": "user_id", // Additional field
					},
				},
			},
			Attack: &templates.Phase{
				Path:           "/test.VideoService/DeleteVideo",
				Operation:      "delete",
				Auth:           "attacker",
				UseStoredField: "video_id",
			},
			Verify: &templates.Phase{
				Path:           "/test.VideoService/GetVideo",
				Operation:      "read",
				Auth:           "victim",
				UseStoredField: "video_id",
			},
		},
	}

	methodDesc := createTestMethodDescriptor(t, "VideoService", "CreateVideo")

	authInfos := map[string]*auth.AuthInfo{
		"victim":   {Method: "bearer", Value: "Bearer victim-token"},
		"attacker": {Method: "bearer", Value: "Bearer attacker-token"},
	}

	result, err := executor.ExecuteGRPCMutation(
		context.Background(),
		tmpl,
		methodDesc,
		authInfos,
	)

	require.NoError(t, err)
	assert.Equal(t, "vid-456", result.ResourceID)

	// Verify tracker has both fields stored
	assert.Equal(t, "vid-456", executor.tracker.GetResource("video_id"))
	assert.Equal(t, "user-789", executor.tracker.GetResource("user_id"))
}

func TestExecuteGRPCMutation_DetectionConditions(t *testing.T) {
	tests := []struct {
		name          string
		attackStatus  codes.Code
		attackBody    string
		checkField    string // Field to check in attack response
		expectedValue string // Expected value for vulnerability detection
		expectedMatch bool
	}{
		{
			name:          "attack_denied_correctly",
			attackStatus:  codes.PermissionDenied,
			attackBody:    `{"error": "permission denied"}`,
			checkField:    "error",             // Check error field exists
			expectedValue: "permission denied", // Expect permission denied message
			expectedMatch: true,                // Correctly denied (message matches expected)
		},
		{
			name:          "attack_succeeded_vulnerability",
			attackStatus:  codes.OK,
			attackBody:    `{"deleted": true}`,
			checkField:    "deleted", // Check 'deleted' field
			expectedValue: "true",    // Expect true = vulnerability
			expectedMatch: true,      // Succeeded = vulnerability found
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockExec := &mockGRPCExecutor{
				responses: map[string]*templates.ExecutionResult{
					"setup": {
						Response: model.HTTPResponse{
							StatusCode: int(codes.OK),
							Body:       `{"id": "test-123"}`,
						},
					},
					"attack": {
						Response: model.HTTPResponse{
							StatusCode: int(tt.attackStatus), // Actual response status
							Body:       tt.attackBody,
						},
					},
					"verify": {
						Response: model.HTTPResponse{
							StatusCode: int(codes.OK),
							Body:       `{"id": "test-123"}`,
						},
					},
				},
			}

			executor := NewGRPCMutationExecutor(mockExec)

			attackPhase := &templates.Phase{
				Path:           "/test.Service/Delete",
				Operation:      "delete",
				Auth:           "attacker",
				UseStoredField: "id",
			}
			// Only set detection conditions if specified
			if tt.checkField != "" {
				attackPhase.CheckField = tt.checkField
				attackPhase.ExpectedValue = tt.expectedValue
			}

			tmpl := &templates.Template{
				ID: "test-detection",
				Info: templates.TemplateInfo{
					TestPattern: "mutation",
				},
				TestPhases: &templates.TestPhases{
					Setup: []*templates.Phase{
						{
							Path:               "/test.Service/Create",
							Operation:          "create",
							Auth:               "victim",
							StoreResponseField: "id",
						},
					},
					Attack: attackPhase,
					Verify: &templates.Phase{
						Path:           "/test.Service/Get",
						Operation:      "read",
						Auth:           "victim",
						UseStoredField: "id",
					},
				},
			}

			methodDesc := createTestMethodDescriptor(t, "Service", "Create")

			authInfos := map[string]*auth.AuthInfo{
				"victim":   {Method: "bearer", Value: "Bearer victim-token"},
				"attacker": {Method: "bearer", Value: "Bearer attacker-token"},
			}

			result, err := executor.ExecuteGRPCMutation(
				context.Background(),
				tmpl,
				methodDesc,
				authInfos,
			)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedMatch, result.Matched, "Matched should be %v for %s", tt.expectedMatch, tt.name)
		})
	}
}

// Helper function to create a minimal method descriptor for testing
func createTestMethodDescriptor(t *testing.T, serviceName, methodName string) *desc.MethodDescriptor {
	// Create a minimal service descriptor
	serviceBuilder := builder.NewService(serviceName)

	// Create minimal message types
	msgBuilder := builder.NewMessage("Request")
	msgBuilder.AddField(builder.NewField("id", builder.FieldTypeString()))

	respBuilder := builder.NewMessage("Response")
	respBuilder.AddField(builder.NewField("id", builder.FieldTypeString()))

	// Add method to service
	methodBuilder := builder.NewMethod(methodName,
		builder.RpcTypeMessage(msgBuilder, false),
		builder.RpcTypeMessage(respBuilder, false),
	)

	serviceBuilder.AddMethod(methodBuilder)

	// Build the service descriptor
	fileBuilder := builder.NewFile("test.proto")
	fileBuilder.AddService(serviceBuilder)

	fileDesc, err := fileBuilder.Build()
	require.NoError(t, err)

	serviceDesc := fileDesc.GetServices()[0]
	return serviceDesc.GetMethods()[0]
}
