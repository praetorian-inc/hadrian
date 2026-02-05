// pkg/runner/grpc_test.go
package runner

import (
	"context"
	"testing"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/builder"
	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/owasp"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
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

// TestGRPCMutationIntegration tests that gRPC runner detects mutation templates
// and routes them to GRPCMutationExecutor
func TestGRPCMutationIntegration(t *testing.T) {
	// Create a mutation template
	tmpl := &templates.CompiledTemplate{
		Template: &templates.Template{
			ID: "test-mutation",
			Info: templates.TemplateInfo{
				TestPattern: "mutation",
				Category:    "BOLA",
				Severity:    "HIGH",
			},
			TestPhases: &templates.TestPhases{
				Setup: []*templates.Phase{
					{
						Path: "/vulnerable.v1.UserService/CreateUser",
						Auth: "victim",
						Data: map[string]string{"name": "test"},
						StoreResponseField: "id",
					},
				},
				Attack: &templates.Phase{
					Path: "/vulnerable.v1.UserService/DeleteUser",
					Auth: "attacker",
					UseStoredField: "id",
				},
				Verify: &templates.Phase{
					Path: "/vulnerable.v1.UserService/GetUser",
					Auth: "victim",
					UseStoredField: "id",
				},
			},
		},
	}

	// Create mock method descriptor
	methodDesc := createMockMethodDescriptor(t, []string{"id", "name"})

	// Create mock auth config
	authCfg := &auth.AuthConfig{
		Method: "bearer",
		Roles: map[string]*auth.RoleAuth{
			"attacker": {Token: "attacker-token"},
			"victim":   {Token: "victim-token"},
		},
	}

	// Create mock roles config
	rolesCfg := &roles.RoleConfig{
		Roles: []*roles.Role{
			{Name: "attacker", ID: "1"},
			{Name: "victim", ID: "2"},
		},
	}

	// Create mock gRPC executor
	mockExecutor := &mockGRPCExecutor{
		responses: []*templates.ExecutionResult{
			{Response: model.HTTPResponse{StatusCode: 200, Body: `{"id": "12345"}`}}, // Setup
			{Response: model.HTTPResponse{StatusCode: 200, Body: `{}`}},              // Attack
			{Response: model.HTTPResponse{StatusCode: 404, Body: `{}`}},              // Verify
		},
	}

	// Create GRPCMutationExecutor with mock
	mutationExecutor := owasp.NewGRPCMutationExecutor(mockExecutor)

	// Execute mutation test
	result, err := mutationExecutor.ExecuteGRPCMutation(
		context.Background(),
		tmpl.Template,
		methodDesc,
		buildAuthInfoMap(authCfg, rolesCfg),
	)

	if err != nil {
		t.Fatalf("ExecuteGRPCMutation failed: %v", err)
	}

	// Verify result
	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if result.TemplateID != "test-mutation" {
		t.Errorf("Expected TemplateID test-mutation, got %s", result.TemplateID)
	}

	// Verify all three phases were called
	if mockExecutor.callCount != 3 {
		t.Errorf("Expected 3 gRPC calls (setup, attack, verify), got %d", mockExecutor.callCount)
	}
}

// mockGRPCExecutor implements owasp.GRPCExecutor for testing
type mockGRPCExecutor struct {
	responses []*templates.ExecutionResult
	callCount int
}

func (m *mockGRPCExecutor) ExecuteGRPC(
	ctx context.Context,
	tmpl *templates.CompiledTemplate,
	methodDesc *desc.MethodDescriptor,
	authInfo *auth.AuthInfo,
	variables map[string]string,
) (*templates.ExecutionResult, error) {
	if m.callCount >= len(m.responses) {
		return nil, nil
	}
	result := m.responses[m.callCount]
	m.callCount++
	return result, nil
}

// Helper function for tests - creates mock method descriptor
func createMockMethodDescriptor(t *testing.T, inputFieldNames []string) *desc.MethodDescriptor {
	t.Helper()

	// Create a message builder for the input type
	msgBuilder := builder.NewMessage("TestRequest")
	for _, fieldName := range inputFieldNames {
		field := builder.NewField(fieldName, builder.FieldTypeString())
		msgBuilder.AddField(field)
	}

	// Create service and method
	svcBuilder := builder.NewService("TestService")
	methodBuilder := builder.NewMethod("TestMethod",
		builder.RpcTypeMessage(msgBuilder, false),
		builder.RpcTypeMessage(builder.NewMessage("TestResponse"), false),
	)
	svcBuilder.AddMethod(methodBuilder)

	// Build the file descriptor
	fileBuilder := builder.NewFile("test.proto").SetPackageName("test")
	fileBuilder.AddService(svcBuilder)
	fileBuilder.AddMessage(msgBuilder)

	fileDesc, err := fileBuilder.Build()
	if err != nil {
		t.Fatalf("Failed to build mock descriptor: %v", err)
	}

	// Get the method descriptor
	services := fileDesc.GetServices()
	if len(services) == 0 {
		t.Fatal("No services found in mock descriptor")
	}
	methods := services[0].GetMethods()
	if len(methods) == 0 {
		t.Fatal("No methods found in mock service")
	}

	return methods[0]
}
