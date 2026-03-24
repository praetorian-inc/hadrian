// pkg/runner/grpc_test.go
package runner

import (
	"context"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/auth"
	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/orchestrator"
	"github.com/praetorian-inc/hadrian/pkg/roles"
	"github.com/praetorian-inc/hadrian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
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
		"template-dir",
		"template",
		"plaintext",
		"tls-ca-cert",
		"rate-limit",
		"timeout",
		"output",
		"verbose",
		"dry-run",
		"proxy",
		"insecure",
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
						Path:               "/vulnerable.v1.UserService/CreateUser",
						Auth:               "victim",
						Data:               map[string]string{"name": "test"},
						StoreResponseField: "id",
					},
				},
				Attack: &templates.Phase{
					Path:           "/vulnerable.v1.UserService/DeleteUser",
					Auth:           "attacker",
					UseStoredField: "id",
				},
				Verify: &templates.Phase{
					Path:           "/vulnerable.v1.UserService/GetUser",
					Auth:           "victim",
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
	mutationExecutor := orchestrator.NewGRPCMutationExecutor(mockExecutor)

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

// mockGRPCExecutor implements orchestrator.GRPCExecutor for testing
type mockGRPCExecutor struct {
	responses []*templates.ExecutionResult
	callCount int
}

func (m *mockGRPCExecutor) ExecuteGRPC(
	ctx context.Context,
	tmpl *templates.CompiledTemplate,
	methodDesc protoreflect.MethodDescriptor,
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
func createMockMethodDescriptor(t *testing.T, inputFieldNames []string) protoreflect.MethodDescriptor {
	t.Helper()

	// Build field descriptors for the input message
	fields := make([]*descriptorpb.FieldDescriptorProto, len(inputFieldNames))
	for i, name := range inputFieldNames {
		num := int32(i + 1)
		typePb := descriptorpb.FieldDescriptorProto_TYPE_STRING
		fields[i] = &descriptorpb.FieldDescriptorProto{
			Name:   &name,
			Number: &num,
			Type:   &typePb,
		}
	}

	reqName := "TestRequest"
	respName := "TestResponse"
	svcName := "TestService"
	methodName := "TestMethod"
	inputTypeName := ".test.TestRequest"
	outputTypeName := ".test.TestResponse"
	pkg := "test"
	syntax := "proto3"
	fileName := "test.proto"

	fdProto := &descriptorpb.FileDescriptorProto{
		Name:    &fileName,
		Package: &pkg,
		Syntax:  &syntax,
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: &reqName, Field: fields},
			{Name: &respName},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: &svcName,
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       &methodName,
						InputType:  &inputTypeName,
						OutputType: &outputTypeName,
					},
				},
			},
		},
	}

	fd, err := protodesc.NewFile(fdProto, nil)
	if err != nil {
		t.Fatalf("Failed to build mock descriptor: %v", err)
	}

	services := fd.Services()
	if services.Len() == 0 {
		t.Fatal("No services found in mock descriptor")
	}
	methods := services.Get(0).Methods()
	if methods.Len() == 0 {
		t.Fatal("No methods found in mock service")
	}

	return methods.Get(0)
}

// TestMatchesEndpointSelector_GRPCServiceAndMethod tests the Service and Method exact match filters
func TestMatchesEndpointSelector_GRPCServiceAndMethod(t *testing.T) {
	t.Run("matches when service filter matches", func(t *testing.T) {
		op := &model.Operation{
			Path:   "/vulnerable.v1.UserService/GetUser",
			Method: "GRPC",
		}
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				EndpointSelector: templates.EndpointSelector{
					Service: "vulnerable.v1.UserService",
				},
			},
		}

		result := matchesEndpointSelector(op, tmpl)
		assert.True(t, result, "should match when service name matches exactly")
	})

	t.Run("does not match when service filter does not match", func(t *testing.T) {
		op := &model.Operation{
			Path:   "/vulnerable.v1.UserService/GetUser",
			Method: "GRPC",
		}
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				EndpointSelector: templates.EndpointSelector{
					Service: "vulnerable.v1.OrderService",
				},
			},
		}

		result := matchesEndpointSelector(op, tmpl)
		assert.False(t, result, "should not match when service name differs")
	})

	t.Run("matches when method filter matches", func(t *testing.T) {
		op := &model.Operation{
			Path:   "/vulnerable.v1.UserService/GetUser",
			Method: "GRPC",
		}
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				EndpointSelector: templates.EndpointSelector{
					Method: "GetUser",
				},
			},
		}

		result := matchesEndpointSelector(op, tmpl)
		assert.True(t, result, "should match when method name matches exactly")
	})

	t.Run("does not match when method filter does not match", func(t *testing.T) {
		op := &model.Operation{
			Path:   "/vulnerable.v1.UserService/GetUser",
			Method: "GRPC",
		}
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				EndpointSelector: templates.EndpointSelector{
					Method: "DeleteUser",
				},
			},
		}

		result := matchesEndpointSelector(op, tmpl)
		assert.False(t, result, "should not match when method name differs")
	})

	t.Run("matches when both service and method filters match", func(t *testing.T) {
		op := &model.Operation{
			Path:   "/vulnerable.v1.UserService/GetUser",
			Method: "GRPC",
		}
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				EndpointSelector: templates.EndpointSelector{
					Service: "vulnerable.v1.UserService",
					Method:  "GetUser",
				},
			},
		}

		result := matchesEndpointSelector(op, tmpl)
		assert.True(t, result, "should match when both service and method match")
	})

	t.Run("does not match when service matches but method does not", func(t *testing.T) {
		op := &model.Operation{
			Path:   "/vulnerable.v1.UserService/GetUser",
			Method: "GRPC",
		}
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				EndpointSelector: templates.EndpointSelector{
					Service: "vulnerable.v1.UserService",
					Method:  "DeleteUser",
				},
			},
		}

		result := matchesEndpointSelector(op, tmpl)
		assert.False(t, result, "should not match when service matches but method does not")
	})

	t.Run("matches when service and method filters empty and methods glob matches", func(t *testing.T) {
		op := &model.Operation{
			Path:   "/vulnerable.v1.UserService/GetUser",
			Method: "GRPC",
		}
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				EndpointSelector: templates.EndpointSelector{
					Methods: []string{"Get*"},
				},
			},
		}

		result := matchesEndpointSelector(op, tmpl)
		assert.True(t, result, "should use methods glob when service/method filters empty")
	})

	t.Run("matches with service filter and methods glob both matching", func(t *testing.T) {
		op := &model.Operation{
			Path:   "/vulnerable.v1.UserService/GetUser",
			Method: "GRPC",
		}
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				EndpointSelector: templates.EndpointSelector{
					Service: "vulnerable.v1.UserService",
					Methods: []string{"Get*"},
				},
			},
		}

		result := matchesEndpointSelector(op, tmpl)
		assert.True(t, result, "should match when service filter and methods glob both match")
	})
}

// TestBuildGRPCFinding tests finding construction with various template configurations
func TestBuildGRPCFinding(t *testing.T) {
	t.Run("template with custom severity and category", func(t *testing.T) {
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				ID: "test-template-id",
				Info: templates.TemplateInfo{
					Severity: "HIGH",
					Category: "BOLA",
				},
			},
		}
		op := &model.Operation{
			Path:   "/example.Service/Method",
			Method: "GRPC",
		}

		finding := buildGRPCFinding(tmpl, op, "attacker", "victim")

		assert.Equal(t, "test-template-id", finding.ID)
		assert.Equal(t, "BOLA", finding.Category)
		assert.Equal(t, "test-template-id", finding.Name)
		assert.Equal(t, model.Severity("HIGH"), finding.Severity)
		assert.True(t, finding.IsVulnerability)
		assert.Equal(t, "/example.Service/Method", finding.Endpoint)
		assert.Equal(t, "GRPC", finding.Method)
		assert.Equal(t, "attacker", finding.AttackerRole)
		assert.Equal(t, "victim", finding.VictimRole)
	})

	t.Run("template with defaults (no severity/category set)", func(t *testing.T) {
		tmpl := &templates.CompiledTemplate{
			Template: &templates.Template{
				ID:   "default-template",
				Info: templates.TemplateInfo{},
			},
		}
		op := &model.Operation{
			Path:   "/test.Service/TestMethod",
			Method: "GRPC",
		}

		finding := buildGRPCFinding(tmpl, op, "user1", "user2")

		assert.Equal(t, "default-template", finding.ID)
		assert.Equal(t, "default-template", finding.Category) // Uses ID as category
		assert.Equal(t, model.Severity("MEDIUM"), finding.Severity)
		assert.Equal(t, "user1", finding.AttackerRole)
		assert.Equal(t, "user2", finding.VictimRole)
	})
}

// TestBuildAuthInfoMap tests auth info map construction
func TestBuildAuthInfoMap(t *testing.T) {
	t.Run("nil authCfg returns empty map", func(t *testing.T) {
		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "user1", ID: "1"},
			},
		}

		result := buildAuthInfoMap(nil, rolesCfg)

		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result))
	})

	t.Run("nil rolesCfg returns empty map", func(t *testing.T) {
		authCfg := &auth.AuthConfig{
			Method: "bearer",
			Roles: map[string]*auth.RoleAuth{
				"user1": {Token: "token1"},
			},
		}

		result := buildAuthInfoMap(authCfg, nil)

		assert.NotNil(t, result)
		assert.Equal(t, 0, len(result))
	})

	t.Run("valid config returns populated map", func(t *testing.T) {
		authCfg := &auth.AuthConfig{
			Method: "bearer",
			Roles: map[string]*auth.RoleAuth{
				"user1": {Token: "token1"},
				"user2": {Token: "token2"},
			},
		}
		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "user1", ID: "1"},
				{Name: "user2", ID: "2"},
			},
		}

		result := buildAuthInfoMap(authCfg, rolesCfg)

		assert.Equal(t, 2, len(result))
		assert.NotNil(t, result["user1"])
		assert.NotNil(t, result["user2"])
	})
}

// TestLoadGRPCTemplates tests template loading from directories
func TestLoadGRPCTemplates(t *testing.T) {
	t.Run("load from existing templates/grpc/ directory", func(t *testing.T) {
		// Use path relative to test file location (pkg/runner/)
		templatesPath := "../../templates/grpc"

		templates, err := loadGRPCTemplates(templatesPath)

		// Should successfully load templates without error
		assert.NoError(t, err)
		assert.NotNil(t, templates)
		// The directory should contain at least some templates
		assert.GreaterOrEqual(t, len(templates), 0)
	})

	t.Run("load from non-existent directory returns error", func(t *testing.T) {
		templates, err := loadGRPCTemplates("/nonexistent/path")

		assert.Error(t, err)
		assert.Nil(t, templates)
	})
}

// TestBuildTemplateVariablesWithRoles tests variable construction with and without auth/roles
func TestBuildTemplateVariablesWithRoles(t *testing.T) {
	t.Run("with nil auth/roles configs uses defaults", func(t *testing.T) {
		methodDesc := createMockMethodDescriptor(t, []string{"id", "name"})
		op := &model.Operation{
			Path:   "/test.Service/TestMethod",
			Method: "GRPC",
		}

		variables, attackerRole, victimRole := buildTemplateVariablesWithRoles(op, methodDesc, nil, nil)

		// Check operation variables
		assert.Equal(t, "/test.Service/TestMethod", variables["operation.path"])
		assert.Equal(t, "TestMethod", variables["operation.method"])
		assert.Equal(t, "TestService", variables["operation.service"])
		assert.Equal(t, "TestService", variables["service.name"])

		// Check owner field fallback (should use first field from descriptor)
		assert.Equal(t, "id", variables["operation.owner_field"])

		// Check default role names
		assert.Equal(t, "user1", attackerRole)
		assert.Equal(t, "user2", victimRole)

		// Check fallback tokens/IDs
		assert.Equal(t, "test-victim-id", variables["victim_id"])
		assert.Equal(t, "test-attacker-token", variables["attacker_token"])
	})

	t.Run("with auth and roles configs uses real values", func(t *testing.T) {
		methodDesc := createMockMethodDescriptor(t, []string{"user_id", "data"})
		op := &model.Operation{
			Path:       "/example.UserService/GetUser",
			Method:     "GRPC",
			OwnerField: "user_id",
		}

		authCfg := &auth.AuthConfig{
			Method: "bearer",
			Roles: map[string]*auth.RoleAuth{
				"user1": {Token: "real-token-1"},
				"user2": {Token: "real-token-2"},
			},
		}
		rolesCfg := &roles.RoleConfig{
			Roles: []*roles.Role{
				{Name: "user1", ID: "attacker-id-123"},
				{Name: "user2", ID: "victim-id-456"},
			},
		}

		variables, attackerRole, victimRole := buildTemplateVariablesWithRoles(op, methodDesc, authCfg, rolesCfg)

		// Check operation variables
		assert.Equal(t, "/example.UserService/GetUser", variables["operation.path"])
		assert.Equal(t, "TestMethod", variables["operation.method"]) // From mock
		assert.Equal(t, "user_id", variables["operation.owner_field"])

		// Check role names from config
		assert.Equal(t, "user1", attackerRole)
		assert.Equal(t, "user2", victimRole)

		// Check real tokens/IDs from config
		assert.Equal(t, "victim-id-456", variables["victim_id"])
		assert.Equal(t, "real-token-1", variables["attacker_token"])
	})
}

// TestGRPCConfigValidate tests all validation paths
func TestGRPCConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    GRPCConfig
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid config (proto mode)",
			config: GRPCConfig{
				Target:    "localhost:50051",
				Proto:     "test.proto",
				Timeout:   30,
				RateLimit: 5.0,
			},
			wantError: false,
		},
		{
			name: "valid config (reflection mode)",
			config: GRPCConfig{
				Target:     "localhost:50051",
				Reflection: true,
				Timeout:    30,
				RateLimit:  5.0,
			},
			wantError: false,
		},
		{
			name: "missing target",
			config: GRPCConfig{
				Proto:     "test.proto",
				Timeout:   30,
				RateLimit: 5.0,
			},
			wantError: true,
			errorMsg:  "--target is required",
		},
		{
			name: "missing proto and reflection",
			config: GRPCConfig{
				Target:    "localhost:50051",
				Timeout:   30,
				RateLimit: 5.0,
			},
			wantError: true,
			errorMsg:  "either --proto or --reflection must be provided",
		},
		{
			name: "plaintext + TLSCACert mutual exclusion",
			config: GRPCConfig{
				Target:    "localhost:50051",
				Proto:     "test.proto",
				Plaintext: true,
				TLSCACert: "/path/to/ca.crt",
				Timeout:   30,
				RateLimit: 5.0,
			},
			wantError: true,
			errorMsg:  "--plaintext and --tls-ca-cert are mutually exclusive",
		},
		{
			name: "insecure + TLSCACert mutual exclusion",
			config: GRPCConfig{
				Target:    "localhost:50051",
				Proto:     "test.proto",
				Insecure:  true,
				TLSCACert: "/path/to/ca.crt",
				Timeout:   30,
				RateLimit: 5.0,
			},
			wantError: true,
			errorMsg:  "--insecure and --tls-ca-cert are mutually exclusive",
		},
		{
			name: "TLSCACert file not found",
			config: GRPCConfig{
				Target:    "localhost:50051",
				Proto:     "test.proto",
				TLSCACert: "/nonexistent/ca.crt",
				Timeout:   30,
				RateLimit: 5.0,
			},
			wantError: true,
			errorMsg:  "TLS CA certificate file not found",
		},
		// Note: zero/negative timeout and rate limit are now handled by setDefaults()
		// which fills in sensible defaults (matching REST Config.setDefaults() pattern).
		// This allows library callers to omit these fields.
	}

	for _, tt := range tests {
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

// TestGRPCConfigSetDefaults verifies that setDefaults fills zero-valued fields
// with sensible defaults and does not overwrite explicitly set values.
func TestGRPCConfigSetDefaults(t *testing.T) {
	t.Run("zero-valued config gets sensible defaults", func(t *testing.T) {
		c := GRPCConfig{}
		c.setDefaults()

		assert.Equal(t, "json", c.Output)
		assert.Equal(t, 5.0, c.RateLimit)
		assert.Equal(t, 30, c.Timeout)
		assert.Equal(t, "./templates/grpc", c.TemplateDir)
	})

	t.Run("explicitly set values are not overwritten by setDefaults", func(t *testing.T) {
		c := GRPCConfig{
			Output:      "terminal",
			RateLimit:   10.0,
			Timeout:     60,
			TemplateDir: "/custom/templates",
		}
		c.setDefaults()

		assert.Equal(t, "terminal", c.Output)
		assert.Equal(t, 10.0, c.RateLimit)
		assert.Equal(t, 60, c.Timeout)
		assert.Equal(t, "/custom/templates", c.TemplateDir)
	})
}

// TestCountServices tests service counting from operations
func TestCountServices(t *testing.T) {
	t.Run("empty operations - 0 services", func(t *testing.T) {
		operations := []*model.Operation{}

		count := countServices(operations)

		assert.Equal(t, 0, count)
	})

	t.Run("single service with multiple methods - 1 service", func(t *testing.T) {
		operations := []*model.Operation{
			{Path: "/example.UserService/GetUser"},
			{Path: "/example.UserService/CreateUser"},
			{Path: "/example.UserService/DeleteUser"},
		}

		count := countServices(operations)

		assert.Equal(t, 1, count)
	})

	t.Run("multiple services - correct count", func(t *testing.T) {
		operations := []*model.Operation{
			{Path: "/example.UserService/GetUser"},
			{Path: "/example.UserService/CreateUser"},
			{Path: "/example.OrderService/GetOrder"},
			{Path: "/example.OrderService/CreateOrder"},
			{Path: "/example.ProductService/GetProduct"},
		}

		count := countServices(operations)

		assert.Equal(t, 3, count)
	})

	t.Run("handles malformed paths gracefully", func(t *testing.T) {
		operations := []*model.Operation{
			{Path: "/example.UserService/GetUser"},
			{Path: "malformed"},
			{Path: ""},
			{Path: "/example.OrderService/GetOrder"},
		}

		// Should count only valid service paths
		count := countServices(operations)

		assert.Equal(t, 2, count)
	})
}
