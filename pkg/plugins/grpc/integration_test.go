//go:build integration
// +build integration

package grpc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration_ParseSampleProto(t *testing.T) {
	// Find test fixtures relative to repo root
	protoPath := filepath.Join("..", "..", "..", "test", "grpc", "sample.proto")

	content, err := os.ReadFile(protoPath)
	require.NoError(t, err, "Failed to read sample.proto")

	plugin := &GRPCPlugin{}

	// Verify CanParse
	assert.True(t, plugin.CanParse(content, "sample.proto"))

	// Parse
	spec, err := plugin.Parse(content)
	require.NoError(t, err)
	require.NotNil(t, spec)

	// Verify services extracted
	assert.Equal(t, "gRPC API", spec.Info.Title)

	// Should have operations from both UserService and AdminService
	// UserService: 5 methods, AdminService: 2 methods = 7 total
	assert.GreaterOrEqual(t, len(spec.Operations), 7)

	// Find GetUser operation
	var getUserOp *model.Operation
	for _, op := range spec.Operations {
		if strings.Contains(op.Path, "GetUser") {
			getUserOp = op
			break
		}
	}
	require.NotNil(t, getUserOp, "GetUser operation should exist")

	assert.Equal(t, "grpc", getUserOp.Protocol)
	assert.Equal(t, "id", getUserOp.OwnerField)
	assert.False(t, getUserOp.RequiresAuth, "GetUser should not require auth")
}

func TestIntegration_ParseComplexProto(t *testing.T) {
	protoPath := filepath.Join("..", "..", "..", "test", "grpc", "complex.proto")

	content, err := os.ReadFile(protoPath)
	require.NoError(t, err)

	plugin := &GRPCPlugin{}
	spec, err := plugin.Parse(content)
	require.NoError(t, err)

	// Should skip streaming method (StreamOrders)
	// CreateOrder and GetOrder should be included = 2 operations
	assert.Equal(t, 2, len(spec.Operations))

	// Verify CreateOrder has user_id as owner field
	var createOrderOp *model.Operation
	for _, op := range spec.Operations {
		if strings.Contains(op.Path, "CreateOrder") {
			createOrderOp = op
			break
		}
	}
	require.NotNil(t, createOrderOp)

	// Should have user_id as owner field
	assert.Equal(t, "user_id", createOrderOp.OwnerField)
}

func TestIntegration_AuthRequirementInference(t *testing.T) {
	protoPath := filepath.Join("..", "..", "..", "test", "grpc", "sample.proto")

	content, err := os.ReadFile(protoPath)
	require.NoError(t, err)

	plugin := &GRPCPlugin{}
	spec, err := plugin.Parse(content)
	require.NoError(t, err)

	authRequired := make(map[string]bool)
	for _, op := range spec.Operations {
		// Extract method name from path
		parts := strings.Split(op.Path, "/")
		methodName := parts[len(parts)-1]
		authRequired[methodName] = op.RequiresAuth
	}

	// Read operations should not require auth
	assert.False(t, authRequired["GetUser"])
	assert.False(t, authRequired["ListUsers"])
	assert.False(t, authRequired["GetSystemConfig"])

	// Write operations should require auth
	assert.True(t, authRequired["CreateUser"])
	assert.True(t, authRequired["UpdateUser"])
	assert.True(t, authRequired["DeleteUser"])
	assert.True(t, authRequired["SetSystemConfig"])
}

func TestIntegration_OperationPaths(t *testing.T) {
	protoPath := filepath.Join("..", "..", "..", "test", "grpc", "sample.proto")

	content, err := os.ReadFile(protoPath)
	require.NoError(t, err)

	plugin := &GRPCPlugin{}
	spec, err := plugin.Parse(content)
	require.NoError(t, err)

	// Find specific operations and verify path format
	pathsFound := make(map[string]bool)
	for _, op := range spec.Operations {
		pathsFound[op.Path] = true
	}

	// Verify expected paths exist
	assert.True(t, pathsFound["/test.v1.UserService/GetUser"], "GetUser path")
	assert.True(t, pathsFound["/test.v1.UserService/CreateUser"], "CreateUser path")
	assert.True(t, pathsFound["/test.v1.AdminService/GetSystemConfig"], "GetSystemConfig path")
}
