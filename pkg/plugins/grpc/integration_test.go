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

// These integration tests parse the local .proto fixtures under test/grpc/.
// They require no Docker or running gRPC server — parsing happens in-process.

func TestIntegration_ParseSampleProto(t *testing.T) {
	protoPath := filepath.Join("..", "..", "..", "test", "grpc", "sample.proto")

	content, err := os.ReadFile(protoPath)
	require.NoError(t, err, "Failed to read sample.proto")

	plugin := &GRPCPlugin{}

	assert.True(t, plugin.CanParse(content, "sample.proto"))

	spec, err := plugin.Parse(content)
	require.NoError(t, err)
	require.NotNil(t, spec)

	assert.Equal(t, "gRPC API", spec.Info.Title)

	// sample.proto defines GreeterService with SayHello + GetProfile (2 methods).
	assert.Equal(t, 2, len(spec.Operations))

	var getProfileOp *model.Operation
	for _, op := range spec.Operations {
		if strings.Contains(op.Path, "GetProfile") {
			getProfileOp = op
			break
		}
	}
	require.NotNil(t, getProfileOp, "GetProfile operation should exist")

	assert.Equal(t, "grpc", getProfileOp.Protocol)
	// ProfileRequest has a user_id field → inferred as the owner field.
	assert.Equal(t, "user_id", getProfileOp.OwnerField)
}

func TestIntegration_ParseComplexProto(t *testing.T) {
	protoPath := filepath.Join("..", "..", "..", "test", "grpc", "complex.proto")

	content, err := os.ReadFile(protoPath)
	require.NoError(t, err)

	plugin := &GRPCPlugin{}
	spec, err := plugin.Parse(content)
	require.NoError(t, err)

	// Should skip the streaming method (StreamOrders); CreateOrder + GetOrder = 2.
	assert.Equal(t, 2, len(spec.Operations))

	var createOrderOp *model.Operation
	for _, op := range spec.Operations {
		if strings.Contains(op.Path, "CreateOrder") {
			createOrderOp = op
			break
		}
	}
	require.NotNil(t, createOrderOp)

	// CreateOrderRequest has user_id → owner field.
	assert.Equal(t, "user_id", createOrderOp.OwnerField)
}

func TestIntegration_AuthRequirementInference(t *testing.T) {
	protoPath := filepath.Join("..", "..", "..", "test", "grpc", "complex.proto")

	content, err := os.ReadFile(protoPath)
	require.NoError(t, err)

	plugin := &GRPCPlugin{}
	spec, err := plugin.Parse(content)
	require.NoError(t, err)

	authRequired := make(map[string]bool)
	for _, op := range spec.Operations {
		parts := strings.Split(op.Path, "/")
		methodName := parts[len(parts)-1]
		authRequired[methodName] = op.RequiresAuth
	}

	// Read operation should not require auth; write/create operation should.
	assert.False(t, authRequired["GetOrder"], "GetOrder (read) should not require auth")
	assert.True(t, authRequired["CreateOrder"], "CreateOrder (write) should require auth")
}

func TestIntegration_OperationPaths(t *testing.T) {
	protoPath := filepath.Join("..", "..", "..", "test", "grpc", "sample.proto")

	content, err := os.ReadFile(protoPath)
	require.NoError(t, err)

	plugin := &GRPCPlugin{}
	spec, err := plugin.Parse(content)
	require.NoError(t, err)

	pathsFound := make(map[string]bool)
	for _, op := range spec.Operations {
		pathsFound[op.Path] = true
	}

	assert.True(t, pathsFound["/example.GreeterService/SayHello"], "SayHello path")
	assert.True(t, pathsFound["/example.GreeterService/GetProfile"], "GetProfile path")
}
