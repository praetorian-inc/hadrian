package grpc

import (
	"google.golang.org/protobuf/reflect/protoreflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testProto = `
syntax = "proto3";
package user.v1;

service UserService {
    rpc GetUser (GetUserRequest) returns (User);
    rpc CreateUser (CreateUserRequest) returns (User);
    rpc DeleteUser (DeleteUserRequest) returns (Empty);
    rpc StreamUsers (StreamUsersRequest) returns (stream User);
    rpc UploadUsers (stream CreateUserRequest) returns (User);
}

message GetUserRequest {
    string id = 1;
}

message CreateUserRequest {
    string name = 1;
    string email = 2;
}

message DeleteUserRequest {
    string id = 1;
}

message StreamUsersRequest {
    int32 limit = 1;
}

message User {
    string id = 1;
    string name = 2;
    string email = 3;
}

message Empty {}
`

func TestParseProtoFile(t *testing.T) {
	services, err := parseProtoFile([]byte(testProto))
	require.NoError(t, err, "parseProtoFile should not return error for valid proto")
	require.Len(t, services, 1, "should find exactly 1 service")

	service := services[0]
	assert.Equal(t, "UserService", service.Name)
	assert.Equal(t, "user.v1.UserService", service.FullName)

	// Should have 3 unary methods (skipping streaming)
	assert.Len(t, service.Methods, 3, "should have 3 unary methods (streaming methods skipped)")

	// Verify method names
	methodNames := make([]string, len(service.Methods))
	for i, m := range service.Methods {
		methodNames[i] = m.Name
	}
	assert.Contains(t, methodNames, "GetUser")
	assert.Contains(t, methodNames, "CreateUser")
	assert.Contains(t, methodNames, "DeleteUser")

	// Should NOT contain streaming methods
	assert.NotContains(t, methodNames, "StreamUsers")
	assert.NotContains(t, methodNames, "UploadUsers")
}

func TestParseProtoFile_MethodDetails(t *testing.T) {
	services, err := parseProtoFile([]byte(testProto))
	require.NoError(t, err)
	require.Len(t, services, 1)

	service := services[0]

	// Find GetUser method
	var getUserMethod *MethodDescriptor
	for _, m := range service.Methods {
		if m.Name == "GetUser" {
			getUserMethod = m
			break
		}
	}
	require.NotNil(t, getUserMethod, "GetUser method should exist")

	// Verify method details
	assert.Equal(t, "GetUser", getUserMethod.Name)
	assert.Equal(t, "user.v1.UserService.GetUser", getUserMethod.FullName)
	assert.False(t, getUserMethod.IsServerStream)
	assert.False(t, getUserMethod.IsClientStream)

	// Verify input type
	require.NotNil(t, getUserMethod.InputType)
	assert.Equal(t, "GetUserRequest", getUserMethod.InputType.Name)
	assert.Equal(t, "user.v1.GetUserRequest", getUserMethod.InputType.FullName)
	require.Len(t, getUserMethod.InputType.Fields, 1)
	assert.Equal(t, "id", getUserMethod.InputType.Fields[0].Name)
	assert.Equal(t, int32(1), getUserMethod.InputType.Fields[0].Number)
	assert.Equal(t, "string", getUserMethod.InputType.Fields[0].Type)

	// Verify output type
	require.NotNil(t, getUserMethod.OutputType)
	assert.Equal(t, "User", getUserMethod.OutputType.Name)
	assert.Equal(t, "user.v1.User", getUserMethod.OutputType.FullName)
	require.Len(t, getUserMethod.OutputType.Fields, 3)

	// Verify User fields
	userFields := getUserMethod.OutputType.Fields
	assert.Equal(t, "id", userFields[0].Name)
	assert.Equal(t, int32(1), userFields[0].Number)
	assert.Equal(t, "string", userFields[0].Type)

	assert.Equal(t, "name", userFields[1].Name)
	assert.Equal(t, int32(2), userFields[1].Number)
	assert.Equal(t, "string", userFields[1].Type)

	assert.Equal(t, "email", userFields[2].Name)
	assert.Equal(t, int32(3), userFields[2].Number)
	assert.Equal(t, "string", userFields[2].Type)
}

func TestParseProtoFile_SkipsStreaming(t *testing.T) {
	services, err := parseProtoFile([]byte(testProto))
	require.NoError(t, err)
	require.Len(t, services, 1)

	service := services[0]

	// Verify streaming methods are skipped
	for _, method := range service.Methods {
		assert.False(t, method.IsServerStream, "method %s should not be server streaming", method.Name)
		assert.False(t, method.IsClientStream, "method %s should not be client streaming", method.Name)

		// Verify no streaming method names
		assert.NotEqual(t, "StreamUsers", method.Name)
		assert.NotEqual(t, "UploadUsers", method.Name)
	}
}

func TestParseProtoFile_InvalidSyntax(t *testing.T) {
	invalidProto := `
syntax = "proto3";
package invalid;

service BadService {
    rpc InvalidMethod (
}
`
	services, err := parseProtoFile([]byte(invalidProto))
	assert.Error(t, err, "should return error for invalid proto syntax")
	assert.Nil(t, services, "should return nil services on error")
}

// TestMethodDescriptor_RawDescriptorField tests that RawDescriptor field is populated
func TestMethodDescriptor_RawDescriptorField(t *testing.T) {
	services, err := parseProtoFile([]byte(testProto))
	require.NoError(t, err)
	require.Len(t, services, 1)

	service := services[0]
	require.NotEmpty(t, service.Methods, "should have at least one method")

	// Verify RawDescriptor is populated for all methods
	for _, method := range service.Methods {
		assert.NotNil(t, method.RawDescriptor, "RawDescriptor should not be nil for method %s", method.Name)
		assert.Equal(t, method.Name, string(method.RawDescriptor.Name()), "RawDescriptor name should match method name")
	}
}

// TestBuildMethodDescriptorMap tests the method descriptor lookup map creation
func TestBuildMethodDescriptorMap(t *testing.T) {
	services, err := parseProtoFile([]byte(testProto))
	require.NoError(t, err)
	require.Len(t, services, 1)

	// Build the method descriptor map
	descriptorMap := BuildMethodDescriptorMap(services)
	require.NotNil(t, descriptorMap, "BuildMethodDescriptorMap should not return nil")

	// Map should have 3 entries (3 unary methods)
	assert.Len(t, descriptorMap, 3, "should have 3 method descriptors (streaming methods excluded)")

	// Verify entries exist for each unary method with correct path format
	getUserDesc, ok := descriptorMap["/user.v1.UserService/GetUser"]
	assert.True(t, ok, "should find GetUser method descriptor")
	assert.NotNil(t, getUserDesc, "GetUser descriptor should not be nil")
	assert.Equal(t, protoreflect.Name("GetUser"), getUserDesc.Name())

	createUserDesc, ok := descriptorMap["/user.v1.UserService/CreateUser"]
	assert.True(t, ok, "should find CreateUser method descriptor")
	assert.NotNil(t, createUserDesc, "CreateUser descriptor should not be nil")
	assert.Equal(t, protoreflect.Name("CreateUser"), createUserDesc.Name())

	deleteUserDesc, ok := descriptorMap["/user.v1.UserService/DeleteUser"]
	assert.True(t, ok, "should find DeleteUser method descriptor")
	assert.NotNil(t, deleteUserDesc, "DeleteUser descriptor should not be nil")
	assert.Equal(t, protoreflect.Name("DeleteUser"), deleteUserDesc.Name())

	// Verify streaming methods are NOT in the map
	_, ok = descriptorMap["/user.v1.UserService/StreamUsers"]
	assert.False(t, ok, "should not include server streaming method StreamUsers")

	_, ok = descriptorMap["/user.v1.UserService/UploadUsers"]
	assert.False(t, ok, "should not include client streaming method UploadUsers")
}
