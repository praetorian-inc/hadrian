package grpc

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGRPCPlugin_Name(t *testing.T) {
	plugin := &GRPCPlugin{}
	assert.Equal(t, "gRPC Proto Parser", plugin.Name())
}

func TestGRPCPlugin_Type(t *testing.T) {
	plugin := &GRPCPlugin{}
	assert.Equal(t, plugins.ProtocolGRPC, plugin.Type())
}

func TestGRPCPlugin_CanParse_ProtoExtension(t *testing.T) {
	plugin := &GRPCPlugin{}

	tests := []struct {
		name     string
		filename string
		input    []byte
		want     bool
	}{
		{
			name:     "proto extension",
			filename: "api.proto",
			input:    []byte(""),
			want:     true,
		},
		{
			name:     "non-proto extension",
			filename: "api.json",
			input:    []byte(""),
			want:     false,
		},
		{
			name:     "proto extension with path",
			filename: "/path/to/service.proto",
			input:    []byte(""),
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plugin.CanParse(tt.input, tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGRPCPlugin_CanParse_ProtoContent(t *testing.T) {
	plugin := &GRPCPlugin{}

	tests := []struct {
		name     string
		filename string
		input    []byte
		want     bool
	}{
		{
			name:     "proto3 syntax",
			filename: "unknown.txt",
			input:    []byte(`syntax = "proto3";`),
			want:     true,
		},
		{
			name:     "proto2 syntax",
			filename: "unknown.txt",
			input:    []byte(`syntax = "proto2";`),
			want:     true,
		},
		{
			name:     "service definition only (no rpc)",
			filename: "unknown.txt",
			input:    []byte(`service UserService {`),
			want:     false, // requires both "service " and "rpc " to reduce false positives
		},
		{
			name:     "rpc method only (no service)",
			filename: "unknown.txt",
			input:    []byte(`rpc GetUser(UserRequest) returns (UserResponse);`),
			want:     false, // requires both "service " and "rpc " to reduce false positives
		},
		{
			name:     "service and rpc together",
			filename: "unknown.txt",
			input: []byte(`service UserService {
  rpc GetUser(UserRequest) returns (UserResponse);
}`),
			want: true,
		},
		{
			name:     "complete proto file",
			filename: "unknown.txt",
			input: []byte(`syntax = "proto3";
service UserService {
  rpc GetUser(UserRequest) returns (UserResponse);
}`),
			want: true,
		},
		{
			name:     "non-proto content",
			filename: "unknown.txt",
			input:    []byte(`{"type": "object"}`),
			want:     false,
		},
		{
			name:     "empty content",
			filename: "unknown.txt",
			input:    []byte(``),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := plugin.CanParse(tt.input, tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGRPCPlugin_Registration(t *testing.T) {
	// The plugin should be registered via init()
	plugin, ok := plugins.Get(plugins.ProtocolGRPC)
	assert.True(t, ok, "gRPC plugin should be registered")
	assert.NotNil(t, plugin)
	assert.Equal(t, "gRPC Proto Parser", plugin.Name())
	assert.Equal(t, plugins.ProtocolGRPC, plugin.Type())
}

func TestGRPCPlugin_Parse(t *testing.T) {
	p := &GRPCPlugin{}

	protoContent := `
syntax = "proto3";
package test;

service TestService {
    rpc GetItem (GetItemRequest) returns (Item);
}

message GetItemRequest {
    string id = 1;
}

message Item {
    string id = 1;
    string name = 2;
}
`

	spec, err := p.Parse([]byte(protoContent))
	require.NoError(t, err)
	require.NotNil(t, spec)

	assert.Equal(t, "gRPC API", spec.Info.Title)
	assert.Equal(t, "1.0.0", spec.Info.Version)
	require.Len(t, spec.Operations, 1)

	op := spec.Operations[0]
	assert.Equal(t, "/test.TestService/GetItem", op.Path)
	assert.Equal(t, "GRPC", op.Method)
	assert.Equal(t, "grpc", op.Protocol)
}

// TestGRPCPlugin_ParseWithDescriptors tests the new method that returns both spec and descriptors
func TestGRPCPlugin_ParseWithDescriptors(t *testing.T) {
	p := &GRPCPlugin{}

	protoContent := `
syntax = "proto3";
package test;

service TestService {
    rpc GetItem (GetItemRequest) returns (Item);
    rpc CreateItem (CreateItemRequest) returns (Item);
}

message GetItemRequest {
    string id = 1;
}

message CreateItemRequest {
    string name = 1;
}

message Item {
    string id = 1;
    string name = 2;
}
`

	spec, methodDescriptors, err := p.ParseWithDescriptors([]byte(protoContent))
	require.NoError(t, err, "ParseWithDescriptors should not return error")
	require.NotNil(t, spec, "spec should not be nil")
	require.NotNil(t, methodDescriptors, "methodDescriptors should not be nil")

	// Verify spec is populated correctly
	assert.Equal(t, "gRPC API", spec.Info.Title)
	assert.Equal(t, "1.0.0", spec.Info.Version)
	require.Len(t, spec.Operations, 2, "should have 2 operations")

	// Verify method descriptors map is populated correctly
	assert.Len(t, methodDescriptors, 2, "should have 2 method descriptors")

	// Verify GetItem method descriptor
	getItemDesc, ok := methodDescriptors["/test.TestService/GetItem"]
	assert.True(t, ok, "should find GetItem method descriptor")
	require.NotNil(t, getItemDesc, "GetItem descriptor should not be nil")
	assert.Equal(t, "GetItem", string(getItemDesc.Name()))

	// Verify CreateItem method descriptor
	createItemDesc, ok := methodDescriptors["/test.TestService/CreateItem"]
	assert.True(t, ok, "should find CreateItem method descriptor")
	require.NotNil(t, createItemDesc, "CreateItem descriptor should not be nil")
	assert.Equal(t, "CreateItem", string(createItemDesc.Name()))

	// Verify operation paths match descriptor map keys
	for _, op := range spec.Operations {
		desc, ok := methodDescriptors[op.Path]
		assert.True(t, ok, "operation path %s should have corresponding method descriptor", op.Path)
		assert.NotNil(t, desc, "method descriptor for %s should not be nil", op.Path)
	}
}
