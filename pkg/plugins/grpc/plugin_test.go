package grpc

import (
	"testing"

	"github.com/praetorian-inc/hadrian/pkg/plugins"
	"github.com/stretchr/testify/assert"
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
			name:     "service definition",
			filename: "unknown.txt",
			input:    []byte(`service UserService {`),
			want:     true,
		},
		{
			name:     "rpc method",
			filename: "unknown.txt",
			input:    []byte(`rpc GetUser(UserRequest) returns (UserResponse);`),
			want:     true,
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
