package grpc

import (
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/plugins"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// GRPCPlugin parses Protocol Buffer (.proto) files
type GRPCPlugin struct{}

// init self-registers the plugin
func init() {
	plugins.Register(plugins.ProtocolGRPC, &GRPCPlugin{})
}

func (p *GRPCPlugin) Name() string {
	return "gRPC Proto Parser"
}

func (p *GRPCPlugin) Type() plugins.Protocol {
	return plugins.ProtocolGRPC
}

// CanParse checks if input is a Protocol Buffer file (.proto extension or proto content)
func (p *GRPCPlugin) CanParse(input []byte, filename string) bool {
	ext := filepath.Ext(filename)

	// Check for .proto file extension
	if ext == ".proto" {
		return true
	}

	// Check content for proto markers
	content := string(input)

	// Proto syntax declaration is a strong indicator
	if strings.Contains(content, `syntax = "proto3"`) ||
		strings.Contains(content, `syntax = "proto2"`) {
		return true
	}

	// Require both service and rpc markers together to reduce false positives
	if strings.Contains(content, "service ") && strings.Contains(content, "rpc ") {
		return true
	}

	return false
}

// Parse converts proto file to internal model
func (p *GRPCPlugin) Parse(input []byte) (*model.APISpec, error) {
	// Parse proto file to service descriptors
	services, err := parseProtoFile(input)
	if err != nil {
		return nil, err
	}

	// Convert services to operations
	operations, err := ConvertServicesToOperations(services)
	if err != nil {
		return nil, err
	}

	// Create API spec
	spec := &model.APISpec{
		Info: model.APIInfo{
			Title:   "gRPC API",
			Version: "1.0.0",
		},
		Operations: operations,
	}

	return spec, nil
}

// ParseWithDescriptors parses proto file and returns both the API spec and method descriptors
func (p *GRPCPlugin) ParseWithDescriptors(input []byte) (*model.APISpec, map[string]protoreflect.MethodDescriptor, error) {
	// Parse proto file to service descriptors
	services, err := parseProtoFile(input)
	if err != nil {
		return nil, nil, err
	}

	// Build method descriptor lookup map
	methodDescriptors := BuildMethodDescriptorMap(services)

	// Convert services to operations
	operations, err := ConvertServicesToOperations(services)
	if err != nil {
		return nil, nil, err
	}

	// Create API spec
	spec := &model.APISpec{
		Info: model.APIInfo{
			Title:   "gRPC API",
			Version: "1.0.0",
		},
		Operations: operations,
	}

	return spec, methodDescriptors, nil
}
