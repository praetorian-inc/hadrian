package grpc

import (
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/hadrian/pkg/model"
	"github.com/praetorian-inc/hadrian/pkg/plugins"
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

	// Proto syntax markers
	if strings.Contains(content, `syntax = "proto3"`) ||
		strings.Contains(content, `syntax = "proto2"`) {
		return true
	}

	// Service definition marker
	if strings.Contains(content, "service ") {
		return true
	}

	// RPC method marker
	if strings.Contains(content, "rpc ") {
		return true
	}

	return false
}

// Parse converts proto file to internal model (placeholder implementation for Batch 2)
func (p *GRPCPlugin) Parse(input []byte) (*model.APISpec, error) {
	// Placeholder for Batch 2 implementation
	return nil, ErrNotImplemented
}

// ErrNotImplemented indicates proto parsing is not yet implemented
var ErrNotImplemented = &NotImplementedError{msg: "proto parsing not yet implemented"}

// NotImplementedError represents a not-yet-implemented feature
type NotImplementedError struct {
	msg string
}

func (e *NotImplementedError) Error() string {
	return e.msg
}
