package grpc

import (
	"fmt"

	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/desc/protoparse"
)

// ServiceDescriptor wraps protoreflect's service descriptor
type ServiceDescriptor struct {
	Name     string
	FullName string
	Methods  []*MethodDescriptor
}

// MethodDescriptor wraps protoreflect's method descriptor
type MethodDescriptor struct {
	Name           string
	FullName       string
	InputType      *MessageDescriptor
	OutputType     *MessageDescriptor
	IsServerStream bool
	IsClientStream bool
	// RawDescriptor holds the original protoreflect descriptor for dynamic message building
	RawDescriptor *desc.MethodDescriptor
}

// MessageDescriptor wraps protoreflect's message descriptor
type MessageDescriptor struct {
	Name     string
	FullName string
	Fields   []*FieldDescriptor
}

// FieldDescriptor wraps protoreflect's field descriptor
type FieldDescriptor struct {
	Name       string
	Number     int32
	Type       string
	TypeName   string
	IsRepeated bool
	IsRequired bool
}

// parseProtoFile parses a proto file and extracts service definitions
func parseProtoFile(input []byte) ([]*ServiceDescriptor, error) {
	parser := protoparse.Parser{
		Accessor: protoparse.FileContentsFromMap(map[string]string{
			"input.proto": string(input),
		}),
	}

	fds, err := parser.ParseFiles("input.proto")
	if err != nil {
		return nil, fmt.Errorf("failed to parse proto file: %w", err)
	}

	if len(fds) == 0 {
		return nil, fmt.Errorf("no file descriptors found")
	}

	return extractServices(fds[0]), nil
}

// extractServices converts protoreflect descriptors to our wrapper types
func extractServices(fd *desc.FileDescriptor) []*ServiceDescriptor {
	services := fd.GetServices()
	result := make([]*ServiceDescriptor, 0, len(services))

	for _, svc := range services {
		methods := make([]*MethodDescriptor, 0)

		for _, method := range svc.GetMethods() {
			// Skip streaming methods in v1.0
			if method.IsServerStreaming() || method.IsClientStreaming() {
				continue
			}

			methodDesc := &MethodDescriptor{
				Name:           method.GetName(),
				FullName:       method.GetFullyQualifiedName(),
				InputType:      convertMessageDesc(method.GetInputType()),
				OutputType:     convertMessageDesc(method.GetOutputType()),
				IsServerStream: method.IsServerStreaming(),
				IsClientStream: method.IsClientStreaming(),
				RawDescriptor:  method, // Store the original descriptor
			}

			methods = append(methods, methodDesc)
		}

		serviceDesc := &ServiceDescriptor{
			Name:     svc.GetName(),
			FullName: svc.GetFullyQualifiedName(),
			Methods:  methods,
		}

		result = append(result, serviceDesc)
	}

	return result
}

// BuildMethodDescriptorMap creates a map from operation path to method descriptor
// Path format: /package.Service/Method
func BuildMethodDescriptorMap(services []*ServiceDescriptor) map[string]*desc.MethodDescriptor {
	result := make(map[string]*desc.MethodDescriptor)
	for _, svc := range services {
		for _, method := range svc.Methods {
			if method.RawDescriptor != nil {
				path := fmt.Sprintf("/%s/%s", svc.FullName, method.Name)
				result[path] = method.RawDescriptor
			}
		}
	}
	return result
}

// convertMessageDesc converts a message descriptor
func convertMessageDesc(md *desc.MessageDescriptor) *MessageDescriptor {
	fields := make([]*FieldDescriptor, 0, len(md.GetFields()))

	for _, field := range md.GetFields() {
		fieldDesc := &FieldDescriptor{
			Name:       field.GetName(),
			Number:     field.GetNumber(),
			Type:       field.GetType().String(),
			TypeName:   field.GetFullyQualifiedName(),
			IsRepeated: field.IsRepeated(),
			IsRequired: field.IsRequired(),
		}

		fields = append(fields, fieldDesc)
	}

	return &MessageDescriptor{
		Name:     md.GetName(),
		FullName: md.GetFullyQualifiedName(),
		Fields:   fields,
	}
}
