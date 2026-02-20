package grpc

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/bufbuild/protocompile"
	"github.com/bufbuild/protocompile/reporter"
	"google.golang.org/protobuf/reflect/protoreflect"
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
	RawDescriptor protoreflect.MethodDescriptor
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
	compiler := protocompile.Compiler{
		Resolver: &protocompile.SourceResolver{
			Accessor: func(path string) (io.ReadCloser, error) {
				if path == "input.proto" {
					return io.NopCloser(strings.NewReader(string(input))), nil
				}
				return nil, fmt.Errorf("file not found: %s", path)
			},
		},
		Reporter: reporter.NewReporter(nil, nil),
	}

	fds, err := compiler.Compile(context.Background(), "input.proto")
	if err != nil {
		return nil, fmt.Errorf("failed to parse proto file: %w", err)
	}

	if len(fds) == 0 {
		return nil, fmt.Errorf("no file descriptors found")
	}

	return extractServices(fds[0]), nil
}

// extractServices converts protoreflect descriptors to our wrapper types
func extractServices(fd protoreflect.FileDescriptor) []*ServiceDescriptor {
	services := fd.Services()
	result := make([]*ServiceDescriptor, 0, services.Len())

	for i := 0; i < services.Len(); i++ {
		svc := services.Get(i)
		methods := make([]*MethodDescriptor, 0)

		svcMethods := svc.Methods()
		for j := 0; j < svcMethods.Len(); j++ {
			method := svcMethods.Get(j)

			// Skip streaming methods in v1.0
			if method.IsStreamingServer() || method.IsStreamingClient() {
				continue
			}

			methodDesc := &MethodDescriptor{
				Name:           string(method.Name()),
				FullName:       string(method.FullName()),
				InputType:      convertMessageDesc(method.Input()),
				OutputType:     convertMessageDesc(method.Output()),
				IsServerStream: method.IsStreamingServer(),
				IsClientStream: method.IsStreamingClient(),
				RawDescriptor:  method, // Store the original descriptor
			}

			methods = append(methods, methodDesc)
		}

		serviceDesc := &ServiceDescriptor{
			Name:     string(svc.Name()),
			FullName: string(svc.FullName()),
			Methods:  methods,
		}

		result = append(result, serviceDesc)
	}

	return result
}

// BuildMethodDescriptorMap creates a map from operation path to method descriptor
// Path format: /package.Service/Method
func BuildMethodDescriptorMap(services []*ServiceDescriptor) map[string]protoreflect.MethodDescriptor {
	result := make(map[string]protoreflect.MethodDescriptor)
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
func convertMessageDesc(md protoreflect.MessageDescriptor) *MessageDescriptor {
	fields := md.Fields()
	result := make([]*FieldDescriptor, 0, fields.Len())

	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		fieldDesc := &FieldDescriptor{
			Name:       string(field.Name()),
			Number:     int32(field.Number()),
			Type:       field.Kind().String(),
			TypeName:   string(field.FullName()),
			IsRepeated: field.IsList(),
			IsRequired: field.Cardinality() == protoreflect.Required,
		}

		result = append(result, fieldDesc)
	}

	return &MessageDescriptor{
		Name:     string(md.Name()),
		FullName: string(md.FullName()),
		Fields:   result,
	}
}
